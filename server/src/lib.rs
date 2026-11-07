use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use windows_sys::Win32::Foundation::{LocalFree, ERROR_SUCCESS, HLOCAL, NTE_BAD_KEYSET};
use windows_sys::Win32::Security::Cryptography::{
    BCryptGenRandom, CryptProtectData, CryptUnprotectData, NCryptCreatePersistedKey, NCryptDecrypt,
    NCryptEncrypt, NCryptFinalizeKey, NCryptFreeObject, NCryptOpenKey, NCryptOpenStorageProvider,
    NCryptSetProperty, BCRYPT_OAEP_PADDING_INFO, BCRYPT_RSA_ALGORITHM, BCRYPT_SHA256_ALGORITHM,
    BCRYPT_USE_SYSTEM_PREFERRED_RNG, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    MS_PLATFORM_CRYPTO_PROVIDER, NCRYPT_KEY_HANDLE, NCRYPT_LENGTH_PROPERTY, NCRYPT_PAD_OAEP_FLAG,
    NCRYPT_PROV_HANDLE,
};
use zeroize::Zeroizing;

const FILE_MAGIC: &[u8; 8] = b"NLOGPG01";
const COOKIE_AAD: &[u8] = b"NoLog PostgreSQL credential vault v1";
const DEK_SIZE: usize = 32;
const NONCE_SIZE: usize = 12;
const TPM_RSA_BITS: u32 = 2048;
const TPM_WRAPPED_MAX_SIZE: usize = TPM_RSA_BITS as usize / 8;
const MAX_FIELD_SIZE: usize = 4096;
const TPM_KEY_NAME: windows_sys::core::PCWSTR =
    windows_sys::core::w!("NoLog.Server.PostgreSQL.Vault.TPM");

#[derive(Debug)]
pub enum VaultError {
    Io(io::Error),
    Windows(i32),
    InvalidFormat,
    AuthenticationFailed,
    RandomnessUnavailable,
    InvalidUtf8,
}

impl std::fmt::Display for VaultError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "vault I/O error: {error}"),
            Self::Windows(status) => write!(f, "Windows cryptography error: 0x{status:08X}"),
            Self::InvalidFormat => write!(f, "invalid NoLog PostgreSQL vault file"),
            Self::AuthenticationFailed => write!(f, "vault authentication failed"),
            Self::RandomnessUnavailable => write!(f, "Windows CSPRNG unavailable"),
            Self::InvalidUtf8 => write!(f, "vault field is not valid UTF-8"),
        }
    }
}

impl std::error::Error for VaultError {}

impl From<io::Error> for VaultError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// Identifiants PostgreSQL conservés uniquement côté serveur.
pub struct PostgresAccount {
    pub host: String,
    pub port: u16,
    pub database: String,
    pub username: String,
    pub password: Zeroizing<String>,
}

impl PostgresAccount {
    pub fn new(
        host: impl Into<String>,
        port: u16,
        database: impl Into<String>,
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> Self {
        Self {
            host: host.into(),
            port,
            database: database.into(),
            username: username.into(),
            password: Zeroizing::new(password.into()),
        }
    }
}

struct NcryptHandle(usize);

impl Drop for NcryptHandle {
    fn drop(&mut self) {
        if self.0 != 0 {
            unsafe {
                NCryptFreeObject(self.0);
            }
        }
    }
}

fn check_status(status: i32) -> Result<(), VaultError> {
    if status == ERROR_SUCCESS as i32 {
        Ok(())
    } else {
        Err(VaultError::Windows(status))
    }
}

fn random_bytes(buffer: &mut [u8]) -> Result<(), VaultError> {
    let status = unsafe {
        BCryptGenRandom(
            null_mut(),
            buffer.as_mut_ptr(),
            buffer.len() as u32,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };

    if status == 0 {
        Ok(())
    } else {
        Err(VaultError::RandomnessUnavailable)
    }
}

fn open_tpm_key() -> Result<(NcryptHandle, NcryptHandle), VaultError> {
    let mut provider: NCRYPT_PROV_HANDLE = 0;
    check_status(unsafe {
        NCryptOpenStorageProvider(&mut provider, MS_PLATFORM_CRYPTO_PROVIDER, 0)
    })?;
    let provider = NcryptHandle(provider);

    let mut key: NCRYPT_KEY_HANDLE = 0;
    let open_status = unsafe { NCryptOpenKey(provider.0, &mut key, TPM_KEY_NAME, 0, 0) };
    if open_status == ERROR_SUCCESS as i32 {
        return Ok((provider, NcryptHandle(key)));
    }
    if open_status != NTE_BAD_KEYSET {
        return Err(VaultError::Windows(open_status));
    }

    check_status(unsafe {
        NCryptCreatePersistedKey(
            provider.0,
            &mut key,
            BCRYPT_RSA_ALGORITHM,
            TPM_KEY_NAME,
            0,
            0,
        )
    })?;

    let key = NcryptHandle(key);
    let bits = TPM_RSA_BITS;
    check_status(unsafe {
        NCryptSetProperty(
            key.0,
            NCRYPT_LENGTH_PROPERTY,
            &bits as *const u32 as *const u8,
            size_of::<u32>() as u32,
            0,
        )
    })?;
    check_status(unsafe { NCryptFinalizeKey(key.0, 0) })?;
    Ok((provider, key))
}

fn oaep_info() -> BCRYPT_OAEP_PADDING_INFO {
    BCRYPT_OAEP_PADDING_INFO {
        pszAlgId: BCRYPT_SHA256_ALGORITHM,
        pbLabel: null_mut(),
        cbLabel: 0,
    }
}

fn wrap_key(key: NCRYPT_KEY_HANDLE, plaintext: &[u8; DEK_SIZE]) -> Result<Vec<u8>, VaultError> {
    let padding = oaep_info();
    let mut wrapped = vec![0u8; TPM_WRAPPED_MAX_SIZE];
    let mut written = 0u32;
    check_status(unsafe {
        NCryptEncrypt(
            key,
            plaintext.as_ptr(),
            plaintext.len() as u32,
            &padding as *const _ as *const _,
            wrapped.as_mut_ptr(),
            wrapped.len() as u32,
            &mut written,
            NCRYPT_PAD_OAEP_FLAG,
        )
    })?;
    wrapped.truncate(written as usize);
    Ok(wrapped)
}

fn unwrap_key(
    key: NCRYPT_KEY_HANDLE,
    wrapped: &[u8],
) -> Result<Zeroizing<[u8; DEK_SIZE]>, VaultError> {
    if wrapped.is_empty() || wrapped.len() > TPM_WRAPPED_MAX_SIZE {
        return Err(VaultError::InvalidFormat);
    }

    let padding = oaep_info();
    let mut plaintext = Zeroizing::new([0u8; DEK_SIZE]);
    let mut written = 0u32;
    check_status(unsafe {
        NCryptDecrypt(
            key,
            wrapped.as_ptr(),
            wrapped.len() as u32,
            &padding as *const _ as *const _,
            plaintext.as_mut_ptr(),
            plaintext.len() as u32,
            &mut written,
            NCRYPT_PAD_OAEP_FLAG,
        )
    })?;

    if written as usize != DEK_SIZE {
        return Err(VaultError::InvalidFormat);
    }
    Ok(plaintext)
}

fn local_blob_to_vec(blob: CRYPT_INTEGER_BLOB) -> Result<Vec<u8>, VaultError> {
    if blob.pbData.is_null() || blob.cbData == 0 {
        return Err(VaultError::InvalidFormat);
    }
    let result = unsafe { std::slice::from_raw_parts(blob.pbData, blob.cbData as usize).to_vec() };
    unsafe {
        LocalFree(blob.pbData as HLOCAL);
    }
    Ok(result)
}

fn protect_dpapi(data: &[u8]) -> Result<Vec<u8>, VaultError> {
    let input = CRYPT_INTEGER_BLOB {
        cbData: u32::try_from(data.len()).map_err(|_| VaultError::InvalidFormat)?,
        pbData: data.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: null_mut(),
    };
    let success = unsafe {
        CryptProtectData(
            &input,
            windows_sys::core::w!("NoLog PostgreSQL vault"),
            null(),
            null(),
            null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    if success == 0 {
        return Err(VaultError::Io(io::Error::last_os_error()));
    }
    local_blob_to_vec(output)
}

fn unprotect_dpapi(data: &[u8]) -> Result<Vec<u8>, VaultError> {
    let input = CRYPT_INTEGER_BLOB {
        cbData: u32::try_from(data.len()).map_err(|_| VaultError::InvalidFormat)?,
        pbData: data.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: null_mut(),
    };
    let success = unsafe {
        CryptUnprotectData(
            &input,
            null_mut(),
            null(),
            null(),
            null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    if success == 0 {
        return Err(VaultError::Io(io::Error::last_os_error()));
    }
    local_blob_to_vec(output)
}

fn push_field(target: &mut Vec<u8>, value: &str) -> Result<(), VaultError> {
    if value.len() > MAX_FIELD_SIZE {
        return Err(VaultError::InvalidFormat);
    }
    target.extend_from_slice(&(value.len() as u32).to_be_bytes());
    target.extend_from_slice(value.as_bytes());
    Ok(())
}

fn serialize_account(account: &PostgresAccount) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    let mut result = Zeroizing::new(Vec::new());
    result.extend_from_slice(&account.port.to_be_bytes());
    push_field(&mut result, &account.host)?;
    push_field(&mut result, &account.database)?;
    push_field(&mut result, &account.username)?;
    push_field(&mut result, &account.password)?;
    Ok(result)
}

fn take_field(data: &[u8], cursor: &mut usize) -> Result<String, VaultError> {
    if data.len().saturating_sub(*cursor) < 4 {
        return Err(VaultError::InvalidFormat);
    }
    let length = u32::from_be_bytes(
        data[*cursor..*cursor + 4]
            .try_into()
            .map_err(|_| VaultError::InvalidFormat)?,
    ) as usize;
    *cursor += 4;
    if length > MAX_FIELD_SIZE || data.len().saturating_sub(*cursor) < length {
        return Err(VaultError::InvalidFormat);
    }
    let value = std::str::from_utf8(&data[*cursor..*cursor + length])
        .map_err(|_| VaultError::InvalidUtf8)?
        .to_owned();
    *cursor += length;
    Ok(value)
}

fn deserialize_account(data: &[u8]) -> Result<PostgresAccount, VaultError> {
    if data.len() < 2 {
        return Err(VaultError::InvalidFormat);
    }
    let mut cursor = 0;
    let port = u16::from_be_bytes(
        data[..2]
            .try_into()
            .map_err(|_| VaultError::InvalidFormat)?,
    );
    cursor += 2;
    let host = take_field(data, &mut cursor)?;
    let database = take_field(data, &mut cursor)?;
    let username = take_field(data, &mut cursor)?;
    let password = take_field(data, &mut cursor)?;
    if cursor != data.len() {
        return Err(VaultError::InvalidFormat);
    }
    Ok(PostgresAccount::new(
        host, port, database, username, password,
    ))
}

fn encode_file(protected: &[u8]) -> Result<Vec<u8>, VaultError> {
    let length = u32::try_from(protected.len()).map_err(|_| VaultError::InvalidFormat)?;
    let mut result = Vec::with_capacity(FILE_MAGIC.len() + 4 + protected.len());
    result.extend_from_slice(FILE_MAGIC);
    result.extend_from_slice(&length.to_be_bytes());
    result.extend_from_slice(protected);
    Ok(result)
}

fn decode_file(file: &[u8]) -> Result<&[u8], VaultError> {
    if file.len() < FILE_MAGIC.len() + 4 || &file[..FILE_MAGIC.len()] != FILE_MAGIC {
        return Err(VaultError::InvalidFormat);
    }
    let length_start = FILE_MAGIC.len();
    let protected_length = u32::from_be_bytes(
        file[length_start..length_start + 4]
            .try_into()
            .map_err(|_| VaultError::InvalidFormat)?,
    ) as usize;
    if protected_length == 0 || file.len() != length_start + 4 + protected_length {
        return Err(VaultError::InvalidFormat);
    }
    Ok(&file[length_start + 4..])
}

fn write_atomic(path: &Path, data: &[u8]) -> Result<(), VaultError> {
    let temporary_path = PathBuf::from(format!("{}.tmp", path.display()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary_path)?;
    file.write_all(data)?;
    file.sync_all()?;
    drop(file);
    if let Err(error) = fs::rename(&temporary_path, path) {
        let _ = fs::remove_file(&temporary_path);
        return Err(error.into());
    }
    Ok(())
}

/// Vault local protégé par DPAPI et une clé persistante du TPM.
pub struct SecretVault {
    path: PathBuf,
}

impl SecretVault {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn save_postgres_account(&self, account: &PostgresAccount) -> Result<(), VaultError> {
        let plaintext = serialize_account(account)?;
        let mut dek = Zeroizing::new([0u8; DEK_SIZE]);
        random_bytes(dek.as_mut())?;
        let mut nonce = [0u8; NONCE_SIZE];
        random_bytes(&mut nonce)?;

        let key = Key::try_from(dek.as_ref()).map_err(|_| VaultError::InvalidFormat)?;
        let cipher = ChaCha20Poly1305::new(&key);
        let nonce = Nonce::try_from(nonce.as_slice()).map_err(|_| VaultError::InvalidFormat)?;
        let ciphertext = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: &plaintext,
                    aad: COOKIE_AAD,
                },
            )
            .map_err(|_| VaultError::AuthenticationFailed)?;

        let (_provider, tpm_key) = open_tpm_key()?;
        let wrapped_dek = wrap_key(tpm_key.0, &dek)?;
        let wrapped_len =
            u32::try_from(wrapped_dek.len()).map_err(|_| VaultError::InvalidFormat)?;

        let mut envelope =
            Vec::with_capacity(4 + wrapped_dek.len() + NONCE_SIZE + ciphertext.len());
        envelope.extend_from_slice(&wrapped_len.to_be_bytes());
        envelope.extend_from_slice(&wrapped_dek);
        envelope.extend_from_slice(&nonce);
        envelope.extend_from_slice(&ciphertext);

        let protected = protect_dpapi(&envelope)?;
        let encoded = encode_file(&protected)?;
        if let Some(parent) = self.path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }
        write_atomic(&self.path, &encoded)
    }

    pub fn load_postgres_account(&self) -> Result<PostgresAccount, VaultError> {
        let file = fs::read(&self.path)?;
        let protected = decode_file(&file)?;
        let envelope = unprotect_dpapi(protected)?;
        if envelope.len() < 4 + NONCE_SIZE {
            return Err(VaultError::InvalidFormat);
        }

        let wrapped_len = u32::from_be_bytes(
            envelope[..4]
                .try_into()
                .map_err(|_| VaultError::InvalidFormat)?,
        ) as usize;
        let wrapped_start = 4;
        let nonce_start = wrapped_start + wrapped_len;
        if wrapped_len == 0
            || wrapped_len > TPM_WRAPPED_MAX_SIZE
            || envelope.len() < nonce_start + NONCE_SIZE
        {
            return Err(VaultError::InvalidFormat);
        }

        let (_provider, tpm_key) = open_tpm_key()?;
        let dek = unwrap_key(tpm_key.0, &envelope[wrapped_start..nonce_start])?;
        let nonce = &envelope[nonce_start..nonce_start + NONCE_SIZE];
        let ciphertext = &envelope[nonce_start + NONCE_SIZE..];
        let key = Key::try_from(dek.as_ref()).map_err(|_| VaultError::InvalidFormat)?;
        let cipher = ChaCha20Poly1305::new(&key);
        let nonce = Nonce::try_from(nonce).map_err(|_| VaultError::InvalidFormat)?;
        let plaintext = cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: ciphertext,
                    aad: COOKIE_AAD,
                },
            )
            .map_err(|_| VaultError::AuthenticationFailed)?;
        deserialize_account(&plaintext)
    }
}

pub fn default_vault_path() -> Result<PathBuf, VaultError> {
    let root = std::env::var_os("PROGRAMDATA")
        .or_else(|| std::env::var_os("LOCALAPPDATA"))
        .ok_or_else(|| {
            VaultError::Io(io::Error::new(
                io::ErrorKind::NotFound,
                "PROGRAMDATA and LOCALAPPDATA are not available",
            ))
        })?;
    Ok(PathBuf::from(root)
        .join("NoLog")
        .join("vault")
        .join("postgres.account"))
}
