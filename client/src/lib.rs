use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};

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

pub mod net;
pub mod tor;

pub use net::{
    NetworkError, NetworkInterface, TcpConnection, UdpConnection, MAX_DATAGRAM_SIZE, MAX_FRAME_SIZE,
};
pub use tor::{TorError, TorProxy, TorProxyConfig};

const COOKIE_SIZE: usize = 32;
const TPM_RSA_BITS: u32 = 2048;
const TPM_WRAPPED_MAX_SIZE: usize = TPM_RSA_BITS as usize / 8;
const COOKIE_MAGIC: &[u8; 8] = b"NLOGCK01";
const TPM_KEY_NAME: windows_sys::core::PCWSTR = windows_sys::core::w!("NoLog.Client.Cookie.TPM");

#[derive(Debug)]
pub enum CookieError {
    Io(io::Error),
    Windows(i32),
    InvalidFormat,
    RandomnessUnavailable,
}

impl std::fmt::Display for CookieError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "I/O error: {error}"),
            Self::Windows(status) => write!(f, "Windows cryptography error: 0x{status:08X}"),
            Self::InvalidFormat => write!(f, "invalid NoLog cookie file"),
            Self::RandomnessUnavailable => write!(f, "Windows CSPRNG unavailable"),
        }
    }
}

impl std::error::Error for CookieError {}

impl From<io::Error> for CookieError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// Cookie chargé en mémoire. Sa mémoire est effacée lors de sa destruction.
pub struct ClientCookie(Zeroizing<[u8; COOKIE_SIZE]>);

impl ClientCookie {
    pub fn as_bytes(&self) -> &[u8; COOKIE_SIZE] {
        &self.0
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

fn check_status(status: i32) -> Result<(), CookieError> {
    if status == ERROR_SUCCESS as i32 {
        Ok(())
    } else {
        Err(CookieError::Windows(status))
    }
}

fn random_cookie() -> Result<Zeroizing<[u8; COOKIE_SIZE]>, CookieError> {
    let mut cookie = Zeroizing::new([0u8; COOKIE_SIZE]);
    let status = unsafe {
        BCryptGenRandom(
            null_mut(),
            cookie.as_mut_ptr(),
            cookie.len() as u32,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };

    if status == 0 {
        Ok(cookie)
    } else {
        Err(CookieError::RandomnessUnavailable)
    }
}

fn open_tpm_key() -> Result<(NcryptHandle, NcryptHandle), CookieError> {
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
        return Err(CookieError::Windows(open_status));
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
    let key_bits = TPM_RSA_BITS;
    check_status(unsafe {
        NCryptSetProperty(
            key.0,
            NCRYPT_LENGTH_PROPERTY,
            &key_bits as *const u32 as *const u8,
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

fn wrap_with_tpm(
    key: NCRYPT_KEY_HANDLE,
    cookie: &[u8; COOKIE_SIZE],
) -> Result<Vec<u8>, CookieError> {
    let padding = oaep_info();
    let mut wrapped = vec![0u8; TPM_WRAPPED_MAX_SIZE];
    let mut written = 0u32;

    check_status(unsafe {
        NCryptEncrypt(
            key,
            cookie.as_ptr(),
            cookie.len() as u32,
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

fn unwrap_with_tpm(
    key: NCRYPT_KEY_HANDLE,
    wrapped: &[u8],
) -> Result<Zeroizing<[u8; COOKIE_SIZE]>, CookieError> {
    if wrapped.is_empty() || wrapped.len() > TPM_WRAPPED_MAX_SIZE {
        return Err(CookieError::InvalidFormat);
    }

    let padding = oaep_info();
    let mut cookie = Zeroizing::new([0u8; COOKIE_SIZE]);
    let mut written = 0u32;

    check_status(unsafe {
        NCryptDecrypt(
            key,
            wrapped.as_ptr(),
            wrapped.len() as u32,
            &padding as *const _ as *const _,
            cookie.as_mut_ptr(),
            cookie.len() as u32,
            &mut written,
            NCRYPT_PAD_OAEP_FLAG,
        )
    })?;

    if written as usize != COOKIE_SIZE {
        return Err(CookieError::InvalidFormat);
    }

    Ok(cookie)
}

fn local_blob_to_vec(blob: CRYPT_INTEGER_BLOB) -> Result<Vec<u8>, CookieError> {
    if blob.pbData.is_null() || blob.cbData == 0 {
        return Err(CookieError::InvalidFormat);
    }

    let result = unsafe { std::slice::from_raw_parts(blob.pbData, blob.cbData as usize).to_vec() };
    unsafe {
        LocalFree(blob.pbData as HLOCAL);
    }
    Ok(result)
}

fn protect_dpapi(data: &[u8]) -> Result<Vec<u8>, CookieError> {
    let input = CRYPT_INTEGER_BLOB {
        cbData: u32::try_from(data.len()).map_err(|_| CookieError::InvalidFormat)?,
        pbData: data.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: null_mut(),
    };

    let success = unsafe {
        CryptProtectData(
            &input,
            windows_sys::core::w!("NoLog client cookie"),
            null(),
            null(),
            null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };

    if success == 0 {
        return Err(CookieError::Io(io::Error::last_os_error()));
    }

    local_blob_to_vec(output)
}

fn unprotect_dpapi(data: &[u8]) -> Result<Vec<u8>, CookieError> {
    let input = CRYPT_INTEGER_BLOB {
        cbData: u32::try_from(data.len()).map_err(|_| CookieError::InvalidFormat)?,
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
        return Err(CookieError::Io(io::Error::last_os_error()));
    }

    local_blob_to_vec(output)
}

fn encode_cookie_file(protected_wrapped_cookie: &[u8]) -> Result<Vec<u8>, CookieError> {
    let length =
        u32::try_from(protected_wrapped_cookie.len()).map_err(|_| CookieError::InvalidFormat)?;
    let mut file = Vec::with_capacity(COOKIE_MAGIC.len() + 4 + protected_wrapped_cookie.len());
    file.extend_from_slice(COOKIE_MAGIC);
    file.extend_from_slice(&length.to_le_bytes());
    file.extend_from_slice(protected_wrapped_cookie);
    Ok(file)
}

fn decode_cookie_file(file: &[u8]) -> Result<&[u8], CookieError> {
    if file.len() < COOKIE_MAGIC.len() + 4 || &file[..COOKIE_MAGIC.len()] != COOKIE_MAGIC {
        return Err(CookieError::InvalidFormat);
    }

    let length_start = COOKIE_MAGIC.len();
    let length_end = length_start + 4;
    let protected_length = u32::from_le_bytes(
        file[length_start..length_end]
            .try_into()
            .map_err(|_| CookieError::InvalidFormat)?,
    ) as usize;

    if protected_length == 0 || file.len() != length_end + protected_length {
        return Err(CookieError::InvalidFormat);
    }

    Ok(&file[length_end..])
}

fn write_atomic(path: &Path, data: &[u8]) -> Result<(), CookieError> {
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

/// Retourne le chemin persistant recommandé pour le cookie du client.
pub fn default_cookie_path() -> Result<PathBuf, CookieError> {
    let local_app_data = std::env::var_os("LOCALAPPDATA").ok_or_else(|| {
        CookieError::Io(io::Error::new(
            io::ErrorKind::NotFound,
            "LOCALAPPDATA is not available",
        ))
    })?;

    Ok(PathBuf::from(local_app_data)
        .join("NoLog")
        .join("client.cookie"))
}

/// Charge ou crée le cookie client persistant.
///
/// Le fichier contient uniquement une enveloppe DPAPI. La valeur réelle est
/// en plus chiffrée par une clé RSA persistante du TPM.
pub fn load_or_create_cookie(path: impl AsRef<Path>) -> Result<ClientCookie, CookieError> {
    let path = path.as_ref();
    let (_provider, key) = open_tpm_key()?;

    match fs::read(path) {
        Ok(file) => {
            let protected = decode_cookie_file(&file)?;
            let wrapped = unprotect_dpapi(protected)?;
            let cookie = unwrap_with_tpm(key.0, &wrapped)?;
            Ok(ClientCookie(cookie))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            if let Some(parent) = path.parent() {
                if !parent.as_os_str().is_empty() {
                    fs::create_dir_all(parent)?;
                }
            }

            let cookie = random_cookie()?;
            let wrapped = wrap_with_tpm(key.0, &cookie)?;
            let protected = protect_dpapi(&wrapped)?;
            let encoded = encode_cookie_file(&protected)?;
            write_atomic(path, &encoded)?;
            Ok(ClientCookie(cookie))
        }
        Err(error) => Err(error.into()),
    }
}

/// Charge ou crée le cookie dans `%LOCALAPPDATA%\NoLog\client.cookie`.
pub fn load_or_create_default_cookie() -> Result<ClientCookie, CookieError> {
    let path = default_cookie_path()?;
    load_or_create_cookie(path)
}
