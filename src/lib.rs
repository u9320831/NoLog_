#![no_std]

extern crate alloc;

mod bcrypt_rng;

use alloc::vec::Vec;
use core::{
    mem::size_of,
    slice,
    sync::atomic::{AtomicU64, Ordering},
};

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
use hex_literal::hex;
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use spin::Mutex;
use vbs_enclave::error::{EnclaveError, HRESULT, S_OK};
use vbs_enclave::is_valid_vtl0;
use vbs_enclave::winenclave::{
    ImageEnclaveConfig, IMAGE_ENCLAVE_FLAG_PRIMARY_IMAGE, IMAGE_ENCLAVE_MINIMUM_CONFIG_SIZE,
};
use x25519_dalek::{EphemeralSecret, PublicKey};
use zeroize::Zeroizing;

use crate::bcrypt_rng::BcryptRng;

const PUBLIC_KEY_SIZE: usize = 32;
const DERIVED_KEY_SIZE: usize = 32;
const NONCE_SIZE: usize = 12;
const NONCE_PREFIX_SIZE: usize = 4;
const POLY1305_TAG_SIZE: usize = 16;
const HASH_SIZE: usize = 32;
const MAX_MESSAGE_SIZE: usize = 64 * 1024;
const MAX_BUFFER_SIZE: usize = MAX_MESSAGE_SIZE + POLY1305_TAG_SIZE;

static CLIENT_SECRET: Mutex<Option<EphemeralSecret>> = Mutex::new(None);
static SERVER_SECRET: Mutex<Option<EphemeralSecret>> = Mutex::new(None);
static CLIENT_KEY: Mutex<Option<Zeroizing<[u8; DERIVED_KEY_SIZE]>>> = Mutex::new(None);
static SERVER_KEY: Mutex<Option<Zeroizing<[u8; DERIVED_KEY_SIZE]>>> = Mutex::new(None);
static CLIENT_NONCE_PREFIX: Mutex<Option<[u8; NONCE_PREFIX_SIZE]>> = Mutex::new(None);
static SERVER_NONCE_PREFIX: Mutex<Option<[u8; NONCE_PREFIX_SIZE]>> = Mutex::new(None);
static CLIENT_NONCE_COUNTER: AtomicU64 = AtomicU64::new(0);
static SERVER_NONCE_COUNTER: AtomicU64 = AtomicU64::new(0);

#[cfg(debug_assertions)]
const ENCLAVE_CONFIG_POLICY_FLAGS: u32 = vbs_enclave::winenclave::IMAGE_ENCLAVE_POLICY_DEBUGGABLE;
#[cfg(not(debug_assertions))]
const ENCLAVE_CONFIG_POLICY_FLAGS: u32 = 0;

// Configuration required by the Windows VBS enclave loader.
#[no_mangle]
#[allow(non_upper_case_globals)]
pub static __enclave_config: ImageEnclaveConfig = ImageEnclaveConfig {
    size: size_of::<ImageEnclaveConfig>() as u32,
    minimum_required_config_size: IMAGE_ENCLAVE_MINIMUM_CONFIG_SIZE,
    policy_flags: ENCLAVE_CONFIG_POLICY_FLAGS,
    number_of_imports: 0,
    import_list: 0,
    import_entry_size: 0,
    family_id: hex!("4e6f4c6f 672d5632 532d4661 6d696c79"),
    image_id: hex!("4e6f4c6f 672d456e 636c6176 652d7631"),
    image_version: 1,
    security_version: 1,
    enclave_size: 0x1000_0000,
    number_of_threads: 4,
    enclave_flags: IMAGE_ENCLAVE_FLAG_PRIMARY_IMAGE,
};

fn invalid_arg() -> HRESULT {
    EnclaveError::invalid_arg().into()
}

fn copy_public_key_out(out: *mut u8, public_key: &PublicKey) -> bool {
    if !is_valid_vtl0(out, PUBLIC_KEY_SIZE) {
        return false;
    }

    unsafe {
        slice::from_raw_parts_mut(out, PUBLIC_KEY_SIZE).copy_from_slice(public_key.as_bytes());
    }

    true
}

fn copy_public_key_in(input: *const u8) -> Option<[u8; PUBLIC_KEY_SIZE]> {
    if !is_valid_vtl0(input, PUBLIC_KEY_SIZE) {
        return None;
    }

    let mut public_key = [0u8; PUBLIC_KEY_SIZE];
    unsafe {
        public_key.copy_from_slice(slice::from_raw_parts(input, PUBLIC_KEY_SIZE));
    }

    Some(public_key)
}

fn copy_buffer_in(input: *const u8, length: usize) -> Option<Vec<u8>> {
    if length > MAX_BUFFER_SIZE {
        return None;
    }

    if length == 0 {
        return Some(Vec::new());
    }

    if !is_valid_vtl0(input, length) {
        return None;
    }

    let mut buffer = Vec::new();
    buffer.resize(length, 0);

    unsafe {
        buffer.copy_from_slice(slice::from_raw_parts(input, length));
    }

    Some(buffer)
}

fn copy_buffer_out(output: *mut u8, data: &[u8]) -> bool {
    if data.is_empty() {
        return true;
    }

    if !is_valid_vtl0(output, data.len()) {
        return false;
    }

    unsafe {
        slice::from_raw_parts_mut(output, data.len()).copy_from_slice(data);
    }

    true
}

fn copy_length_out(output_length: *mut usize, length: usize) -> bool {
    if !is_valid_vtl0(output_length as *mut u8, size_of::<usize>()) {
        return false;
    }

    unsafe {
        *output_length = length;
    }

    true
}

fn derive_key(shared_secret: &[u8; PUBLIC_KEY_SIZE]) -> [u8; DERIVED_KEY_SIZE] {
    let hkdf = Hkdf::<Sha256>::new(Some(b"NoLog-X25519-VBS-v1"), shared_secret);

    let mut key = [0u8; DERIVED_KEY_SIZE];
    hkdf.expand(b"NoLog shared channel key", &mut key)
        .expect("a 32-byte HKDF output is valid");
    key
}

fn begin(
    output_public_key: *mut u8,
    secret_slot: &Mutex<Option<EphemeralSecret>>,
    nonce_prefix_slot: &Mutex<Option<[u8; NONCE_PREFIX_SIZE]>>,
    nonce_counter: &AtomicU64,
) -> HRESULT {
    if !is_valid_vtl0(output_public_key, PUBLIC_KEY_SIZE) {
        return invalid_arg();
    }

    let mut secret_slot = secret_slot.lock();
    if secret_slot.is_some() {
        return invalid_arg();
    }

    let mut rng = BcryptRng;
    let secret = EphemeralSecret::random_from_rng(&mut rng);
    let public_key = PublicKey::from(&secret);
    let mut nonce_prefix = [0u8; NONCE_PREFIX_SIZE];
    rng.fill_bytes(&mut nonce_prefix);

    if !copy_public_key_out(output_public_key, &public_key) {
        return invalid_arg();
    }

    *secret_slot = Some(secret);
    *nonce_prefix_slot.lock() = Some(nonce_prefix);
    nonce_counter.store(0, Ordering::Relaxed);
    S_OK
}

fn next_nonce(
    nonce_prefix_slot: &Mutex<Option<[u8; NONCE_PREFIX_SIZE]>>,
    nonce_counter: &AtomicU64,
) -> Option<[u8; NONCE_SIZE]> {
    let prefix = nonce_prefix_slot.lock().as_ref().copied()?;
    let counter = nonce_counter.fetch_add(1, Ordering::Relaxed);

    if counter == u64::MAX {
        return None;
    }

    let mut nonce = [0u8; NONCE_SIZE];
    nonce[..NONCE_PREFIX_SIZE].copy_from_slice(&prefix);
    nonce[NONCE_PREFIX_SIZE..].copy_from_slice(&counter.to_be_bytes());
    Some(nonce)
}

fn finish(
    peer_public_key: *const u8,
    secret_slot: &Mutex<Option<EphemeralSecret>>,
    derived_key_slot: &Mutex<Option<Zeroizing<[u8; DERIVED_KEY_SIZE]>>>,
) -> HRESULT {
    let Some(peer_public_key) = copy_public_key_in(peer_public_key) else {
        return invalid_arg();
    };

    let peer_public_key = PublicKey::from(peer_public_key);
    let Some(secret) = secret_slot.lock().take() else {
        return invalid_arg();
    };

    let shared_secret = secret.diffie_hellman(&peer_public_key);
    if shared_secret.as_bytes().iter().all(|byte| *byte == 0) {
        return invalid_arg();
    }

    *derived_key_slot.lock() = Some(Zeroizing::new(derive_key(shared_secret.as_bytes())));
    S_OK
}

fn session_key_copy(
    key_slot: &Mutex<Option<Zeroizing<[u8; DERIVED_KEY_SIZE]>>>,
) -> Option<Zeroizing<[u8; DERIVED_KEY_SIZE]>> {
    key_slot.lock().as_ref().map(|key| Zeroizing::new(**key))
}

fn encrypt_for(
    key_slot: &Mutex<Option<Zeroizing<[u8; DERIVED_KEY_SIZE]>>>,
    nonce_prefix_slot: &Mutex<Option<[u8; NONCE_PREFIX_SIZE]>>,
    nonce_counter: &AtomicU64,
    plaintext: *const u8,
    plaintext_len: usize,
    aad: *const u8,
    aad_len: usize,
    nonce_output: *mut u8,
    ciphertext_output: *mut u8,
    ciphertext_capacity: usize,
    ciphertext_length_output: *mut usize,
) -> HRESULT {
    let Some(ciphertext_len) = plaintext_len.checked_add(POLY1305_TAG_SIZE) else {
        return invalid_arg();
    };

    if plaintext_len > MAX_MESSAGE_SIZE
        || ciphertext_capacity < ciphertext_len
        || !is_valid_vtl0(nonce_output, NONCE_SIZE)
        || !is_valid_vtl0(ciphertext_output, ciphertext_len)
        || !is_valid_vtl0(ciphertext_length_output as *mut u8, size_of::<usize>())
    {
        return invalid_arg();
    }

    let Some(plaintext) = copy_buffer_in(plaintext, plaintext_len) else {
        return invalid_arg();
    };
    let Some(aad) = copy_buffer_in(aad, aad_len) else {
        return invalid_arg();
    };
    let Some(key) = session_key_copy(key_slot) else {
        return invalid_arg();
    };

    let Some(nonce) = next_nonce(nonce_prefix_slot, nonce_counter) else {
        return invalid_arg();
    };

    let cipher_key = Key::from(*key);
    let cipher = ChaCha20Poly1305::new(&cipher_key);
    let nonce =
        Nonce::try_from(nonce.as_slice()).expect("un nonce ChaCha20 doit contenir 12 octets");
    let ciphertext = match cipher.encrypt(
        &nonce,
        Payload {
            msg: plaintext.as_slice(),
            aad: aad.as_slice(),
        },
    ) {
        Ok(ciphertext) => ciphertext,
        Err(_) => return invalid_arg(),
    };

    if !copy_buffer_out(nonce_output, &nonce)
        || !copy_buffer_out(ciphertext_output, &ciphertext)
        || !copy_length_out(ciphertext_length_output, ciphertext.len())
    {
        return invalid_arg();
    }

    S_OK
}

fn decrypt_for(
    key_slot: &Mutex<Option<Zeroizing<[u8; DERIVED_KEY_SIZE]>>>,
    nonce_input: *const u8,
    ciphertext: *const u8,
    ciphertext_len: usize,
    aad: *const u8,
    aad_len: usize,
    plaintext_output: *mut u8,
    plaintext_capacity: usize,
    plaintext_length_output: *mut usize,
) -> HRESULT {
    if !(POLY1305_TAG_SIZE..=MAX_MESSAGE_SIZE + POLY1305_TAG_SIZE).contains(&ciphertext_len)
        || !is_valid_vtl0(nonce_input, NONCE_SIZE)
        || !is_valid_vtl0(ciphertext, ciphertext_len)
        || !is_valid_vtl0(plaintext_length_output as *mut u8, size_of::<usize>())
    {
        return invalid_arg();
    }

    let Some(ciphertext) = copy_buffer_in(ciphertext, ciphertext_len) else {
        return invalid_arg();
    };
    let Some(aad) = copy_buffer_in(aad, aad_len) else {
        return invalid_arg();
    };
    let Some(key) = session_key_copy(key_slot) else {
        return invalid_arg();
    };

    let mut nonce = [0u8; NONCE_SIZE];
    unsafe {
        nonce.copy_from_slice(slice::from_raw_parts(nonce_input, NONCE_SIZE));
    }

    let cipher_key = Key::from(*key);
    let cipher = ChaCha20Poly1305::new(&cipher_key);
    let nonce =
        Nonce::try_from(nonce.as_slice()).expect("un nonce ChaCha20 doit contenir 12 octets");
    let plaintext = match cipher.decrypt(
        &nonce,
        Payload {
            msg: ciphertext.as_slice(),
            aad: aad.as_slice(),
        },
    ) {
        Ok(plaintext) => plaintext,
        Err(_) => return invalid_arg(),
    };

    if plaintext.len() > plaintext_capacity || !copy_buffer_out(plaintext_output, &plaintext) {
        return invalid_arg();
    }

    if !copy_length_out(plaintext_length_output, plaintext.len()) {
        return invalid_arg();
    }

    S_OK
}

fn hash_sha256(input: *const u8, input_len: usize, output: *mut u8) -> HRESULT {
    if !is_valid_vtl0(output, HASH_SIZE) {
        return invalid_arg();
    }

    let Some(input) = copy_buffer_in(input, input_len) else {
        return invalid_arg();
    };
    let digest = Sha256::digest(&input);

    if !copy_buffer_out(output, digest.as_ref()) {
        return invalid_arg();
    }

    S_OK
}

/// Génère la clé publique éphémère du côté client.
#[no_mangle]
pub extern "C" fn nolog_client_begin(output_public_key: *mut u8) -> HRESULT {
    begin(
        output_public_key,
        &CLIENT_SECRET,
        &CLIENT_NONCE_PREFIX,
        &CLIENT_NONCE_COUNTER,
    )
}

/// Génère la clé publique éphémère du côté serveur.
#[no_mangle]
pub extern "C" fn nolog_server_begin(output_public_key: *mut u8) -> HRESULT {
    begin(
        output_public_key,
        &SERVER_SECRET,
        &SERVER_NONCE_PREFIX,
        &SERVER_NONCE_COUNTER,
    )
}

/// Termine l’échange côté client et conserve la clé dans l’enclave.
#[no_mangle]
pub extern "C" fn nolog_client_finish(peer_public_key: *const u8) -> HRESULT {
    finish(peer_public_key, &CLIENT_SECRET, &CLIENT_KEY)
}

/// Termine l’échange côté serveur et conserve la clé dans l’enclave.
#[no_mangle]
pub extern "C" fn nolog_server_finish(peer_public_key: *const u8) -> HRESULT {
    finish(peer_public_key, &SERVER_SECRET, &SERVER_KEY)
}

/// Chiffre avec la clé client et ajoute le tag Poly1305 aux données chiffrées.
/// Le nonce de 12 octets est généré par BCryptGenRandom et doit être transmis
/// avec le ciphertext.
#[no_mangle]
pub extern "C" fn nolog_client_encrypt(
    plaintext: *const u8,
    plaintext_len: usize,
    aad: *const u8,
    aad_len: usize,
    nonce_output: *mut u8,
    ciphertext_output: *mut u8,
    ciphertext_capacity: usize,
    ciphertext_length_output: *mut usize,
) -> HRESULT {
    encrypt_for(
        &CLIENT_KEY,
        &CLIENT_NONCE_PREFIX,
        &CLIENT_NONCE_COUNTER,
        plaintext,
        plaintext_len,
        aad,
        aad_len,
        nonce_output,
        ciphertext_output,
        ciphertext_capacity,
        ciphertext_length_output,
    )
}

/// Chiffre avec la clé serveur.
#[no_mangle]
pub extern "C" fn nolog_server_encrypt(
    plaintext: *const u8,
    plaintext_len: usize,
    aad: *const u8,
    aad_len: usize,
    nonce_output: *mut u8,
    ciphertext_output: *mut u8,
    ciphertext_capacity: usize,
    ciphertext_length_output: *mut usize,
) -> HRESULT {
    encrypt_for(
        &SERVER_KEY,
        &SERVER_NONCE_PREFIX,
        &SERVER_NONCE_COUNTER,
        plaintext,
        plaintext_len,
        aad,
        aad_len,
        nonce_output,
        ciphertext_output,
        ciphertext_capacity,
        ciphertext_length_output,
    )
}

/// Déchiffre et vérifie le tag Poly1305 avec la clé client.
#[no_mangle]
pub extern "C" fn nolog_client_decrypt(
    nonce_input: *const u8,
    ciphertext: *const u8,
    ciphertext_len: usize,
    aad: *const u8,
    aad_len: usize,
    plaintext_output: *mut u8,
    plaintext_capacity: usize,
    plaintext_length_output: *mut usize,
) -> HRESULT {
    decrypt_for(
        &CLIENT_KEY,
        nonce_input,
        ciphertext,
        ciphertext_len,
        aad,
        aad_len,
        plaintext_output,
        plaintext_capacity,
        plaintext_length_output,
    )
}

/// Déchiffre et vérifie le tag Poly1305 avec la clé serveur.
#[no_mangle]
pub extern "C" fn nolog_server_decrypt(
    nonce_input: *const u8,
    ciphertext: *const u8,
    ciphertext_len: usize,
    aad: *const u8,
    aad_len: usize,
    plaintext_output: *mut u8,
    plaintext_capacity: usize,
    plaintext_length_output: *mut usize,
) -> HRESULT {
    decrypt_for(
        &SERVER_KEY,
        nonce_input,
        ciphertext,
        ciphertext_len,
        aad,
        aad_len,
        plaintext_output,
        plaintext_capacity,
        plaintext_length_output,
    )
}

/// Calcule SHA-256 dans l’enclave.
#[no_mangle]
pub extern "C" fn nolog_sha256(
    input: *const u8,
    input_len: usize,
    output_hash: *mut u8,
) -> HRESULT {
    hash_sha256(input, input_len, output_hash)
}
