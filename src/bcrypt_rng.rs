use core::ptr::null_mut;
use windows_sys::Win32::Security::Cryptography::{
    BCryptGenRandom, BCRYPT_USE_SYSTEM_PREFERRED_RNG,
};
use x25519_dalek::rand_core::{Infallible, TryCryptoRng, TryRng};

/// RNG cryptographique alimenté par le générateur système Windows CNG.
///
/// En cas d'échec, l'application s'arrête immédiatement : il ne faut jamais
/// continuer avec des octets aléatoires incomplets ou prévisibles.
#[derive(Debug, Default, Clone, Copy)]
pub struct BcryptRng;

impl BcryptRng {
    pub fn fill_bytes(&mut self, dest: &mut [u8]) {
        assert!(
            dest.len() <= u32::MAX as usize,
            "demande aléatoire trop grande"
        );

        let status = unsafe {
            BCryptGenRandom(
                null_mut(),
                dest.as_mut_ptr(),
                dest.len() as u32,
                BCRYPT_USE_SYSTEM_PREFERRED_RNG,
            )
        };

        assert_eq!(
            status, 0,
            "BCryptGenRandom a échoué : NTSTATUS=0x{status:08X}"
        );
    }
}

impl TryRng for BcryptRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut bytes = [0u8; 4];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut bytes = [0u8; 8];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl TryCryptoRng for BcryptRng {}
