use zeroize::Zeroizing;

pub const PROTOCOL_VERSION: u8 = 1;
pub const RECORD_ID_SIZE: usize = 16;
pub const NONCE_SIZE: usize = 12;
pub const MAX_CIPHERTEXT_SIZE: usize = 64 * 1024;
const MAGIC: &[u8; 4] = b"NLG1";
const HEADER_SIZE: usize = 4 + 1 + 4 + RECORD_ID_SIZE + NONCE_SIZE + 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvelopeError {
    InvalidFormat,
    UnsupportedVersion,
    PayloadTooLarge,
}

impl std::fmt::Display for EnvelopeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidFormat => write!(f, "invalid NoLog envelope"),
            Self::UnsupportedVersion => write!(f, "unsupported NoLog envelope version"),
            Self::PayloadTooLarge => write!(f, "NoLog envelope payload is too large"),
        }
    }
}

impl std::error::Error for EnvelopeError {}

/// Donnée chiffrée transportable entre l’application, le réseau et le serveur.
///
/// Cette structure ne contient jamais le texte clair. `record_id` doit être
/// généré aléatoirement et ne doit pas encoder une identité métier.
pub struct EncryptedEnvelope {
    version: u8,
    key_version: u32,
    record_id: [u8; RECORD_ID_SIZE],
    nonce: [u8; NONCE_SIZE],
    ciphertext: Zeroizing<Vec<u8>>,
}

impl EncryptedEnvelope {
    pub fn new(
        key_version: u32,
        record_id: [u8; RECORD_ID_SIZE],
        nonce: [u8; NONCE_SIZE],
        ciphertext: Vec<u8>,
    ) -> Result<Self, EnvelopeError> {
        if ciphertext.len() > MAX_CIPHERTEXT_SIZE {
            return Err(EnvelopeError::PayloadTooLarge);
        }
        Ok(Self {
            version: PROTOCOL_VERSION,
            key_version,
            record_id,
            nonce,
            ciphertext: Zeroizing::new(ciphertext),
        })
    }

    pub fn version(&self) -> u8 {
        self.version
    }

    pub fn key_version(&self) -> u32 {
        self.key_version
    }

    pub fn record_id(&self) -> &[u8; RECORD_ID_SIZE] {
        &self.record_id
    }

    pub fn nonce(&self) -> &[u8; NONCE_SIZE] {
        &self.nonce
    }

    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(HEADER_SIZE + self.ciphertext.len());
        encoded.extend_from_slice(MAGIC);
        encoded.push(self.version);
        encoded.extend_from_slice(&self.key_version.to_be_bytes());
        encoded.extend_from_slice(&self.record_id);
        encoded.extend_from_slice(&self.nonce);
        encoded.extend_from_slice(&(self.ciphertext.len() as u32).to_be_bytes());
        encoded.extend_from_slice(&self.ciphertext);
        encoded
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, EnvelopeError> {
        if encoded.len() < HEADER_SIZE || &encoded[..MAGIC.len()] != MAGIC {
            return Err(EnvelopeError::InvalidFormat);
        }

        let version = encoded[4];
        if version != PROTOCOL_VERSION {
            return Err(EnvelopeError::UnsupportedVersion);
        }

        let key_version = u32::from_be_bytes(
            encoded[5..9]
                .try_into()
                .map_err(|_| EnvelopeError::InvalidFormat)?,
        );
        let mut record_id = [0u8; RECORD_ID_SIZE];
        record_id.copy_from_slice(&encoded[9..9 + RECORD_ID_SIZE]);
        let nonce_start = 9 + RECORD_ID_SIZE;
        let mut nonce = [0u8; NONCE_SIZE];
        nonce.copy_from_slice(&encoded[nonce_start..nonce_start + NONCE_SIZE]);

        let length_start = nonce_start + NONCE_SIZE;
        let ciphertext_length = u32::from_be_bytes(
            encoded[length_start..length_start + 4]
                .try_into()
                .map_err(|_| EnvelopeError::InvalidFormat)?,
        ) as usize;
        if ciphertext_length > MAX_CIPHERTEXT_SIZE
            || encoded.len() != HEADER_SIZE + ciphertext_length
        {
            return Err(if ciphertext_length > MAX_CIPHERTEXT_SIZE {
                EnvelopeError::PayloadTooLarge
            } else {
                EnvelopeError::InvalidFormat
            });
        }

        Self::new(
            key_version,
            record_id,
            nonce,
            encoded[HEADER_SIZE..].to_vec(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_round_trip() {
        let envelope = EncryptedEnvelope::new(3, [7u8; 16], [8u8; 12], vec![1, 2, 3]).unwrap();
        let decoded = EncryptedEnvelope::decode(&envelope.encode()).unwrap();
        assert_eq!(decoded.key_version(), 3);
        assert_eq!(decoded.record_id(), &[7u8; 16]);
        assert_eq!(decoded.nonce(), &[8u8; 12]);
        assert_eq!(decoded.ciphertext(), &[1, 2, 3]);
    }
}
