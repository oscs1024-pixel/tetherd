use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use serde::de::DeserializeOwned;
use serde::Serialize;
use tokio::io::{AsyncRead, AsyncWrite};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{Error, Result};

use super::frame::{read_raw_frame, write_raw_frame};

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SessionKeys {
    pub c2s: [u8; 32],
    pub s2c: [u8; 32],
}

pub struct CipherState {
    cipher: ChaCha20Poly1305,
    direction: [u8; 4],
    seq: u64,
}

impl CipherState {
    pub fn new(key: &[u8; 32], direction: [u8; 4]) -> Self {
        let cipher = ChaCha20Poly1305::new_from_slice(key)
            .expect("ChaCha20-Poly1305 requires a 32-byte key");
        Self {
            cipher,
            direction,
            seq: 0,
        }
    }

    fn nonce(&self, seq: u64) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce[..4].copy_from_slice(&self.direction);
        nonce[4..].copy_from_slice(&seq.to_be_bytes());
        nonce
    }

    pub fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let seq = self.seq;
        self.seq = self
            .seq
            .checked_add(1)
            .ok_or_else(|| Error::Protocol("send sequence exhausted".into()))?;
        let nonce_bytes = self.nonce(seq);
        let aad = seq.to_be_bytes();
        let ciphertext = self
            .cipher
            .encrypt(
                Nonce::from_slice(&nonce_bytes),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| Error::Crypto)?;
        let mut out = Vec::with_capacity(8 + ciphertext.len());
        out.extend_from_slice(&seq.to_be_bytes());
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    pub fn open(&mut self, payload: &[u8]) -> Result<Vec<u8>> {
        if payload.len() < 8 + 16 {
            return Err(Error::Protocol("encrypted frame is too short".into()));
        }
        let seq = u64::from_be_bytes(
            payload[..8]
                .try_into()
                .map_err(|_| Error::Protocol("invalid sequence field".into()))?,
        );
        if seq != self.seq {
            return Err(Error::Protocol(format!(
                "unexpected sequence: got {seq}, expected {}",
                self.seq
            )));
        }
        let nonce_bytes = self.nonce(seq);
        let aad = seq.to_be_bytes();
        let plaintext = self
            .cipher
            .decrypt(
                Nonce::from_slice(&nonce_bytes),
                Payload {
                    msg: &payload[8..],
                    aad: &aad,
                },
            )
            .map_err(|_| Error::Crypto)?;
        self.seq = self
            .seq
            .checked_add(1)
            .ok_or_else(|| Error::Protocol("receive sequence exhausted".into()))?;
        Ok(plaintext)
    }
}

pub async fn write_encrypted<W, T>(
    writer: &mut W,
    cipher: &mut CipherState,
    value: &T,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let plaintext = serde_json::to_vec(value)?;
    let mut encrypted = cipher.seal(&plaintext)?;
    let result = write_raw_frame(writer, &encrypted).await;
    encrypted.zeroize();
    result
}

pub async fn read_encrypted<R, T>(reader: &mut R, cipher: &mut CipherState) -> Result<T>
where
    R: AsyncRead + Unpin,
    T: DeserializeOwned,
{
    let mut encrypted = read_raw_frame(reader).await?;
    let mut plaintext = cipher.open(&encrypted)?;
    encrypted.zeroize();
    let decoded = serde_json::from_slice(&plaintext)?;
    plaintext.zeroize();
    Ok(decoded)
}
