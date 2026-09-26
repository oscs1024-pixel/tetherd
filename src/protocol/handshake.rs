use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::protocol::cipher::{CipherState, SessionKeys};
use crate::protocol::frame::{read_json_frame_limited, write_json_frame};
use crate::protocol::{MAX_HANDSHAKE_FRAME_BYTES, PROTOCOL_VERSION};
use crate::{Error, Result};

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Serialize, Deserialize)]
struct ClientHello {
    version: u16,
    client_pub: [u8; 32],
    nonce: [u8; 32],
}

#[derive(Debug, Serialize, Deserialize)]
struct ServerHello {
    version: u16,
    server_pub: [u8; 32],
    nonce: [u8; 32],
    tag: [u8; 32],
}

#[derive(Debug, Serialize, Deserialize)]
struct ClientAuth {
    tag: [u8; 32],
}

pub struct SecureChannel {
    pub reader: OwnedReadHalf,
    pub writer: OwnedWriteHalf,
    pub recv_cipher: CipherState,
    pub send_cipher: CipherState,
}

fn auth_tag(
    psk: &[u8],
    label: &[u8],
    client_pub: &[u8; 32],
    server_pub: &[u8; 32],
    client_nonce: &[u8; 32],
    server_nonce: &[u8; 32],
) -> Result<[u8; 32]> {
    let mut mac = HmacSha256::new_from_slice(psk).map_err(|_| Error::Crypto)?;
    mac.update(label);
    mac.update(client_pub);
    mac.update(server_pub);
    mac.update(client_nonce);
    mac.update(server_nonce);
    let bytes = mac.finalize().into_bytes();
    Ok(bytes.into())
}

fn verify_tag(expected: &[u8; 32], actual: &[u8; 32]) -> Result<()> {
    if expected.ct_eq(actual).into() {
        Ok(())
    } else {
        Err(Error::Authentication)
    }
}

fn reject_all_zero_shared(shared: &mut [u8; 32]) -> Result<()> {
    if shared.ct_eq(&[0u8; 32]).into() {
        shared.zeroize();
        Err(Error::Authentication)
    } else {
        Ok(())
    }
}

fn derive_keys(
    shared: &[u8; 32],
    psk: &[u8],
    client_pub: &[u8; 32],
    server_pub: &[u8; 32],
    client_nonce: &[u8; 32],
    server_nonce: &[u8; 32],
) -> Result<SessionKeys> {
    let mut h = Sha256::new();
    h.update(b"tetherd-transcript-v1");
    h.update(client_pub);
    h.update(server_pub);
    h.update(client_nonce);
    h.update(server_nonce);
    let transcript = h.finalize();

    let hk = Hkdf::<Sha256>::new(Some(psk), shared);
    let mut okm = [0u8; 64];
    hk.expand(&transcript, &mut okm)
        .map_err(|_| Error::Crypto)?;
    let mut c2s = [0u8; 32];
    let mut s2c = [0u8; 32];
    c2s.copy_from_slice(&okm[..32]);
    s2c.copy_from_slice(&okm[32..]);
    okm.zeroize();
    Ok(SessionKeys { c2s, s2c })
}

pub async fn client_handshake(mut stream: TcpStream, psk: &[u8]) -> Result<SecureChannel> {
    let secret = StaticSecret::random_from_rng(OsRng);
    let client_pub = PublicKey::from(&secret).to_bytes();
    let mut client_nonce = [0u8; 32];
    OsRng.fill_bytes(&mut client_nonce);

    let hello = ClientHello {
        version: PROTOCOL_VERSION,
        client_pub,
        nonce: client_nonce,
    };
    write_json_frame(&mut stream, &hello).await?;

    let server: ServerHello =
        read_json_frame_limited(&mut stream, MAX_HANDSHAKE_FRAME_BYTES).await?;
    if server.version != PROTOCOL_VERSION {
        return Err(Error::Protocol(format!(
            "unsupported server protocol version {}",
            server.version
        )));
    }
    let expected = auth_tag(
        psk,
        b"server-auth-v1",
        &client_pub,
        &server.server_pub,
        &client_nonce,
        &server.nonce,
    )?;
    verify_tag(&expected, &server.tag)?;

    let client_tag = auth_tag(
        psk,
        b"client-auth-v1",
        &client_pub,
        &server.server_pub,
        &client_nonce,
        &server.nonce,
    )?;
    write_json_frame(&mut stream, &ClientAuth { tag: client_tag }).await?;

    let server_pub = PublicKey::from(server.server_pub);
    let mut shared = secret.diffie_hellman(&server_pub).to_bytes();
    reject_all_zero_shared(&mut shared)?;
    let mut keys = derive_keys(
        &shared,
        psk,
        &client_pub,
        &server.server_pub,
        &client_nonce,
        &server.nonce,
    )?;
    shared.zeroize();
    let send_cipher = CipherState::new(&keys.c2s, *b"C2S1");
    let recv_cipher = CipherState::new(&keys.s2c, *b"S2C1");
    keys.zeroize();
    let (reader, writer) = stream.into_split();
    Ok(SecureChannel {
        reader,
        writer,
        recv_cipher,
        send_cipher,
    })
}

pub async fn server_handshake(mut stream: TcpStream, psk: &[u8]) -> Result<SecureChannel> {
    let client: ClientHello =
        read_json_frame_limited(&mut stream, MAX_HANDSHAKE_FRAME_BYTES).await?;
    if client.version != PROTOCOL_VERSION {
        return Err(Error::Protocol(format!(
            "unsupported client protocol version {}",
            client.version
        )));
    }

    let secret = StaticSecret::random_from_rng(OsRng);
    let server_pub = PublicKey::from(&secret).to_bytes();
    let mut server_nonce = [0u8; 32];
    OsRng.fill_bytes(&mut server_nonce);
    let server_tag = auth_tag(
        psk,
        b"server-auth-v1",
        &client.client_pub,
        &server_pub,
        &client.nonce,
        &server_nonce,
    )?;
    write_json_frame(
        &mut stream,
        &ServerHello {
            version: PROTOCOL_VERSION,
            server_pub,
            nonce: server_nonce,
            tag: server_tag,
        },
    )
    .await?;

    let auth: ClientAuth = read_json_frame_limited(&mut stream, MAX_HANDSHAKE_FRAME_BYTES).await?;
    let expected = auth_tag(
        psk,
        b"client-auth-v1",
        &client.client_pub,
        &server_pub,
        &client.nonce,
        &server_nonce,
    )?;
    verify_tag(&expected, &auth.tag)?;

    let client_pub = PublicKey::from(client.client_pub);
    let mut shared = secret.diffie_hellman(&client_pub).to_bytes();
    reject_all_zero_shared(&mut shared)?;
    let mut keys = derive_keys(
        &shared,
        psk,
        &client.client_pub,
        &server_pub,
        &client.nonce,
        &server_nonce,
    )?;
    shared.zeroize();
    let recv_cipher = CipherState::new(&keys.c2s, *b"C2S1");
    let send_cipher = CipherState::new(&keys.s2c, *b"S2C1");
    keys.zeroize();
    let (reader, writer) = stream.into_split();
    Ok(SecureChannel {
        reader,
        writer,
        recv_cipher,
        send_cipher,
    })
}

#[cfg(test)]
mod tests {
    use super::reject_all_zero_shared;

    #[test]
    fn all_zero_shared_secret_is_rejected() {
        let mut shared = [0u8; 32];
        assert!(reject_all_zero_shared(&mut shared).is_err());
        assert_eq!(shared, [0u8; 32]);
    }

    #[test]
    fn nonzero_shared_secret_is_accepted() {
        let mut shared = [0u8; 32];
        shared[7] = 1;
        assert!(reject_all_zero_shared(&mut shared).is_ok());
    }
}
