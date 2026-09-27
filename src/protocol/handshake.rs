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
use crate::protocol::frame::{read_json_frame_limited, write_json_frame_limited};
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
    mac.update(b"tetherd-handshake");
    mac.update(&PROTOCOL_VERSION.to_be_bytes());
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
    h.update(b"tetherd-transcript");
    h.update(PROTOCOL_VERSION.to_be_bytes());
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
    write_json_frame_limited(&mut stream, &hello, MAX_HANDSHAKE_FRAME_BYTES).await?;

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
    write_json_frame_limited(
        &mut stream,
        &ClientAuth { tag: client_tag },
        MAX_HANDSHAKE_FRAME_BYTES,
    )
    .await?;

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
    write_json_frame_limited(
        &mut stream,
        &ServerHello {
            version: PROTOCOL_VERSION,
            server_pub,
            nonce: server_nonce,
            tag: server_tag,
        },
        MAX_HANDSHAKE_FRAME_BYTES,
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
    use super::{auth_tag, derive_keys, reject_all_zero_shared};

    #[test]
    fn authenticated_transcript_has_stable_v1_test_vector() {
        let psk: Vec<u8> = (0u8..32).collect();
        let client_pub: [u8; 32] = (32u8..64).collect::<Vec<_>>().try_into().unwrap();
        let server_pub: [u8; 32] = (64u8..96).collect::<Vec<_>>().try_into().unwrap();
        let client_nonce: [u8; 32] = (96u8..128).collect::<Vec<_>>().try_into().unwrap();
        let server_nonce: [u8; 32] = (128u8..160).collect::<Vec<_>>().try_into().unwrap();

        let tag = auth_tag(
            &psk,
            b"server-auth-v1",
            &client_pub,
            &server_pub,
            &client_nonce,
            &server_nonce,
        )
        .unwrap();
        assert_eq!(
            tag,
            [
                0x32, 0xf4, 0x9d, 0xb4, 0xc2, 0xd9, 0x52, 0x8d, 0x77, 0x6e, 0xa0, 0xf2, 0xb6, 0xef,
                0x33, 0x74, 0x17, 0x59, 0x37, 0xa0, 0x3d, 0x91, 0x56, 0x85, 0x90, 0xce, 0x76, 0x26,
                0x93, 0x99, 0xb8, 0xaa,
            ]
        );

        let shared = [0xa5u8; 32];
        let keys = derive_keys(
            &shared,
            &psk,
            &client_pub,
            &server_pub,
            &client_nonce,
            &server_nonce,
        )
        .unwrap();
        assert_eq!(
            keys.c2s,
            [
                0xb2, 0x36, 0xee, 0xc0, 0x5a, 0xaf, 0x52, 0x67, 0xa1, 0x6f, 0xe6, 0xa8, 0xaa, 0x9d,
                0x1e, 0x71, 0xb3, 0xb0, 0x27, 0x88, 0xfa, 0x7b, 0x9f, 0xda, 0x17, 0x10, 0x82, 0x0b,
                0xc2, 0x58, 0x12, 0x3e,
            ]
        );
        assert_eq!(
            keys.s2c,
            [
                0x2f, 0x4a, 0x0b, 0x65, 0x1d, 0x94, 0x80, 0xc9, 0xb6, 0x2b, 0x66, 0x3c, 0x0e, 0x3b,
                0x7f, 0x21, 0xd6, 0x8b, 0xc2, 0x7c, 0x7a, 0xd0, 0xee, 0x6f, 0xdd, 0xf9, 0x16, 0xd2,
                0xce, 0xfa, 0x8b, 0xcb,
            ]
        );
    }

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
