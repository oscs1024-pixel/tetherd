use std::time::Duration;

use rand::{rngs::StdRng, RngCore, SeedableRng};
use tetherd::protocol::cipher::CipherState;
use tetherd::protocol::cipher::{read_encrypted, write_encrypted};
use tetherd::protocol::frame::{read_raw_frame_limited, write_raw_frame_limited};
use tetherd::protocol::handshake::{client_handshake, server_handshake};
use tetherd::protocol::message::Message;
use tetherd::protocol::MAX_PEER_FRAME_BYTES;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

#[test]
fn cipher_round_trip_and_replay_rejected() {
    let key = [7u8; 32];
    let mut sender = CipherState::new(&key, *b"TEST");
    let mut receiver = CipherState::new(&key, *b"TEST");
    let sealed = sender.seal(b"hello").unwrap();
    assert_eq!(receiver.open(&sealed).unwrap(), b"hello");
    assert!(receiver.open(&sealed).is_err(), "replay must be rejected");
}

#[test]
fn cipher_tamper_rejected() {
    let key = [9u8; 32];
    let mut sender = CipherState::new(&key, *b"TEST");
    let mut receiver = CipherState::new(&key, *b"TEST");
    let mut sealed = sender.seal(b"hello").unwrap();
    let last = sealed.len() - 1;
    sealed[last] ^= 0x40;
    assert!(receiver.open(&sealed).is_err());
}

#[tokio::test]
async fn handshake_and_encrypted_message_round_trip() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let psk = [0x42u8; 32];

    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut channel = server_handshake(stream, &psk).await.unwrap();
        let message: Message = read_encrypted(&mut channel.reader, &mut channel.recv_cipher)
            .await
            .unwrap();
        match message {
            Message::Ping { nonce: 77 } => {}
            other => panic!("unexpected message: {other:?}"),
        }
        write_encrypted(
            &mut channel.writer,
            &mut channel.send_cipher,
            &Message::Pong { nonce: 77 },
        )
        .await
        .unwrap();
    });

    let stream = TcpStream::connect(addr).await.unwrap();
    let mut channel = client_handshake(stream, &psk).await.unwrap();
    write_encrypted(
        &mut channel.writer,
        &mut channel.send_cipher,
        &Message::Ping { nonce: 77 },
    )
    .await
    .unwrap();
    let response: Message = read_encrypted(&mut channel.reader, &mut channel.recv_cipher)
        .await
        .unwrap();
    assert!(matches!(response, Message::Pong { nonce: 77 }));
    tokio::time::timeout(Duration::from_secs(2), server)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn wrong_psk_is_rejected() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        server_handshake(stream, &[1u8; 32]).await
    });
    let client_stream = TcpStream::connect(addr).await.unwrap();
    let client_result = client_handshake(client_stream, &[2u8; 32]).await;
    assert!(client_result.is_err());
    let server_result = tokio::time::timeout(Duration::from_secs(2), server)
        .await
        .unwrap()
        .unwrap();
    assert!(server_result.is_err());
}

#[test]
fn cipher_rejects_random_malformed_authenticated_payloads() {
    let key = [0xA5u8; 32];
    let mut rng = StdRng::seed_from_u64(0x0054_4554_4845_5244);
    for _ in 0..512 {
        let mut payload = vec![0u8; 8 + 16 + 64];
        payload[..8].copy_from_slice(&0u64.to_be_bytes());
        rng.fill_bytes(&mut payload[8..]);
        let mut receiver = CipherState::new(&key, *b"TEST");
        assert!(receiver.open(&payload).is_err());
    }
}

#[tokio::test]
async fn frame_reader_rejects_oversized_length_before_allocating_payload() {
    let (mut writer, mut reader) = tokio::io::duplex(64);
    writer.write_all(&(4097u32).to_be_bytes()).await.unwrap();
    let result = read_raw_frame_limited(&mut reader, 4096).await;
    assert!(matches!(
        result,
        Err(tetherd::Error::FrameTooLarge {
            actual: 4097,
            limit: 4096
        })
    ));
}

#[tokio::test]
async fn frame_reader_rejects_truncated_payload() {
    let (mut writer, mut reader) = tokio::io::duplex(64);
    writer.write_all(&(10u32).to_be_bytes()).await.unwrap();
    writer.write_all(b"abc").await.unwrap();
    writer.shutdown().await.unwrap();
    assert!(read_raw_frame_limited(&mut reader, 64).await.is_err());
}

#[tokio::test]
async fn frame_writer_rejects_payload_above_explicit_limit() {
    let (mut writer, _reader) = tokio::io::duplex(64);
    let payload = vec![0u8; 65];
    let result = write_raw_frame_limited(&mut writer, &payload, 64).await;
    assert!(matches!(
        result,
        Err(tetherd::Error::FrameTooLarge {
            actual: 65,
            limit: 64
        })
    ));
}

#[tokio::test]
async fn encrypted_peer_reader_rejects_frame_above_peer_ceiling_before_payload_read() {
    let (mut writer, mut reader) = tokio::io::duplex(64);
    let oversized = u32::try_from(MAX_PEER_FRAME_BYTES + 1).unwrap();
    writer.write_all(&oversized.to_be_bytes()).await.unwrap();

    let key = [0x5au8; 32];
    let mut cipher = CipherState::new(&key, *b"TEST");
    let result: tetherd::Result<Message> = read_encrypted(&mut reader, &mut cipher).await;
    assert!(matches!(
        result,
        Err(tetherd::Error::FrameTooLarge {
            actual,
            limit: MAX_PEER_FRAME_BYTES
        }) if actual == MAX_PEER_FRAME_BYTES + 1
    ));
}
