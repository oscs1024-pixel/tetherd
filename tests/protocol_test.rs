use std::time::Duration;

use tetherd::protocol::cipher::CipherState;
use tetherd::protocol::cipher::{read_encrypted, write_encrypted};
use tetherd::protocol::handshake::{client_handshake, server_handshake};
use tetherd::protocol::message::Message;
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
