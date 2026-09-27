use std::time::Duration;

use tetherd::protocol::cipher::CipherState;
use tetherd::protocol::cipher::{read_encrypted, write_encrypted};
use tetherd::protocol::handshake::{client_handshake, server_handshake};
use tetherd::protocol::message::Message;
use tetherd::protocol::transport::{spawn_message_transport, stop_transport};
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fragmented_frames_remain_synchronized_under_bidirectional_traffic() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let psk = [0x33u8; 32];

    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let channel = server_handshake(stream, &psk).await.unwrap();
        let mut transport = spawn_message_transport(channel, Duration::from_secs(2), 16);

        for expected in 1u64..=32 {
            let message = tokio::time::timeout(Duration::from_secs(2), transport.incoming.recv())
                .await
                .unwrap()
                .unwrap();
            assert!(matches!(message, Message::Ping { nonce } if nonce == expected));
            transport
                .outgoing
                .try_send(Message::Pong { nonce: expected })
                .unwrap();
        }

        stop_transport(&mut transport).await;
    });

    let stream = TcpStream::connect(addr).await.unwrap();
    let mut channel = client_handshake(stream, &psk).await.unwrap();

    for nonce in 1u64..=32 {
        let plaintext = serde_json::to_vec(&Message::Ping { nonce }).unwrap();
        let sealed = channel.send_cipher.seal(&plaintext).unwrap();
        let len = u32::try_from(sealed.len()).unwrap().to_be_bytes();

        for byte in len {
            channel.writer.write_all(&[byte]).await.unwrap();
            tokio::task::yield_now().await;
        }
        for chunk in sealed.chunks(3) {
            channel.writer.write_all(chunk).await.unwrap();
            tokio::task::yield_now().await;
        }
        channel.writer.flush().await.unwrap();

        let response: Message = read_encrypted(&mut channel.reader, &mut channel.recv_cipher)
            .await
            .unwrap();
        assert!(matches!(response, Message::Pong { nonce: value } if value == nonce));
    }

    tokio::time::timeout(Duration::from_secs(5), server)
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
