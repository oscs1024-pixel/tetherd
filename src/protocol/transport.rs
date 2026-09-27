use std::time::Duration;

use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::protocol::cipher::{read_encrypted, write_encrypted};
use crate::protocol::handshake::SecureChannel;
use crate::protocol::message::Message;
use crate::{Error, Result};

pub struct MessageTransport {
    pub incoming: mpsc::Receiver<Message>,
    pub outgoing: mpsc::Sender<Message>,
    pub reader_task: JoinHandle<Result<()>>,
    pub writer_task: JoinHandle<Result<()>>,
}

pub fn spawn_message_transport(
    channel: SecureChannel,
    write_timeout: Duration,
    capacity: usize,
) -> MessageTransport {
    let SecureChannel {
        mut reader,
        mut writer,
        mut recv_cipher,
        mut send_cipher,
    } = channel;

    let (incoming_tx, incoming) = mpsc::channel::<Message>(capacity);
    let (outgoing, mut outgoing_rx) = mpsc::channel::<Message>(capacity);

    let reader_task = tokio::spawn(async move {
        loop {
            let message: Message = read_encrypted(&mut reader, &mut recv_cipher).await?;
            incoming_tx
                .send(message)
                .await
                .map_err(|_| Error::Disconnected)?;
        }
    });

    let writer_task = tokio::spawn(async move {
        while let Some(message) = outgoing_rx.recv().await {
            tokio::time::timeout(
                write_timeout,
                write_encrypted(&mut writer, &mut send_cipher, &message),
            )
            .await
            .map_err(|_| Error::Timeout)??;
        }
        Ok(())
    });

    MessageTransport {
        incoming,
        outgoing,
        reader_task,
        writer_task,
    }
}

pub async fn stop_transport(transport: &mut MessageTransport) {
    transport.reader_task.abort();
    transport.writer_task.abort();
    let _ = (&mut transport.reader_task).await;
    let _ = (&mut transport.writer_task).await;
}
