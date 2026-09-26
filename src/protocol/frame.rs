use serde::de::DeserializeOwned;
use serde::Serialize;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{Error, Result};

use super::MAX_FRAME_BYTES;

pub async fn write_raw_frame<W>(writer: &mut W, payload: &[u8]) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    if payload.len() > MAX_FRAME_BYTES {
        return Err(Error::FrameTooLarge {
            actual: payload.len(),
            limit: MAX_FRAME_BYTES,
        });
    }
    let len = u32::try_from(payload.len())
        .map_err(|_| Error::Protocol("frame length does not fit u32".into()))?;
    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(payload).await?;
    writer.flush().await?;
    Ok(())
}

pub async fn read_raw_frame<R>(reader: &mut R) -> Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    read_raw_frame_limited(reader, MAX_FRAME_BYTES).await
}

pub async fn read_raw_frame_limited<R>(reader: &mut R, limit: usize) -> Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let mut len_buf = [0u8; 4];
    match reader.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Err(Error::Disconnected),
        Err(e) => return Err(e.into()),
    }
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > limit {
        return Err(Error::FrameTooLarge { actual: len, limit });
    }
    let mut payload = vec![0u8; len];
    reader.read_exact(&mut payload).await?;
    Ok(payload)
}

pub async fn write_json_frame<W, T>(writer: &mut W, value: &T) -> Result<()>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let payload = serde_json::to_vec(value)?;
    write_raw_frame(writer, &payload).await
}

pub async fn read_json_frame<R, T>(reader: &mut R) -> Result<T>
where
    R: AsyncRead + Unpin,
    T: DeserializeOwned,
{
    let payload = read_raw_frame(reader).await?;
    Ok(serde_json::from_slice(&payload)?)
}

pub async fn read_json_frame_limited<R, T>(reader: &mut R, limit: usize) -> Result<T>
where
    R: AsyncRead + Unpin,
    T: DeserializeOwned,
{
    let payload = read_raw_frame_limited(reader, limit).await?;
    Ok(serde_json::from_slice(&payload)?)
}
