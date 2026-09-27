use serde::de::DeserializeOwned;
use serde::Serialize;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{Error, Result};

pub async fn write_raw_frame_limited<W>(
    writer: &mut W,
    payload: &[u8],
    limit: usize,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    if payload.len() > limit {
        return Err(Error::FrameTooLarge {
            actual: payload.len(),
            limit,
        });
    }
    let len = u32::try_from(payload.len())
        .map_err(|_| Error::Protocol("frame length does not fit u32".into()))?;
    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(payload).await?;
    writer.flush().await?;
    Ok(())
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

pub async fn write_json_frame_limited<W, T>(
    writer: &mut W,
    value: &T,
    limit: usize,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let payload = serde_json::to_vec(value)?;
    write_raw_frame_limited(writer, &payload, limit).await
}

pub async fn read_json_frame_limited<R, T>(reader: &mut R, limit: usize) -> Result<T>
where
    R: AsyncRead + Unpin,
    T: DeserializeOwned,
{
    let payload = read_raw_frame_limited(reader, limit).await?;
    Ok(serde_json::from_slice(&payload)?)
}
