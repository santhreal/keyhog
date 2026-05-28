//! Length-prefixed JSON framing over an async stream.
//!
//! Frame layout: `<u32 BE body length><JSON body>`. The length
//! prefix bounds the recv buffer (we refuse any frame larger than
//! `MAX_FRAME_BYTES`), so a hostile peer can't make us OOM by lying
//! about the size.

use crate::daemon::protocol::{Request, Response, MAX_FRAME_BYTES};
use anyhow::{bail, Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub async fn write_request<W>(writer: &mut W, request: &Request) -> Result<()>
where
    W: AsyncWriteExt + Unpin,
{
    let body = serde_json::to_vec(request)
        .with_context(|| format!("frame: serialize Request::{}", request_kind(request)))?;
    write_frame(writer, &body).await
}

pub async fn write_response<W>(writer: &mut W, response: &Response) -> Result<()>
where
    W: AsyncWriteExt + Unpin,
{
    let body = serde_json::to_vec(response)
        .with_context(|| format!("frame: serialize Response::{}", response_kind(response)))?;
    write_frame(writer, &body).await
}

pub async fn read_request<R>(reader: &mut R) -> Result<Option<Request>>
where
    R: AsyncReadExt + Unpin,
{
    let Some(body) = read_frame(reader).await? else {
        return Ok(None);
    };
    let req = serde_json::from_slice(&body)
        .with_context(|| format!("frame: parse request ({} bytes)", body.len()))?;
    Ok(Some(req))
}

pub async fn read_response<R>(reader: &mut R) -> Result<Option<Response>>
where
    R: AsyncReadExt + Unpin,
{
    let Some(body) = read_frame(reader).await? else {
        return Ok(None);
    };
    let resp = serde_json::from_slice(&body)
        .with_context(|| format!("frame: parse response ({} bytes)", body.len()))?;
    Ok(Some(resp))
}

/// One-word kind label for a Request. Keeps frame-serialize errors
/// from leaking JSON-shaped payloads into operator logs.
fn request_kind(r: &Request) -> &'static str {
    match r {
        Request::Hello => "Hello",
        Request::Health => "Health",
        Request::ScanText { .. } => "ScanText",
        Request::ScanPath { .. } => "ScanPath",
        Request::Shutdown => "Shutdown",
    }
}

/// One-word kind label for a Response. Same rationale as request_kind.
fn response_kind(r: &Response) -> &'static str {
    match r {
        Response::Hello { .. } => "Hello",
        Response::Health { .. } => "Health",
        Response::ScanResults { .. } => "ScanResults",
        Response::Shutdown => "Shutdown",
        Response::Error { .. } => "Error",
    }
}

async fn write_frame<W>(writer: &mut W, body: &[u8]) -> Result<()>
where
    W: AsyncWriteExt + Unpin,
{
    let len: u32 = body
        .len()
        .try_into()
        .ok()
        .filter(|n: &u32| *n <= MAX_FRAME_BYTES)
        .with_context(|| {
            format!(
                "frame: body of {} bytes exceeds {} byte cap",
                body.len(),
                MAX_FRAME_BYTES
            )
        })?;
    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(body).await?;
    writer.flush().await?;
    Ok(())
}

async fn read_frame<R>(reader: &mut R) -> Result<Option<Vec<u8>>>
where
    R: AsyncReadExt + Unpin,
{
    let mut len_bytes = [0u8; 4];
    // EOF on the first byte means the peer closed cleanly - propagate
    // as None so the caller's loop exits without an error.
    match reader.read_exact(&mut len_bytes).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let len = u32::from_be_bytes(len_bytes);
    if len > MAX_FRAME_BYTES {
        bail!(
            "frame: peer announced {} bytes, exceeds {} byte cap",
            len,
            MAX_FRAME_BYTES
        );
    }
    let mut body = vec![0u8; len as usize];
    reader.read_exact(&mut body).await?;
    Ok(Some(body))
}
