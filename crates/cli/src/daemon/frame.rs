//! Length-prefixed JSON framing over an async stream.
//!
//! Frame layout: `<u32 BE body length><JSON body>`. The length
//! prefix bounds the accepted body size (we refuse any frame larger
//! than `MAX_FRAME_BYTES`), and reads grow the buffer only as bytes
//! arrive, so a hostile peer cannot pin `MAX_FRAME_BYTES` of zeroed
//! memory by announcing a large frame and then stalling.

use crate::daemon::protocol::{response_kind, Request, Response, MAX_FRAME_BYTES};
use anyhow::{bail, Context, Result};
use bytes::{Buf, BufMut, BytesMut};
use futures_util::{SinkExt, StreamExt};
use std::marker::PhantomData;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::UnixStream;
use tokio_util::codec::{Decoder, Encoder, Framed, FramedRead, FramedWrite};

const LENGTH_PREFIX_BYTES: usize = 4;

pub(crate) type ServerTransport = Framed<UnixStream, ServerCodec>;
pub(crate) type ClientTransport = Framed<UnixStream, ClientCodec>;

pub(crate) fn server_transport(stream: UnixStream) -> ServerTransport {
    Framed::new(stream, ServerCodec::default())
}

pub(crate) fn client_transport(stream: UnixStream) -> ClientTransport {
    Framed::new(stream, ClientCodec::default())
}

pub async fn write_request<W>(writer: &mut W, request: &Request) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut framed = FramedWrite::new(writer, RequestEncoder::default());
    framed.send(request.clone()).await
}

pub async fn write_response<W>(writer: &mut W, response: &Response) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut framed = FramedWrite::new(writer, ResponseEncoder::default());
    framed.send(response.clone()).await
}

pub async fn read_request<R>(reader: &mut R) -> Result<Option<Request>>
where
    R: AsyncRead + Unpin,
{
    let mut framed = FramedRead::new(reader, RequestDecoder::default());
    framed.next().await.transpose()
}

pub async fn read_response<R>(reader: &mut R) -> Result<Option<Response>>
where
    R: AsyncRead + Unpin,
{
    let mut framed = FramedRead::new(reader, ResponseDecoder::default());
    framed.next().await.transpose()
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

#[derive(Default)]
pub(crate) struct ServerCodec {
    decoder: RequestDecoder,
    encoder: ResponseEncoder,
}

impl Decoder for ServerCodec {
    type Item = Request;
    type Error = anyhow::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>> {
        self.decoder.decode(src)
    }

    fn decode_eof(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>> {
        self.decoder.decode_eof(src)
    }
}

impl Encoder<Response> for ServerCodec {
    type Error = anyhow::Error;

    fn encode(&mut self, item: Response, dst: &mut BytesMut) -> Result<()> {
        self.encoder.encode(item, dst)
    }
}

#[derive(Default)]
pub(crate) struct ClientCodec {
    decoder: ResponseDecoder,
    encoder: RequestEncoder,
}

impl Decoder for ClientCodec {
    type Item = Response;
    type Error = anyhow::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>> {
        self.decoder.decode(src)
    }

    fn decode_eof(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>> {
        self.decoder.decode_eof(src)
    }
}

impl Encoder<Request> for ClientCodec {
    type Error = anyhow::Error;

    fn encode(&mut self, item: Request, dst: &mut BytesMut) -> Result<()> {
        self.encoder.encode(item, dst)
    }
}

#[derive(Default)]
struct RequestEncoder {
    _marker: PhantomData<Request>,
}

impl Encoder<Request> for RequestEncoder {
    type Error = anyhow::Error;

    fn encode(&mut self, item: Request, dst: &mut BytesMut) -> Result<()> {
        let body = serde_json::to_vec(&item)
            .with_context(|| format!("frame: serialize Request::{}", request_kind(&item)))?;
        encode_body(dst, &body)
    }
}

#[derive(Default)]
struct ResponseEncoder {
    _marker: PhantomData<Response>,
}

impl Encoder<Response> for ResponseEncoder {
    type Error = anyhow::Error;

    fn encode(&mut self, item: Response, dst: &mut BytesMut) -> Result<()> {
        let body = serde_json::to_vec(&item)
            .with_context(|| format!("frame: serialize Response::{}", response_kind(&item)))?;
        encode_body(dst, &body)
    }
}

fn encode_body(dst: &mut BytesMut, body: &[u8]) -> Result<()> {
    if body.len() > MAX_FRAME_BYTES as usize {
        bail!(
            "frame: body of {} bytes exceeds {} byte cap",
            body.len(),
            MAX_FRAME_BYTES
        );
    }
    dst.reserve(LENGTH_PREFIX_BYTES + body.len());
    dst.put_u32(body.len() as u32);
    dst.extend_from_slice(body);
    Ok(())
}

#[derive(Default)]
struct RequestDecoder {
    _marker: PhantomData<Request>,
}

impl Decoder for RequestDecoder {
    type Item = Request;
    type Error = anyhow::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>> {
        let Some(body) = decode_body(src, false)? else {
            return Ok(None);
        };
        parse_request(&body)
    }

    fn decode_eof(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>> {
        let Some(body) = decode_body(src, true)? else {
            return Ok(None);
        };
        parse_request(&body)
    }
}

#[derive(Default)]
struct ResponseDecoder {
    _marker: PhantomData<Response>,
}

impl Decoder for ResponseDecoder {
    type Item = Response;
    type Error = anyhow::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>> {
        let Some(body) = decode_body(src, false)? else {
            return Ok(None);
        };
        parse_response(&body)
    }

    fn decode_eof(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>> {
        let Some(body) = decode_body(src, true)? else {
            return Ok(None);
        };
        parse_response(&body)
    }
}

fn decode_body(src: &mut BytesMut, eof: bool) -> Result<Option<BytesMut>> {
    if src.len() < LENGTH_PREFIX_BYTES {
        if eof && !src.is_empty() {
            bail!(
                "frame: peer closed after {} of {} length-prefix bytes",
                src.len(),
                LENGTH_PREFIX_BYTES
            );
        }
        return Ok(None);
    }

    let len = u32::from_be_bytes([src[0], src[1], src[2], src[3]]);
    if len > MAX_FRAME_BYTES {
        bail!(
            "frame: peer announced {} bytes, exceeds {} byte cap",
            len,
            MAX_FRAME_BYTES
        );
    }
    let expected_len = len as usize;
    let full_len = LENGTH_PREFIX_BYTES + expected_len;
    if src.len() < full_len {
        if eof {
            bail!(
                "frame: peer closed after {} of {} announced bytes",
                src.len() - LENGTH_PREFIX_BYTES,
                expected_len
            );
        }
        return Ok(None);
    }
    src.advance(LENGTH_PREFIX_BYTES);
    Ok(Some(src.split_to(expected_len)))
}

fn parse_request(body: &[u8]) -> Result<Option<Request>> {
    let req = serde_json::from_slice(body)
        .with_context(|| format!("frame: parse request ({} bytes)", body.len()))?;
    Ok(Some(req))
}

fn parse_response(body: &[u8]) -> Result<Option<Response>> {
    let resp = serde_json::from_slice(body)
        .with_context(|| format!("frame: parse response ({} bytes)", body.len()))?;
    Ok(Some(resp))
}
