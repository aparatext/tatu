use bytes::{Bytes, BytesMut};
use futures::{Sink, SinkExt, Stream, StreamExt, ready};
use snow::{HandshakeState, TransportState};
use std::{
    collections::VecDeque,
    io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_util::codec::{Decoder, Encoder, Framed, FramedParts, LengthDelimitedCodec};

const MAX_MSG: usize = 65535;
const TAG_LEN: usize = 16;
const MAX_PLAIN: usize = MAX_MSG - TAG_LEN;
const FLUSH_THRESHOLD: usize = 1400;
const PATTERN: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";

fn length_codec() -> LengthDelimitedCodec {
    LengthDelimitedCodec::builder()
        .length_field_length(2)
        .big_endian()
        .max_frame_length(MAX_MSG)
        .new_codec()
}

struct NoiseCodec {
    framing: LengthDelimitedCodec,
    transport: TransportState,
    decrypt_buf: Vec<u8>,
}

impl NoiseCodec {
    fn new(transport: TransportState) -> Self {
        Self {
            framing: length_codec(),
            transport,
            decrypt_buf: vec![0u8; MAX_MSG],
        }
    }

    pub fn transport(&self) -> &TransportState {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut TransportState {
        &mut self.transport
    }
}

impl Decoder for NoiseCodec {
    type Item = Bytes;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> io::Result<Option<Self::Item>> {
        let frame = match self.framing.decode(src).map_err(io_err)? {
            Some(f) => f,
            None => return Ok(None),
        };

        let n = self
            .transport
            .read_message(&frame, &mut self.decrypt_buf)
            .map_err(io_err)?;

        Ok(Some(Bytes::copy_from_slice(&self.decrypt_buf[..n])))
    }
}

impl Encoder<Bytes> for NoiseCodec {
    type Error = io::Error;

    fn encode(&mut self, frame: Bytes, dst: &mut BytesMut) -> io::Result<()> {
        let mut ciphertext = BytesMut::zeroed(frame.len() + TAG_LEN);
        let n = self
            .transport
            .write_message(&frame, &mut ciphertext)
            .map_err(io_err)?;
        ciphertext.truncate(n);

        self.framing
            .encode(ciphertext.freeze(), dst)
            .map_err(io_err)
    }
}

pub struct NoisePipe<T> {
    inner: Framed<T, NoiseCodec>,
    read_buf: BytesMut,
    write_buf: BytesMut,
    write_queue: VecDeque<Bytes>,
}

impl<T: AsyncRead + AsyncWrite + Unpin> NoisePipe<T> {
    pub async fn connect(stream: T, secret: &x25519::StaticSecret) -> io::Result<Self> {
        let hs = snow::Builder::new(PATTERN.parse().unwrap())
            .local_private_key(&secret.to_bytes())
            .map_err(io_err)?
            .build_initiator()
            .map_err(io_err)?;
        handshake(stream, hs).await
    }

    pub async fn accept(stream: T, secret: &x25519::StaticSecret) -> io::Result<Self> {
        let hs = snow::Builder::new(PATTERN.parse().unwrap())
            .local_private_key(&secret.to_bytes())
            .map_err(io_err)?
            .build_responder()
            .map_err(io_err)?;
        handshake(stream, hs).await
    }
}

async fn handshake<T: AsyncRead + AsyncWrite + Unpin>(
    stream: T,
    mut hs: HandshakeState,
) -> io::Result<NoisePipe<T>> {
    let mut framed = Framed::new(stream, length_codec());
    let mut buf = vec![0u8; MAX_MSG];

    while !hs.is_handshake_finished() {
        if hs.is_my_turn() {
            let n = hs.write_message(&[], &mut buf).map_err(io_err)?;
            framed.send(Bytes::copy_from_slice(&buf[..n])).await?;
        } else {
            let msg = framed
                .next()
                .await
                .ok_or_else(|| io_err("closed during handshake"))??;
            hs.read_message(&msg, &mut buf).map_err(io_err)?;
        }
    }

    let transport = hs.into_transport_mode().map_err(io_err)?;

    // Preserve buffered data from handshake phase
    let old_parts = framed.into_parts();
    let mut new_parts = FramedParts::new(old_parts.io, NoiseCodec::new(transport));
    new_parts.read_buf = old_parts.read_buf;
    new_parts.write_buf = old_parts.write_buf;

    Ok(NoisePipe {
        inner: Framed::from_parts(new_parts),
        read_buf: BytesMut::new(),
        write_buf: BytesMut::new(),
        write_queue: VecDeque::new(),
    })
}

impl<T> NoisePipe<T> {
    pub fn transport(&self) -> &TransportState {
        self.inner.codec().transport()
    }

    pub fn transport_mut(&mut self) -> &mut TransportState {
        self.inner.codec_mut().transport_mut()
    }

    pub fn remote_public_key(&self) -> io::Result<x25519::PublicKey> {
        let raw = self
            .transport()
            .get_remote_static()
            .ok_or_else(|| io_err("no remote static key"))?;
        let bytes: [u8; 32] = raw
            .try_into()
            .map_err(|_| io_err("remote key must be 32 bytes"))?;
        Ok(x25519::PublicKey::from(bytes))
    }

    pub fn into_inner(self) -> T {
        self.inner.into_inner()
    }

    pub fn get_ref(&self) -> &T {
        self.inner.get_ref()
    }

    pub fn get_mut(&mut self) -> &mut T {
        self.inner.get_mut()
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for NoisePipe<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        while this.read_buf.is_empty() {
            match ready!(Pin::new(&mut this.inner).poll_next(cx)) {
                Some(Ok(bytes)) => {
                    if bytes.is_empty() {
                        continue;
                    }
                    this.read_buf.extend_from_slice(&bytes);
                }
                Some(Err(e)) => return Poll::Ready(Err(e)),
                None => return Poll::Ready(Ok(())),
            }
        }

        let to_copy = this.read_buf.len().min(buf.remaining());
        buf.put_slice(&this.read_buf.split_to(to_copy));
        Poll::Ready(Ok(()))
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for NoisePipe<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        if !buf.is_empty() {
            this.write_buf.extend_from_slice(buf);
        }

        while this.write_buf.len() >= MAX_PLAIN {
            let chunk = this.write_buf.split_to(MAX_PLAIN).freeze();
            this.write_queue.push_back(chunk);
        }

        if this.write_buf.len() >= FLUSH_THRESHOLD {
            let chunk = this.write_buf.split().freeze();
            this.write_queue.push_back(chunk);
        }

        ready!(this.poll_drain_queue(cx))?;
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        if !this.write_buf.is_empty() {
            let chunk = this.write_buf.split().freeze();
            this.write_queue.push_back(chunk);
        }

        ready!(this.poll_drain_queue(cx))?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.as_mut().poll_flush(cx))?;
        Pin::new(&mut self.get_mut().inner).poll_close(cx)
    }
}

fn io_err(e: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e)
}

impl<T: AsyncWrite + Unpin> NoisePipe<T> {
    fn poll_drain_queue(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.write_queue.front().is_some() {
            ready!(Pin::new(&mut self.inner).poll_ready(cx))?;
            let frame = self.write_queue.pop_front().unwrap();
            Pin::new(&mut self.inner).start_send(frame)?;
        }
        Poll::Ready(Ok(()))
    }
}
