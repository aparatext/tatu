use bytes::{Bytes, BytesMut};
use futures::{Sink, SinkExt, Stream, StreamExt, ready};
use snow::{HandshakeState, TransportState};
use std::{
    collections::VecDeque,
    io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::codec::{Decoder, Encoder, Framed, FramedParts, LengthDelimitedCodec};

// NOTE: COGDEBT

const MAX_MSG: usize = 65535;
const TAG_LEN: usize = 16;
const MAX_PLAIN: usize = MAX_MSG - TAG_LEN - 1;
const PATTERN: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";

fn length_codec() -> LengthDelimitedCodec {
    LengthDelimitedCodec::builder()
        .length_field_length(2)
        .big_endian()
        .max_frame_length(MAX_MSG)
        .new_codec()
}

#[derive(Debug)]
struct NoiseFrame {
    is_final: bool,
    data: Bytes,
}

impl NoiseFrame {
    fn parse(decrypted: &[u8]) -> io::Result<Self> {
        let (&flag, data) = decrypted
            .split_first()
            .ok_or_else(|| io_err("empty frame"))?;

        let is_final = match flag {
            0 => true,
            1 => false,
            f => return Err(io_err(format!("invalid flag: {f}"))),
        };

        Ok(Self {
            is_final,
            data: Bytes::copy_from_slice(data),
        })
    }

    fn serialize(&self, buf: &mut Vec<u8>) {
        buf.clear();
        buf.push(if self.is_final { 0 } else { 1 });
        buf.extend_from_slice(&self.data);
    }
}

struct NoiseCodec {
    framing: LengthDelimitedCodec,
    transport: TransportState,
    decrypt_buf: Vec<u8>,
    encrypt_buf: Vec<u8>,
}

impl NoiseCodec {
    fn new(transport: TransportState) -> Self {
        Self {
            framing: length_codec(),
            transport,
            decrypt_buf: vec![0u8; MAX_MSG],
            encrypt_buf: Vec::with_capacity(MAX_PLAIN + 1),
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
    type Item = NoiseFrame;
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

        NoiseFrame::parse(&self.decrypt_buf[..n]).map(Some)
    }
}

impl Encoder<NoiseFrame> for NoiseCodec {
    type Error = io::Error;

    fn encode(&mut self, frame: NoiseFrame, dst: &mut BytesMut) -> io::Result<()> {
        frame.serialize(&mut self.encrypt_buf);

        let mut ciphertext = BytesMut::zeroed(self.encrypt_buf.len() + TAG_LEN);
        let n = self
            .transport
            .write_message(&self.encrypt_buf, &mut ciphertext)
            .map_err(io_err)?;
        ciphertext.truncate(n);

        self.framing
            .encode(ciphertext.freeze(), dst)
            .map_err(io_err)
    }
}

pub struct NoisePipe<T> {
    inner: Framed<T, NoiseCodec>,
    read_pending: BytesMut,
    write_queue: VecDeque<NoiseFrame>,
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
        read_pending: BytesMut::new(),
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

impl<T: AsyncRead + Unpin> Stream for NoisePipe<T> {
    type Item = io::Result<Bytes>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            match ready!(Pin::new(&mut self.inner).poll_next(cx)) {
                Some(Ok(frame)) => {
                    self.read_pending.extend_from_slice(&frame.data);
                    if frame.is_final {
                        let msg = std::mem::take(&mut self.read_pending).freeze();
                        return Poll::Ready(Some(Ok(msg)));
                    }
                }
                Some(Err(e)) => return Poll::Ready(Some(Err(e))),
                None => {
                    return if self.read_pending.is_empty() {
                        Poll::Ready(None)
                    } else {
                        Poll::Ready(Some(Err(io_err("connection closed mid-message"))))
                    };
                }
            }
        }
    }
}

impl<T: AsyncWrite + Unpin> Sink<Bytes> for NoisePipe<T> {
    type Error = io::Error;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.as_mut().poll_drain_queue(cx)
    }

    fn start_send(mut self: Pin<&mut Self>, msg: Bytes) -> io::Result<()> {
        self.write_queue.extend(into_frames(msg));
        Ok(())
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.as_mut().poll_drain_queue(cx))?;
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.as_mut().poll_flush(cx))?;
        Pin::new(&mut self.inner).poll_close(cx)
    }
}

impl<T: AsyncWrite + Unpin> NoisePipe<T> {
    fn poll_drain_queue(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while !self.write_queue.is_empty() {
            ready!(Pin::new(&mut self.inner).poll_ready(cx))?;
            let frame = self.write_queue.pop_front().unwrap();
            Pin::new(&mut self.inner).start_send(frame)?;
        }
        Poll::Ready(Ok(()))
    }
}

fn into_frames(msg: Bytes) -> impl Iterator<Item = NoiseFrame> {
    let len = msg.len();
    let num_chunks = len.div_ceil(MAX_PLAIN).max(1);
    let last_idx = num_chunks - 1;

    (0..num_chunks).map(move |i| {
        let start = i * MAX_PLAIN;
        let end = ((i + 1) * MAX_PLAIN).min(len);
        NoiseFrame {
            is_final: i == last_idx,
            data: msg.slice(start..end),
        }
    })
}

fn io_err(e: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::{TcpListener, TcpStream};

    fn generate_keypair() -> x25519::StaticSecret {
        use rand::RngCore;
        let mut bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        x25519::StaticSecret::from(bytes)
    }

    async fn setup() -> io::Result<(NoisePipe<TcpStream>, NoisePipe<TcpStream>)> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;

        let client_key = generate_keypair();
        let server_key = generate_keypair();

        let client = tokio::spawn(async move {
            let stream = TcpStream::connect(addr).await?;
            NoisePipe::connect(stream, &client_key).await
        });

        let (stream, _) = listener.accept().await?;
        let server = NoisePipe::accept(stream, &server_key).await?;
        let client = client.await??;

        Ok((client, server))
    }

    #[tokio::test]
    async fn roundtrip_small() -> io::Result<()> {
        let (mut client, mut server) = setup().await?;

        client.send(Bytes::from("hello")).await?;
        let msg = server.next().await.unwrap()?;
        assert_eq!(&msg[..], b"hello");

        server.send(Bytes::from("world")).await?;
        let msg = client.next().await.unwrap()?;
        assert_eq!(&msg[..], b"world");

        Ok(())
    }

    #[tokio::test]
    async fn roundtrip_empty() -> io::Result<()> {
        let (mut client, mut server) = setup().await?;

        client.send(Bytes::new()).await?;
        let msg = server.next().await.unwrap()?;
        assert!(msg.is_empty());

        Ok(())
    }

    #[tokio::test]
    async fn roundtrip_one_chunk() -> io::Result<()> {
        let (mut client, mut server) = setup().await?;

        let payload = vec![0xAB; MAX_PLAIN];
        client.send(Bytes::from(payload.clone())).await?;
        let msg = server.next().await.unwrap()?;
        assert_eq!(msg.len(), MAX_PLAIN);
        assert_eq!(&msg[..], &payload[..]);

        Ok(())
    }

    #[tokio::test]
    async fn roundtrip_one_byte_over_chunk() -> io::Result<()> {
        let (mut client, mut server) = setup().await?;

        let payload = vec![0xCD; MAX_PLAIN + 1];
        client.send(Bytes::from(payload.clone())).await?;
        let msg = server.next().await.unwrap()?;
        assert_eq!(msg.len(), MAX_PLAIN + 1);
        assert_eq!(&msg[..], &payload[..]);

        Ok(())
    }

    #[tokio::test]
    async fn roundtrip_two_chunks() -> io::Result<()> {
        let (mut client, mut server) = setup().await?;

        let payload = vec![0xEF; MAX_PLAIN * 2];
        client.send(Bytes::from(payload.clone())).await?;
        let msg = server.next().await.unwrap()?;
        assert_eq!(msg.len(), MAX_PLAIN * 2);
        assert_eq!(&msg[..], &payload[..]);

        Ok(())
    }

    #[tokio::test]
    async fn roundtrip_large_message() -> io::Result<()> {
        let (mut client, mut server) = setup().await?;

        let payload: Vec<u8> = (0..500_000).map(|i| i as u8).collect();
        client.send(Bytes::from(payload.clone())).await?;
        let msg = server.next().await.unwrap()?;
        assert_eq!(msg.len(), 500_000);
        assert_eq!(&msg[..], &payload[..]);

        Ok(())
    }

    #[tokio::test]
    async fn multi_mes_seq() -> io::Result<()> {
        let (mut client, mut server) = setup().await?;

        for i in 0u8..10 {
            let payload = vec![i; 1000 * (i as usize + 1)];
            client.send(Bytes::from(payload.clone())).await?;
            let msg = server.next().await.unwrap()?;
            assert_eq!(&msg[..], &payload[..]);
        }

        Ok(())
    }
}
