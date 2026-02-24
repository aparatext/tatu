use bytes::{Bytes, BytesMut};
use futures::{Sink, SinkExt, Stream, StreamExt, ready};
use snow::{HandshakeState, TransportState};
use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_util::codec::{Decoder, Encoder, Framed, FramedParts, LengthDelimitedCodec};

const MAX_MSG: usize = 65535;
const TAG_LEN: usize = 16;
const MAX_PLAIN: usize = MAX_MSG - TAG_LEN;
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
    write_pending: Option<Bytes>,
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
        write_pending: None,
    })
}

impl<T> NoisePipe<T> {
    pub fn transport(&self) -> &TransportState {
        self.inner.codec().transport()
    }

    pub fn remote_public_key(&self) -> io::Result<x25519::PublicKey> {
        let raw = self
            .transport()
            .get_remote_static()
            .ok_or_else(|| io_err("no static remote key"))?;
        let bytes: [u8; 32] = raw
            .try_into()
            .map_err(|_| io_err("remote key must be 32 bytes"))?;
        Ok(x25519::PublicKey::from(bytes))
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

        match this.poll_drain_pending(cx)? {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(()) => {}
        }

        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let plain_len = buf.len().min(MAX_PLAIN);
        this.write_pending = Some(Bytes::copy_from_slice(&buf[..plain_len]));
        let _ = this.poll_drain_pending(cx)?;
        Poll::Ready(Ok(plain_len))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        match this.poll_drain_pending(cx)? {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(()) => {}
        }
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
    fn poll_drain_pending(&mut self, cx: &mut Context<'_>) -> io::Result<Poll<()>> {
        let Some(frame) = self.write_pending.take() else {
            return Ok(Poll::Ready(()));
        };

        match Pin::new(&mut self.inner).poll_ready(cx) {
            Poll::Pending => {
                self.write_pending = Some(frame);
                Ok(Poll::Pending)
            }
            Poll::Ready(Ok(())) => {
                Pin::new(&mut self.inner).start_send(frame)?;
                Ok(Poll::Ready(()))
            }
            Poll::Ready(Err(e)) => {
                self.write_pending = Some(frame);
                Err(e)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::join;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    #[test]
    fn stream_roundtrip_under_backpressure() {
        futures::executor::block_on(async {
            let init_sk = x25519::StaticSecret::random_from_rng(rand::rngs::OsRng);
            let resp_sk = x25519::StaticSecret::random_from_rng(rand::rngs::OsRng);

            // Small duplex capacity forces frequent Pending transitions.
            let (left, right) = duplex(64);
            let (left, right) = join!(
                NoisePipe::connect(left, &init_sk),
                NoisePipe::accept(right, &resp_sk)
            );
            let mut left = left.expect("initiator handshake");
            let mut right = right.expect("responder handshake");

            let mut payload = Vec::with_capacity((MAX_PLAIN * 3) + 513);
            for i in 0..(MAX_PLAIN * 3 + 513) {
                payload.push((i % 251) as u8);
            }

            let writer = async {
                // Mixed sizes exercise chunk boundaries and buffered pending writes.
                left.write_all(&payload[..17]).await?;
                left.write_all(&payload[17..MAX_PLAIN + 29]).await?;
                left.write_all(&payload[MAX_PLAIN + 29..]).await?;
                left.flush().await
            };

            let reader = async {
                let mut got = vec![0u8; payload.len()];
                right.read_exact(&mut got).await?;
                if got != payload {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "payload mismatch"));
                }
                Ok::<_, io::Error>(())
            };

            let (w, r) = join!(writer, reader);
            w.expect("writer completed");
            r.expect("reader completed");
        });
    }
}
