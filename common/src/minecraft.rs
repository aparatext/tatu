use std::collections::VecDeque;
use std::io;
use std::net::IpAddr;

use bytes::Bytes;
use tokio::net::TcpStream;
use uuid::Uuid;

use azalea_chat::FormattedText;
use azalea_protocol::{
    connect::{Connection, RawReadConnection, RawWriteConnection},
    packets::{
        PROTOCOL_VERSION,
        config::{ClientboundConfigPacket, ServerboundConfigPacket},
        game::{ClientboundGamePacket, c_system_chat::ClientboundSystemChat},
        handshake::{
            ClientboundHandshakePacket, ServerboundHandshakePacket,
            s_intention::ServerboundIntention,
        },
        login::{
            ClientboundLoginPacket, ServerboundLoginPacket,
            c_login_disconnect::ClientboundLoginDisconnect, s_hello::ServerboundHello,
        },
        status::{
            ClientboundStatusPacket, ServerboundStatusPacket,
            c_pong_response::ClientboundPongResponse,
            c_status_response::{ClientboundStatusResponse, Players, Version},
        },
    },
    read::{ReadPacketError, deserialize_packet},
    write::serialize_packet,
};
use tokio::io::AsyncWriteExt;

use crate::model::Persona;

// ---- Handshake ----

/// Accepted game client, pending intention check.
pub struct Handshake {
    conn: Connection<ServerboundHandshakePacket, ClientboundHandshakePacket>,
    intention: ServerboundIntention,
}

impl Handshake {
    pub async fn accept(stream: TcpStream) -> io::Result<Self> {
        stream.set_nodelay(true)?;
        let mut conn = Connection::wrap(stream);
        let ServerboundHandshakePacket::Intention(intention) =
            conn.read().await.map_err(io::Error::other)?;
        Ok(Self { conn, intention })
    }

    pub fn is_status(&self) -> bool {
        matches!(
            self.intention.intention,
            azalea_protocol::packets::ClientIntention::Status
        )
    }

    pub async fn handle_status(self, description: impl Into<FormattedText>) -> io::Result<()> {
        let mut conn = self.conn.status();

        if let Ok(ServerboundStatusPacket::StatusRequest(_)) = conn.read().await {
            conn.write(ClientboundStatusPacket::StatusResponse(
                ClientboundStatusResponse {
                    description: description.into(),
                    favicon: None,
                    players: Players {
                        max: 0,
                        online: 0,
                        sample: vec![],
                    },
                    version: Version {
                        name: "Tatu".into(),
                        protocol: PROTOCOL_VERSION,
                    },
                    enforces_secure_chat: Some(false),
                },
            ))
            .await
            .map_err(io::Error::other)?;
        }

        if let Ok(ServerboundStatusPacket::PingRequest(ping)) = conn.read().await {
            conn.write(ClientboundStatusPacket::PongResponse(
                ClientboundPongResponse { time: ping.time },
            ))
            .await
            .map_err(io::Error::other)?;
        }

        Ok(())
    }

    pub async fn into_login(self) -> io::Result<(ClientSidePlayer, String)> {
        let mut login = self.conn.login();
        let name = loop {
            match login.read().await {
                Ok(ServerboundLoginPacket::Hello(h)) => break h.name,
                Ok(_) => continue,
                Err(e) => return Err(io::Error::other(e)),
            }
        };
        let (read, write) = login.into_split_raw();
        Ok((
            ClientSidePlayer {
                read,
                write,
                intention: self.intention,
                buffered_play: VecDeque::new(),
            },
            name,
        ))
    }
}

// ---- ClientSidePlayer ----

/// Game client in login phase (we act as server).
pub struct ClientSidePlayer {
    read: RawReadConnection,
    write: RawWriteConnection,
    intention: ServerboundIntention,
    buffered_play: VecDeque<Bytes>,
}

impl ClientSidePlayer {
    pub async fn send_disconnect(&mut self, reason: impl AsRef<str>) -> io::Result<()> {
        let packet = ClientboundLoginPacket::LoginDisconnect(ClientboundLoginDisconnect {
            reason: FormattedText::from(reason.as_ref()),
        });
        self.write
            .write(&serialize_packet(&packet).map_err(io::Error::other)?)
            .await
    }

    /// Queue chat message to be sent when Play state is reached.
    pub fn queue_message(&mut self, msg: impl AsRef<str>) -> io::Result<()> {
        let packet = ClientboundGamePacket::SystemChat(ClientboundSystemChat {
            content: FormattedText::from(msg.as_ref()),
            overlay: false,
        });
        self.buffered_play.push_back(Bytes::from(
            serialize_packet(&packet).map_err(io::Error::other)?,
        ));
        Ok(())
    }

    pub fn handshake_bytes(&self) -> io::Result<Box<[u8]>> {
        serialize_packet(&ServerboundHandshakePacket::Intention(
            self.intention.clone(),
        ))
        .map_err(io::Error::other)
    }

    pub fn into_bridge(self) -> Bridge {
        Bridge {
            read: self.read,
            write: self.write,
            buffered_play: self.buffered_play,
        }
    }
}

// ---- ServerSidePlayer ----

/// Player to connect to backend (we act as client).
pub struct ServerSidePlayer {
    username: String,
    uuid: Uuid,
    client_ip: IpAddr,
    skin: Option<String>,
}

impl ServerSidePlayer {
    pub fn new(persona: &Persona, client_ip: IpAddr) -> Self {
        Self {
            username: persona.handle.to_string(),
            uuid: persona.uuid(),
            client_ip,
            skin: persona.skin.clone(),
        }
    }

    /// Send handshake with BungeeCord forwarding data, then Hello.
    pub async fn connect(self, backend: TcpStream, handshake_bytes: &[u8]) -> io::Result<Bridge> {
        let ServerboundHandshakePacket::Intention(intention) =
            deserialize_packet(&mut std::io::Cursor::new(handshake_bytes))
                .map_err(io::Error::other)?;

        backend.set_nodelay(true)?;

        let rewritten = ServerboundIntention {
            hostname: format!(
                "localhost\0{}\0{}\0{}",
                self.client_ip,
                self.uuid.as_hyphenated(),
                self.skin.as_deref().unwrap_or("[]")
            ),
            port: intention.port,
            protocol_version: intention.protocol_version,
            intention: intention.intention,
        };

        let mut conn: Connection<ClientboundHandshakePacket, ServerboundHandshakePacket> =
            Connection::wrap(backend);
        conn.write(ServerboundHandshakePacket::Intention(rewritten))
            .await?;

        let mut login = conn.login();
        login
            .write(ServerboundLoginPacket::Hello(ServerboundHello {
                name: self.username,
                profile_id: Uuid::nil(),
            }))
            .await?;

        let (read, write) = login.into_split_raw();
        Ok(Bridge {
            read,
            write,
            buffered_play: VecDeque::new(),
        })
    }
}

// ---- Bridge ----

/// Bidirectional packet forwarding with Play state detection.
pub struct Bridge {
    read: RawReadConnection,
    write: RawWriteConnection,
    buffered_play: VecDeque<Bytes>,
}

impl Bridge {
    pub async fn read(&mut self) -> io::Result<Box<[u8]>> {
        self.read.read().await.map_err(io::Error::other)
    }

    pub async fn write(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.write.write(bytes).await
    }

    async fn flush_buffered(&mut self) -> io::Result<()> {
        for packet in self.buffered_play.drain(..) {
            self.write.write(&packet).await?;
        }
        Ok(())
    }

    fn is_server_finish_config(bytes: &[u8]) -> bool {
        deserialize_packet::<ClientboundConfigPacket>(&mut std::io::Cursor::new(bytes))
            .is_ok_and(|p| matches!(p, ClientboundConfigPacket::FinishConfiguration(_)))
    }

    fn is_client_finish_config(bytes: &[u8]) -> bool {
        deserialize_packet::<ServerboundConfigPacket>(&mut std::io::Cursor::new(bytes))
            .is_ok_and(|p| matches!(p, ServerboundConfigPacket::FinishConfiguration(_)))
    }

    fn is_game_packet(bytes: &[u8]) -> bool {
        deserialize_packet::<ClientboundGamePacket>(&mut std::io::Cursor::new(bytes)).is_ok()
    }
}

// ---- Session framing ----

use crate::framing::{read_frame, write_frame};

impl Bridge {
    pub async fn forward<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
        mut self,
        mut io: T,
    ) -> io::Result<()> {
        // Track config-play transition to know when to flush queued messages.
        // Server sends FinishConfig, client acks, then first game packet = Play.
        enum State {
            WaitingServerConfig,
            WaitingClientConfig,
            Ready,
        }
        let mut state = State::WaitingServerConfig;

        loop {
            tokio::select! {
                result = self.read() => {
                    let bytes = result?;

                    if let State::WaitingClientConfig = state
                        && Self::is_client_finish_config(&bytes)
                    {
                        state = State::Ready;
                    }

                    write_frame(&mut io, &bytes).await?;
                    io.flush().await?;
                }

                msg = read_frame(&mut io) => {
                    let bytes = match msg? {
                        Some(bytes) => bytes,
                        None => return Err(io::Error::other("session closed")),
                    };

                    state = match state {
                        State::WaitingServerConfig if Self::is_server_finish_config(&bytes) => {
                            State::WaitingClientConfig
                        }
                        State::Ready if Self::is_game_packet(&bytes) => {
                            self.write(&bytes).await?;
                            self.flush_buffered().await?;
                            break;
                        }
                        s => s,
                    };

                    self.write(&bytes).await?;
                }
            }
        }

        // Transparent forwarding after Play state reached.
        loop {
            tokio::select! {
                result = self.read.read() => {
                    match result {
                        Ok(bytes) => {
                            write_frame(&mut io, &bytes).await?;
                            io.flush().await?;
                        }
                        Err(e) if matches!(*e, ReadPacketError::ConnectionClosed) => break,
                        Err(e) => return Err(io::Error::other(e)),
                    }
                }

                msg = read_frame(&mut io) => {
                    match msg? {
                        Some(bytes) => self.write.write(&bytes).await?,
                        None => break,
                    }
                }
            }
        }

        Ok(())
    }
}
