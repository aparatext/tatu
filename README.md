# Tatu

Tatu is an alternative Minecraft authentication and encryption protocol.

This repository contains its reference implementation as a Rust proxy, but it can also be implemented directly in Java.

Tatu provides players with a persistent, friendly cross-server identity without relying on centralized authentication servers, while being as or more secure than `online-mode`.

- [x] Identity
    - [x] Wesolowski VDF
    - [x] Ed25519-X25519 binding
    - [x] Discriminator encoding
    - [x] Key files
    - [ ] Recovery phrases
- [x] Noise Pipe
    - [x] Server key pinning
- [x] MessagePack wire
- [x] BungeeCord forwarding, Minecraft packet rewriting
    - [ ] Velocity Forwarding
    - [x] Skins
    - [x] Server error injection
    - [x] Server key indication in chat
    - [ ] Arbitrary Minecraft protocol version
    - [ ] FML handshake
- [ ] Specify v1 protocol
    - [ ] Versioning, magic

*Future work*
- [ ] SOCKS5 interface for in-game server selection
- [ ] Fast Noise_KK handshake with known server key
  - [ ] Client key pinning
- [ ] Broadcast peer keys for third-party integrations like voice chat
- [ ] Stream management & 1RTT session resumption?
- [ ] Protocol-aware flushing
- [ ] Custom chunk wire with Hilbert ordering + zstd?

## Setup

### Prerequisites

1. `cargo build --release`
   Debug builds use lower difficulty for quicker testing, breaking the security guarantees and consistency of player names with release, and may also add additional encryption latency.

2. `cp ./target/release/{tatu-server,tatu-client} ~/.local/bin`

### Server

1. Install a BungeeCord-compatible modded server (Paper recommended).
2. Enable offline-mode in server.properties and bungeecord in spigot.yaml. Set your server to listen on `127.0.0.1:25564` only.
3. Run `tatu-server 0.0.0.0:25519 127.0.0.1:25564`.
4. (optional) Install Velocity (or any BungeeCord-compatible proxy) to cohost with Mojang auth.

### Client

1. (optional) Prepare your skin:   
    - Copy another player's skin: `PLAYER=jeb_; curl "https://sessionserver.mojang.com/session/minecraft/profile/$(curl https://api.mojang.com/users/profiles/minecraft/$PLAYER | jq .id -r)?unsigned=false" | jq .properties`

   - Upload your PNG to MineSkin.org. 
      - Copy the "properties" from /give player head command
      - Convert SNBT to JSON (add quotes around keys). It should now look something like this: `[{"name": "textures", "value": "ewogICJ0aW1lc3Rh...", "signature": "VbBnt+S6b/SpmBqY..."}]`

   - Save it as `my-wonderful.skin`
   
2. Run: `tatu-client my-awesome-server.net:25519 --skin my.skin`

3. Set your nick in the launcher.

4. Connect to `localhost:25565`.
