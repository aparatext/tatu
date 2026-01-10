# Tatu

Tatu is an alternative Minecraft authentication and encryption protocol.

This repository contains its reference implementation as a Rust proxy, but it can also be implemented directly in Java.

Tatu provides players with a persistent, friendly cross-server identity without relying on centralized authentication servers, while being as or more secure than `online-mode`.

- [x] Identity
    - [x] Wesolowski VDF
    - [x] Ed25519-X25519 derivation
    - [x] Discriminator base
    - [x] Keyfiles
    - [x] Recovery phrases
- [x] Noise Pipe
    - [x] Server TOFU + fingerprints
- [x] MessagePack wire
- [x] BungeeCord forwarding, Minecraft login rewriting
    - [x] Skins
    - [x] Disconnect message injection
    - [x] Server key indication in chat
    - [ ] Older Minecraft Protocol versions
      - [ ] 1.8 & 1.12
      - [ ] 1.13-1.17?
      - [ ] 1.18
      - [ ] 1.19
    - [x] Server ping responses
      - [ ] Forward actual ping data
    - [ ] Preserve FML handshake
    - [ ] Velocity forwarding
- [ ] Specify v1 protocol
    - [ ] Versioning, magic

*Future work*
- [ ] SOCKS5 interface for in-game server selection
- [ ] Fast Noise_KK handshake with known server key
  - [ ] Client key pinning (proof caching)
- [ ] Broadcast peer keys for third-party integrations like voice chat?
- [ ] Stream management & 1RTT session resumption?

## Setup

### Prerequisites

1. `cargo build --release`
> [!CAUTION]
> Debug builds use a lower handle difficulty for quicker testing, breaking its security guarantees and compatiblity with release!

2. `cp ./target/release/{tatu-server,tatu-client} ~/.local/bin`

### Server

1. Install a BungeeCord-compatible modded server (Paper recommended).
2. Set `online-mode=false`, `server-port=25564`, `server-ip=127.0.0.1` in server.properties and `bungeecord: true` in spigot.yaml.
3. Run: `tatu-server 0.0.0.0:25519 127.0.0.1:25564`.
4. (optional) Install Velocity in legacy mode (or any BungeeCord-compatible proxy) to colocate with Mojang authentication.

> [!CAUTION]
> Do not expose the backend Minecraft server to WAN. Only forward Velocity and Tatu.

### Client

1. (optional) Prepare your skin:
    - Copy another player's skin: `PLAYER=jeb_; curl "https://sessionserver.mojang.com/session/minecraft/profile/$(curl https://api.mojang.com/users/profiles/minecraft/$PLAYER | jq .id -r)?unsigned=false" | jq .properties`
   - Upload your PNG to MineSkin.org. 
      - Copy the Value and Signature blobs into the appropriate fields. See template below:
      - `[{"name": "textures", "value": "ewogICJ0aW1lc3Rh...", "signature": "VbBnt+S6b/SpmBqY..."}]`
   - Save it as `my-wonderful.skin`
   
2. Run: `tatu-client my-awesome-server.net:25519 [--skin my.skin]`

3. Set the launcher to offline mode and pick your nickname.

4. Connect to `localhost:25565`.
