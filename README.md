# Tatu

Tatu is an alternative Minecraft authentication and encryption protocol.

This repository contains its reference implementation as a Rust proxy, but it can also be implemented directly in Java.

Tatu provides players with a persistent, friendly cross-server identity without relying on centralized authentication servers, while being as or more secure than `online-mode`.

- [x] Identity
    - [x] Weseloski VDF
    - [x] Ed25519-X25519 binding
    - [x] Discriminator encoding
    - [x] Key files
    - [ ] Recovery phrases
- [x] Noise Pipe
    - [x] Server key pinning
- [x] MessagePack wire
- [x] BungeeCord forwarding
    - [x] Skins
    - [ ] Client errors as Minecraft connection errors
    - [ ] Server key as client chat message
    - [ ] Arbitrary Minecraft protocol version
    - [ ] FML handshake
- [ ] Specify v1 protocol
    - [ ] Versioning, magic

*Future work*
  - [ ] Fast Noise_KK handshake with known server key
        - [ ] Client key pinning
  - [ ] Stream management & 1RTT session resumption?
  - [ ] Protocol-aware flushing
  - [ ] Custom chunk wire with Hilbert curve ordering + zstd?

