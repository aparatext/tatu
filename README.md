# tatu

> [!IMPORTANT]
> _Here be dragons!_ This is pre-1.0 software.
> 
> Things will break in unforeseen ways, though the worst is probably behind us.
> Just keep a plan-B around in case of emergency...

tatu is a decentralized Minecraft authentication protocol with portable handles and sound transit encryption.

Each tatu player has a persistent, irrevocable identity—a key with an immutable UUID—addressed by _handles_ like `jeb_#jsfn5639`. Handles are approximately-unique player-chosen names; a key can have many, and the player chooses which to present.

Whitelists, bans, permissions, and inventories just work with no auth infrastructure, self-hosted or Mojang. Accounts are free to create, so bots and alt accounts cost nothing. Connections are encrypted and authenticated from the start, so (voice) chat, player identity, and game data don't leak to your network admin.

This repository contains the reference implementation as a Rust proxy. It can also be implemented as a Java mod.

For a closer look at the underlying cryptography and wire format, you should see [PROTOCOL.md](PROTOCOL.md).


## TODO

<details>
<summary>1.0 Roadmap...</summary>

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
      - [ ] (?) 1.13 - 1.17
      - [ ] 1.18
      - [ ] 1.19
    - [x] Server ping responses
      - [ ] Forward actual ping data
    - [ ] Preserve FML handshake
    - [ ] Velocity forwarding
- [ ] Specify v1 protocol
    - [ ] Versioning, magic
- [ ] tracing game chat integration

*Future work*
- [ ] SOCKS5 interface for in-game server selection
- [ ] Fast Noise_KK handshake with known server key
  - [ ] Client key pinning (proof caching)
- [ ] Server-initiated VDF challenges for spam/afk prevention?
- [ ] Broadcast peer keys w/ transparency for third-party integrations like voice chat?
- [ ] Stream management & 1RTT session resumption?
</details>


## How it works

When you first run tatu-client, it will generate a _keyfile_ and display a 12-word _recovery phrase_. You'll only see it **once more** in-game on your first server connection. If you can, write it down **now** on a piece of paper or in a password manager. This is the only way to recover your identity if you lose the keyfile. Recovery phrases tolerate up to 10 characters of transcription errors.

Your keyfile is at `~/.config/tatu/identity.key`. Protect both keyfile and phrase like an SSH private key—anyone with either **is** you.

Servers have their own keyfiles too (but not recovery phrases), so back those up. If you lose or rotate the server key post-compromise, clients will refuse to connect until players manually unpin the old one.

When you connect with a nick (set by your launcher in offline mode) for the first time, tatu will _mine_ your handle. This takes around 40 seconds, once per nick, cached and reused across all servers. The delay is intentional and prevents impersonation. Since handles are derived deterministically from your key and nick, your _discriminator_ (the part after #) will stay the same for that nick everywhere, as long as you preserve your key.


## Getting started

### Building

```bash
cargo install --git https://github.com/aparatext/tatu tatu-server tatu-client
```

> [!WARNING]
> Debug builds use cryptographic parameters chosen for quicker testing at the expense of security.
> They are unfit for and incompatible with production.

### Players

1. Run: `tatu-client my-awesome-server.net:25519 [--skin my.skin]`
2. Set your launcher to offline mode and choose your nick.
3. Connect to `localhost:25565`.

> [!TIP]
> To skip "Chat messages can't be verified" warnings, you should install [No Chat Reports](https://modrinth.com/mod/no-chat-reports) mod.

#### Skins

To remain compatible with unmodified clients and Mojang-colocated servers, it was decided to stay reliant on Microsoft's skin infrastructure. tatu exposes raw property forwarding, so if a client mod disabling signing and origin checking is made and everyone installs it, unsigned textures could be sent directly as data URIs.

Minecraft skins consist of a base64-encoded JSON payload, pointing at texture URLs validated to originate at `minecraft.net`, (value) and a Mojang server signature. Despite the timestamp and UUID included in the signed blob, expiration and ownership aren't enforced by the client, allowing us to upload and sign the skin once and reuse it indefinitely.

You may either rip another player's skin via the command below:

```bash
PLAYER=jeb_
curl "https://sessionserver.mojang.com/session/minecraft/profile/$( \
  curl https://api.mojang.com/users/profiles/minecraft/$PLAYER | jq -r .id \
)?unsigned=false" | jq .properties > "$PLAYER.skin"
```

Or you may use [Mineskin](https://mineskin.org/) to sign your texture for free.

1. Upload your texture.
2. Show jobs > `<your file name>`
3. Insert Skin Value and Signature into the template below:
```json
[{ "name": "textures",
   "value": "ewogICJ0aW1lc3Rh...",
   "signature": "VbBnt+S6b/SpmBqY..." }]
```

4. Save it as `anything.skin`.


### Operators

1. Install a BungeeCord-compatible server (Paper recommended).
2. Configure `server.properties`:
```
online-mode=false
enforce-secure-profile=false
server-port=25564
server-ip=127.0.0.1
```
3. Set `bungeecord: true` in `spigot.yml`.
4. Run: `tatu-server 0.0.0.0:25519 127.0.0.1:25564`

> [!CAUTION]
> Do not expose the backend server to WAN. Only forward tatu (and Velocity, if colocated).

#### Mojang (Velocity) colocation

**TODO**
