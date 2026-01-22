# tatu

> [!IMPORTANT]
> _Here be dragons!_ This is pre-1.0 software.
> 
> Things will break in unforeseen ways, though the worst is probably behind us.
> Just keep a plan B around in case of emergency...

tatu is a decentralized Minecraft authentication protocol with portable handles and sound transit encryption.

Each tatu player has a persistent, irrevocable identity—a key with an immutable UUID—addressed by _handles_ like `jeb_#jsfn5639`. Handles are approximately unique player-chosen names; a key can have many, and the player chooses which to present.

Whitelists, skins, bans, permissions, and inventories just work with no auth infrastructure, self-hosted or Mojang. Your UUID and name are preserved across servers with no operator coordination. Connections are encrypted and authenticated from the first packet: your university admin, coffee shop owner, or sketchy hotspot can't tell you're jeb_, eavesdrop on your {Simple Voice C, c}hat, find your base coordinates, or /op themselves as you. Players can create additional accounts, like camera bots, chat bouncers, miners, map art builders, and alts.

This repository contains the reference implementation as a Rust proxy. It can also be implemented as a Java mod.

For a closer look at the underlying cryptography and wire format, you should see [PROTOCOL.md](PROTOCOL.md).


## Why not...

Password plugins like AuthMe send long-term, human-chosen secrets over the wire as plaintext and rely on servers to manage them. Identity is scoped to one server; if the database leaks or the network is tapped, the damage is irrecoverable and spreads to every server where you reused that password. Without session encryption, everything else travels in the clear too.

The only solution is client-side software—password auto-entry mods, TOTP codes, and WireGuard for transit encryption. If genuine security requires software beyond the vanilla game, why stop there?

Auth servers are a proper solution—community-hosted, reverse-engineered Mojang infrastructure, sharing all online-mode properties, patched into the client. But nobody _wants_ to self-host identity services—maintaining credential databases, OAuth integrations, and web portals—especially small servers. In practice, everyone centralizes on one dominant provider, reproducing the same captive relationship.


## How it works

When you first run tatu-client, it will generate a _keyfile_ and display a 12-word _recovery phrase_. You'll see it twice: once in your terminal at generation and once in-game on your first connection. If you can, write it down **now** on a piece of paper or in a password manager. This is the only way to recover your identity if you lose the keyfile. Recovery phrases can correct up to 10 character transcription errors.

Your keyfile is at `~/.config/tatu/identity.key`. Protect both the keyfile and the phrase like an SSH private key—anyone with either **is** you.

Servers have their own keyfiles too (but not recovery phrases), so back those up. If you lose or rotate the server key post-compromise, clients will refuse to connect until players manually unpin the old key. You might also want to publish your public key (shown at server startup) to a trusted channel, like your website or Discord server, so that players won't have to blindly trust on first use.

When you connect with a nick (set by your launcher in offline mode) for the first time, tatu will _mine_ your handle. This takes around 40 seconds, once per nick, cached and reused across all servers. The delay is intentional and prevents impersonation. Since handles are derived deterministically from your key and nick, your _discriminator_ (the part after #) will stay the same for that nick everywhere, as long as you preserve your key.


## Roadmap

### 0.3: The Network Update

  - [x] Abstract Minecraft players
  - [ ] (0.3.0) Take Minecraft Protocol in-house
    - [ ] (0.3.1) Support legacy Minecraft versions (1.8, 1.12, 1.18, 1.19)
  - [ ] Preserve FML handshake
  - [ ] Server Ping forwarding
  - [ ] Rewrite NoisePipe
  
### 0.4: The Housekeeping Update

  - [ ] Rebrand tatu-common as tatu-lib
    - [ ] Remove anyhow from common
    - [ ] Remove all `unwrap()`
    - [ ] Factor out minecraft protocol
  - [ ] Profile throughput/binary size
    - [x] Remove clap
    - [ ] Remoze azalea
  - [ ] `tatu-keys` command
    - [ ] `tatu-keys recover -k [id.key]`
    - [ ] `cat id.key | tatu-keys pub [--uuid]`
    - [ ] `tatu-keys mine wizard [-k id.key]`
    - [ ] `tatu-keys gen id.key`
  - [ ] VDF progress indication
  - [ ] tracing integration in game chat
  - [ ] CONTRIBUTING.md

### 1.0: The Foundational Update

  - [ ] PROTOCOL.md
    - [ ] Versioning, magic
    - [ ] Compatibility guarantees
  - [ ] SECURITY.md
  - [ ] Call for comments

### The Backlog

  - [ ] SOCKS5 interface for in-game server selection
  - [ ] Velocity forwarding
  - [ ] Server-initiated challenges for moderation
  - [ ] Handle proof caching
    - [ ] Fast Noise_KK handshake
      - [ ] 1-RTT session resumption?
  - [ ] Key succession?
  - [ ] Transparent peer key broadcast; enables possible e2ee voice chat integration, chat signing (incompatible with Minecraft's RSA-based SecureChat)


## Getting started

### Building

```bash
cargo install --git https://github.com/aparatext/tatu tatu-server tatu-client
```

> [!WARNING]
> Debug builds use cryptographic parameters chosen for quicker testing at the expense of security.
> They are unfit for and incompatible with production.

### Players

1. Run: `tatu-client run my-awesome-server.net:25519 -s my.skin`
2. Set your launcher to offline mode and choose your nick.
3. Connect to `localhost:25565`.

> [!TIP]
> To skip "Chat messages can't be verified" warnings, you should install [No Chat Reports](https://modrinth.com/mod/no-chat-reports) mod.

#### Skins

To remain compatible with vanilla clients and Mojang-colocated servers, Mojang skin servers were chosen as the recommended setup. tatu exposes raw property forwarding, so if a client mod disabling signing and origin checking is made and every player installs it, unsigned textures could be sent directly as data URIs.

Minecraft skins consist of a base64-encoded JSON payload pointing at texture URLs validated to originate at `minecraft.net` (value) and a Mojang server signature. Despite the timestamp and UUID included in the signed blob, expiration and ownership aren't enforced by the client, allowing us to upload and sign the skin once and reuse it indefinitely.

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
4. Set
```
unsuported-settings:
  perform-username-validation: false
```
in `config/paper-global.yml`.
5. Run: `tatu-server 0.0.0.0:25519 127.0.0.1:25564`

> [!CAUTION]
> Do not expose the backend server to WAN. Only forward tatu (and Velocity, if colocated).

#### Mojang (Velocity) colocation

**TODO**
