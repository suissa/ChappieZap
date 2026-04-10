# zigwhats — WhatsApp Web Client Library for Zig

## Overview

A Zig library implementing the WhatsApp Web protocol: WebSocket transport, Noise XX handshake (AES-256-GCM + Curve25519), WA binary protocol encoding/decoding, and protobuf message handling. Targets Zig 0.16 (master/nightly).

Reference implementation: `/home/jlucaso/projects/whatsapp-rust` (Rust, feature-complete). Always consult it for protocol correctness.

## Architecture

```
src/
├── client.zig            # High-level client: connect → handshake → encrypted I/O
├── socket.zig            # NoiseSocket: post-handshake AES-256-GCM frame encrypt/decrypt
├── noise.zig             # Noise XX state machine (handshake crypto)
├── framing.zig           # WA frame codec (3-byte BE length prefix)
├── websocket_client.zig  # Raw WebSocket client (ws:// and wss://, RFC 6455)
├── xed25519.zig          # X25519 DH + Ed25519 signatures
├── binary.zig            # WA binary protocol Node encode/decode
├── root.zig              # Library re-exports
├── main.zig              # CLI entry point
└── gen/
    ├── whatsapp.pb.zig   # Generated protobuf types
    └── tokens_generated.zig  # Token dictionary (compile-time)
tests/
└── e2e.zig               # E2E tests against mock server (bartender)
```

### Module Dependency Graph

```
client → websocket_client, noise, xed25519, framing, socket, whatsapp_proto
socket → websocket_client, framing
noise  → xed25519
```

### Key Types

| Type | Module | Purpose |
|------|--------|---------|
| `Client` | client.zig | User-facing API: init, connect, receiveFrame, sendFrame |
| `NoiseSocket` | socket.zig | Encrypted frame I/O with counter-mode AES-GCM |
| `NoiseCipher` | socket.zig | Post-handshake AES-256-GCM (empty AAD, counter nonce) |
| `Noise.NoiseState` | noise.zig | Handshake state: MixHash, MixKey, encrypt/decrypt with hash AAD |
| `Noise.ClientHandshake` | noise.zig | Client-side Noise XX handshake |
| `WebSocketClient` | websocket_client.zig | HTTP upgrade + WebSocket framing with client masking |
| `FrameDecoder` | framing.zig | Streaming frame decoder (accumulate + extract) |
| `XEd25519.KeyPair` | xed25519.zig | Combined X25519/Ed25519 keypair |

## Build & Test

```bash
zig build              # Build executable
zig build test         # Run unit tests
zig build e2e          # Run e2e tests (requires mock server on localhost:8080)
zig build run          # Build and run
zig build gen-proto    # Regenerate protobuf types from proto/whatsapp.proto
```

### Mock Server

E2E tests require the bartender mock server:

```bash
# From the whatsapp-rust repo:
cargo run -p whatsapp-mock-server -- --host 0.0.0.0 --no-tls \
  --adv-secret-key AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
```

Server listens on `ws://localhost:8080/ws/chat`. Tests connect without TLS.

## Protocol Details

### Connection Flow

1. WebSocket connect to `wss://web.whatsapp.com/ws/chat` (or `ws://` for mock)
2. Noise XX handshake:
   - ClientHello: send ephemeral public key (framed with WA_CONN_HEADER `[0x57, 0x41, 0x06, 0x03]`)
   - ServerHello: receive + decrypt server ephemeral, static key, certificate chain
   - ClientFinish: encrypt + send client static key and ClientPayload (framed, no header)
3. Extract cipher pair (write_key, read_key) via HKDF split
4. Switch to NoiseSocket for encrypted communication

### Encryption Differences

| Phase | Cipher | AAD | Nonce |
|-------|--------|-----|-------|
| Handshake | AES-256-GCM | Hash state (h) | Counter-based, resets on MixKey |
| Post-handshake | AES-256-GCM | Empty (`""`) | Counter-based, never resets |

### Frame Format

```
[optional header][3-byte BE length][payload]
```

- ClientHello includes WA_CONN_HEADER (`WA\x06\x03`)
- All subsequent frames: no header, just length + payload
- Max frame size: 16 MB

### Post-Handshake Data Flow

```
WebSocket binary msg → FrameDecoder (3-byte length) → NoiseCipher.decrypt
  → unpack (flag byte: bit 1 = zlib compressed, skip byte 0)
  → binary.decodeNode → Node { tag, attrs, content }
```

## Dependencies

- `zig-protobuf` (zig-master branch): protobuf encoding/decoding
- No external WebSocket or TLS libraries — uses `std.http.Client` for TLS

## Zig 0.16 API Notes

- `main` accepts `std.process.Init` (provides `io: std.Io`, `gpa: Allocator`)
- Randomness: `io.random(&buf)` (not `std.crypto.random`)
- Ed25519: `KeyPair.generate(io)` (takes Io parameter)
- I/O: `std.Io.Reader` / `std.Io.Writer` (vtable-based, buffered)
- Protobuf encoding: `std.Io.Writer.Allocating`
- Tests: `std.testing.io` (const, not function)

## Reference Implementation

The Rust library at `/home/jlucaso/projects/whatsapp-rust` is the authoritative reference:

| Zig module | Rust equivalent |
|------------|----------------|
| client.zig | src/handshake.rs + src/client.rs |
| socket.zig | src/socket/noise_socket.rs |
| noise.zig | wacore/noise/src/state.rs + handshake.rs |
| framing.zig | wacore/noise/src/framing.rs |
| binary.zig | wacore/binary/src/decoder.rs + encoder.rs |
| xed25519.zig | Uses libsignal's Curve25519/Ed25519 |

Always check the Rust implementation when something doesn't work as expected.
