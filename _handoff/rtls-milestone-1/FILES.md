# Useful file map

## Plans and operator documentation

| File | Purpose |
| --- | --- |
| `docs/camouflage-transport-roadmap.md` | Milestones 1-5, design boundaries, acceptance criteria, and upstream maintenance policy. |
| `docs/rtls.md` | RTLS threat model, TOML examples, P2P policies, and verification commands. |

## RTLS implementation

| File | Purpose |
| --- | --- |
| `easytier/src/tunnel/rtls.rs` | TLS engine, authenticated ClientHello token, exporter proofs, replay cache, cover fallback, socket wrapper, and end-to-end tests. |
| `easytier/src/tunnel/protocol/adapters/rtls.rs` | Connects global TOML configuration to separate relay and P2P RTLS engines. |
| `easytier/src/tunnel/protocol/adapters/mod.rs` | Registers RTLS client and server adapters. |
| `easytier/src/tunnel/protocol.rs` | Native protocol adapter composition and capability tests. |
| `easytier/src/tunnel/mod.rs` | `rtls` module and `IpScheme::Rtls`. |
| `easytier/Cargo.toml` | `rtls` feature and native crypto/TLS dependencies. |

## Configuration and listener integration

| File | Purpose |
| --- | --- |
| `easytier-core/src/config/toml.rs` | `[camouflage]`, redacted relay secret, defaults, and parser tests. |
| `easytier-core/src/connectivity/protocol/mod.rs` | Maps `rtls` to TCP, defines its port metadata, and permits a handled fallback connection. |
| `easytier-core/src/listener/transport.rs` | Listener transport recognition. |
| `easytier/src/core.rs` | Keeps RTLS explicit instead of adding an unusable automatic listener. |

## TCP P2P negotiation

| File | Purpose |
| --- | --- |
| `easytier-proto/proto/peer_rpc.proto` | Backward-compatible request/response fields for TCP P2P transport negotiation. |
| `easytier-core/src/connectivity/hole_punch/tcp.rs` | Capability intersection, downgrade policy, `rtls://...?auth=p2p` URLs, and punched socket upgrade. |
| `easytier-core/src/instance/config.rs` | Normalizes `p2p_mode` into the TCP hole-punch policy. |
| `easytier-core/src/instance/mod.rs` | Supplies the native server protocol adapter to punched accepted sockets. |

## Dependency bookkeeping

| File | Purpose |
| --- | --- |
| `Cargo.lock` | Records the additional direct HMAC dependency for the native crate. |
| `rust-toolchain.toml` | Rust toolchain expected by local development and CI. |

## Tests that protect the design

The most important focused tests are in:

- `easytier/src/tunnel/rtls.rs`
  - token round trip, time window, tamper detection, and replay rejection
  - only the armed TLS session ID receives a routing token
  - authenticated engines exchange a framed EasyTier packet
  - unauthenticated standard TLS reaches the cover target
- `easytier-core/src/connectivity/hole_punch/tcp.rs`
  - P2P capability intersection and fail-closed downgrade behavior
- `easytier-core/src/instance/config.rs`
  - TOML P2P mode normalization
- `easytier-core/src/config/toml.rs`
  - configuration round trip and secret redaction

Do not modify generated protobuf Rust output manually. Edit `peer_rpc.proto` and let the
existing build scripts regenerate it.
