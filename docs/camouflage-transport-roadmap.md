# Camouflage transport roadmap

## Goal

Add optional, probe-resistant transports to EasyTier without replacing its peer graph,
routing, virtual addressing, TUN, subnet proxy, ACL, NAT traversal, or packet crypto.
The transport must work for both configured/public relay links and direct links created
by hole punching.

This fork deliberately keeps camouflage below the existing EasyTier `Tunnel` boundary.
Once a socket has been upgraded into a tunnel, the rest of EasyTier behaves exactly as
it does for TCP, UDP, WebSocket, or QUIC today.

## Terminology

- `rtls`: TLS 1.3 over TCP with a configurable cover SNI, authenticated ClientHello,
  TLS-exporter channel proofs, and byte-for-byte fallback to a configured HTTPS target.
- `h3cam`: standard QUIC plus a real HTTP/3 request and HTTP Datagrams, protected by a
  short-lived admission probe and an optional UDP fallback mapping.

These names describe TlsNet-compatible camouflage designs. They are not wire-compatible
with Xray REALITY or Hysteria and must not be advertised as such.

## Non-goals

- Do not introduce a second overlay protocol or routing table.
- Do not change EasyTier network-name/network-secret semantics.
- Do not replace EasyTier's peer handshake or packet encryption.
- Do not require a central network controller.
- Do not make camouflage mandatory for users of the upstream transports.
- Do not copy Xray, sing-box, or Hysteria source code.

## Configuration principles

The relay service identity is independent from an EasyTier network identity. A public
service node may therefore relay many foreign EasyTier networks without knowing their
names or secrets.

- Relay links authenticate with an independent service-level shared secret.
- P2P links authenticate with a domain-separated key derived from the existing
  EasyTier network name and secret.
- Both sides negotiate the P2P transport. Mixed-version peers either fall back to an
  explicitly configured upstream transport or fail closed.
- Secrets must be redacted from configuration dumps, management APIs, and logs.

Example target configuration:

```toml
listeners = ["rtls://0.0.0.0:20260"]

[network_identity]
network_name = "example-network"
network_secret = "change-me"

[camouflage]
server_name = "www.example.com"
tcp_target = "www.example.com:443"
relay_secret = "replace-with-a-random-service-secret"
p2p_mode = "require"

[[peer]]
uri = "rtls://relay.example.net:20260"
```

## Milestone 1: RTLS relay transport

1. Add a feature-gated `rtls` protocol scheme and TCP transport metadata.
2. Add typed, redacted TOML configuration for SNI, fallback target, time window, and
   service-level relay secret.
3. Implement the Rust RTLS client/server adapter at the native protocol seam.
4. Authenticate the ClientHello before returning any EasyTier protocol response.
5. Verify the service identity on the client without relying on a public CA for the
   cover name.
6. Relay unrecognized, syntactically valid TLS ClientHello traffic to the configured
   cover target without generating a distinguishable EasyTier error.
7. Add bounded handshake concurrency, deadlines, and fallback connection limits.
8. Add parser, token, certificate, adapter, fallback, and end-to-end tests.

Acceptance criteria:

- `rtls://` works anywhere a configured EasyTier peer/listener works.
- An authenticated client creates an ordinary EasyTier tunnel.
- An unauthenticated TLS client observes the configured cover target.
- Relay service credentials are independent of `network_secret`.
- Existing protocols behave identically when the feature is disabled.

## Milestone 2: RTLS over TCP hole punching

1. Replace hard-coded `tcp://` post-punch upgrades with a negotiated protocol scheme.
2. Extend the TCP hole-punch RPC with backward-compatible supported/requested transport
   fields.
3. Reuse EasyTier's existing client/server admission roles to choose TLS roles.
4. Derive a P2P camouflage key from the network identity with HMAC-SHA256 domain
   separation and bind tokens to the cover name and a time window.
5. Support `allow` and `require` policies. `require` must never silently downgrade to
   raw TCP.
6. Keep EasyTier's existing connection scoring, duplicate suppression, and failover.
7. Add direct, simultaneous-open, downgrade, replay, and mixed-version tests.

Acceptance criteria:

- Two forked nodes can establish an RTLS-protected direct connection after TCP punch.
- A mismatched network secret or peer binding fails before the EasyTier handshake.
- A required camouflage policy never emits raw EasyTier traffic.
- A relay connection stays available while EasyTier evaluates the direct path.

## Milestone 3: HTTP/3 camouflage on relay links

1. Add an `h3cam` UDP protocol scheme without changing upstream `quic://` behavior.
2. Add a bounded QUIC-shaped admission probe before allocating QUIC state.
3. Complete a standard QUIC TLS 1.3 handshake and a real HTTP/3 request.
4. Carry EasyTier packets in HTTP Datagrams with bounded queues and backpressure.
5. Add optional bounded UDP fallback mappings for unknown endpoints.
6. Add MTU, idle timeout, migration, loss, active-probe, and load tests.

## Milestone 4: HTTP/3 camouflage over UDP hole punching

1. Negotiate `h3cam` in the UDP hole-punch control flow.
2. Assign deterministic QUIC client/server roles from the existing EasyTier admission
   roles and peer IDs.
3. Upgrade the punched UDP session without rebinding or losing its NAT mapping.
4. Preserve the punched socket lifetime for the full QUIC connection.
5. Add strict downgrade policy and automatic fallback to RTLS or relay according to
   configuration.
6. Add cone, symmetric, rebinding, mobile-network, loss, and roaming tests.

## Milestone 5: Product integration

1. Add CLI help and full TOML examples.
2. Add management API fields with secret redaction.
3. Add desktop GUI controls without introducing a second configuration store.
4. Build the same transport adapters for Linux, Windows, macOS, and Android.
5. Ensure Android protects public transport sockets from its `VpnService` TUN.
6. Add release migration notes and retain compatibility with upstream configuration.

## Upstream maintenance policy

- Keep transport engines in new modules under the native `easytier` crate.
- Limit `easytier-core` changes to protocol metadata, small upgrade seams, and
  negotiated hole-punch policy.
- Guard new behavior behind Cargo features and optional configuration.
- Preserve unknown protobuf fields and use only additive field numbers.
- Maintain `upstream` as `https://github.com/EasyTier/EasyTier.git` and regularly
  rebase the feature branch onto a pinned upstream release before merging.
- Each commit must be buildable and scoped to one architectural change.

## Delivery order

The first delivery covers Milestones 1 and 2 only: RTLS for configured/relay links and
TCP P2P links. HTTP/3 work begins only after RTLS passes Linux and Windows end-to-end
tests and demonstrates stable subnet-proxy traffic under loss and reconnects.

## Current implementation status

- Milestone 1: implemented on `feature/camouflage-transports`; CI validation in progress.
- Milestone 2: transport negotiation and RTLS upgrade implemented for TCP hole punching;
  real-NAT interoperability and sustained-loss validation remain before release tagging.
- Milestones 3-5: planned only; no `h3cam` wire implementation or GUI/Android controls
  exist yet.
