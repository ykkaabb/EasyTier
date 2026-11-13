# Next development steps

## 1. Validate milestone 1 on real networks

Before changing the wire format, deploy the templates in `configs/` and record:

- relay throughput in both directions;
- TCP P2P success and fallback rates across the actual NAT pair;
- reconnect behavior after Wi-Fi changes and relay restarts;
- remote-desktop latency under concurrent bulk traffic;
- behavior with 1-5% loss and clock offsets near the token-window boundary.

Keep `p2p_mode = "require"` and disable UDP hole punching when validating that no raw
direct path escapes RTLS.

## 2. Start HTTP/3 camouflage without changing upstream QUIC

Create a new `h3cam` scheme and modules. Do not alter the wire behavior of `quic://`.
Keep the new engine below the existing `Tunnel` boundary, like RTLS.

Suggested implementation order:

1. Define typed TOML fields and protocol metadata.
2. Implement a bounded admission probe before allocating expensive QUIC state.
3. Complete a normal QUIC TLS 1.3 handshake and a real HTTP/3 request.
4. Carry EasyTier packets in HTTP Datagrams with bounded queues and backpressure.
5. Add relay-only end-to-end and active-probe tests.
6. Extend UDP hole-punch negotiation only after relay H3 is stable.

## 3. UDP P2P integration

Reuse the additive negotiation approach used by TCP. Deterministically assign QUIC
client/server roles and retain the punched UDP socket for the complete QUIC connection.
The `require` policy must not silently downgrade to upstream raw UDP or QUIC.

## 4. Product integration

After both transports are stable:

- expose the same TOML fields in management APIs with redaction;
- add desktop controls without a second configuration store;
- build and test Windows and Android clients;
- ensure Android protects public transport sockets from the VPN TUN;
- add migration and release notes.

## Commit discipline

- Rebase or merge from `upstream/main` before each new milestone.
- Keep protocol, tests, documentation, and UI changes in separate atomic commits.
- Never commit real network passwords, relay secrets, or production addresses.
- Open a pull request against the fork's `main` and wait for all six workflows.
