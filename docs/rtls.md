# RTLS transport

RTLS is this fork's optional TLS 1.3 transport for EasyTier configured links and TCP
hole-punched P2P links. It keeps EasyTier's routing, peer graph, virtual IP, subnet
proxy, ACL, and packet encryption unchanged; only the byte stream below an EasyTier
tunnel is replaced.

RTLS is an EasyTier-specific protocol. It is not wire-compatible with Xray REALITY,
sing-box, Hysteria, or ordinary HTTPS.

## Security and camouflage model

- The ClientHello carries a short-lived HMAC token in its TLS 1.3 compatibility
  session ID. It uses the configured `server_name` as SNI.
- After TLS completes, both sides prove the shared key over TLS exporter material.
  An ephemeral certificate alone is never trusted.
- Tokens accept the current and one adjacent time window and are rejected on replay.
- A syntactically valid but unauthenticated TLS ClientHello is forwarded byte-for-byte
  to `tcp_target`. Non-TLS or malformed probes are closed.
- Relay authentication uses `relay_secret`, which is deliberately independent from
  the EasyTier network name and secret.
- P2P authentication derives a distinct key from `network_name` and `network_secret`.

Use a high-entropy random `relay_secret` and keep clocks synchronized with NTP. The
cover target must be a service you are authorized to use and must be reachable from
the listening node. A cover name does not grant permission to impersonate or misuse
that domain.

## Relay service configuration

The relay is a normal EasyTier node with an explicit `rtls://` listener. RTLS is not
added to the automatic listener set, so it must be listed explicitly.

```toml
instance_name = "rtls-relay"
hostname = "rtls-relay"
listeners = ["rtls://0.0.0.0:20260"]

[network_identity]
network_name = "public-relay"
network_secret = ""

[camouflage]
server_name = "www.speedtest.cn"
tcp_target = "www.speedtest.cn:443"
relay_secret = "REPLACE_WITH_A_LONG_RANDOM_SERVICE_SECRET"
p2p_mode = "disabled"
time_window_seconds = 30
handshake_timeout_seconds = 5
```

Allow TCP port `20260` in both the cloud security group and the host firewall, then
start the node:

```sh
easytier-core --config-file /etc/easytier/rtls-relay.toml
```

## Ordinary client configuration

`relay_secret` and `server_name` must exactly match the relay. `p2p_mode = "require"`
requests RTLS after TCP hole punching and refuses a raw-TCP downgrade.

```toml
instance_name = "tx-air"
hostname = "TX-Air"
ipv4 = "192.168.100.2"

[[peer]]
uri = "rtls://relay.example.com:20260"

[network_identity]
network_name = "zyk7788"
network_secret = "REPLACE_WITH_THE_EASYTIER_NETWORK_SECRET"

[camouflage]
server_name = "www.speedtest.cn"
tcp_target = "www.speedtest.cn:443"
relay_secret = "REPLACE_WITH_A_LONG_RANDOM_SERVICE_SECRET"
p2p_mode = "require"
time_window_seconds = 30
handshake_timeout_seconds = 5

[flags]
disable_udp_hole_punching = true
disable_tcp_hole_punching = false
```

Disabling UDP hole punching is necessary only when every direct link must use RTLS.
If it remains enabled, EasyTier can still select its original UDP P2P transport.

## Home subnet gateway configuration

```toml
instance_name = "fnos"
hostname = "fnos"
ipv4 = "192.168.100.1"

[[peer]]
uri = "rtls://relay.example.com:20260"

[[proxy_network]]
cidr = "192.168.3.0/24"

[network_identity]
network_name = "zyk7788"
network_secret = "REPLACE_WITH_THE_EASYTIER_NETWORK_SECRET"

[camouflage]
server_name = "www.speedtest.cn"
tcp_target = "www.speedtest.cn:443"
relay_secret = "REPLACE_WITH_A_LONG_RANDOM_SERVICE_SECRET"
p2p_mode = "require"
time_window_seconds = 30
handshake_timeout_seconds = 5

[flags]
disable_udp_hole_punching = true
disable_tcp_hole_punching = false
```

## P2P policy

`camouflage.p2p_mode` has three values:

| Value | TCP hole-punch behavior |
| --- | --- |
| `disabled` | Use the upstream raw TCP transport. |
| `allow` | Prefer RTLS, but allow negotiation to fall back to raw TCP. |
| `require` | Require RTLS and fail closed if the peer cannot negotiate it. |

All nodes that use P2P RTLS need the same `network_name`, `network_secret`, and
`server_name`. `relay_secret` is used only for configured `rtls://` relay links.

## Verification

On the relay, verify that the listener exists:

```sh
ss -lntp | grep 20260
```

On each client, inspect peers with `easytier-cli peer`. A configured relay connection
shows `rtls`; a successful TCP P2P upgrade also reports `rtls`. For throughput, run
`iperf3` between virtual IPs in both directions. For latency-sensitive validation,
also run UDP tests with one-second intervals and check loss and jitter rather than only
the peak TCP number.

## Current limitations

- Only TLS/TCP camouflage is implemented. HTTP/3 camouflage is a later milestone.
- The P2P negotiation is additive and backward-compatible, but `require` intentionally
  cannot connect to an unmodified peer through raw TCP.
- The first delivery still needs real-NAT soak tests on Linux and Windows before a
  release tag is suitable for unattended production use.
