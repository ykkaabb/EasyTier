# RTLS milestone 1 handoff

This temporary directory is the entry point for continuing development on another
computer. The actual source of truth remains in its normal repository locations; do
not copy source files into this directory or edit duplicated implementations here.

## Repository state

- Repository: <https://github.com/ykkaabb/EasyTier>
- Baseline branch: `main`
- RTLS merge commit: `99d5a0af379b95f954b7a4ab39e5e05e98917b5a`
- Merged pull request: <https://github.com/ykkaabb/EasyTier/pull/1>
- Delivered scope: configured/relay RTLS links and negotiated RTLS over TCP hole punching
- Deferred scope: `h3cam`, UDP hole punching, GUI controls, and Android product integration

All six final workflows passed on merge: Core, Test, GUI, Mobile, OHOS, and JavaScript
Hosts. The Test workflow included formatting, Clippy with `-D warnings`, WASI, test
archive compilation, and the complete nextest suite.

## Start on another computer

```sh
git clone https://github.com/ykkaabb/EasyTier.git
cd EasyTier
git remote add upstream https://github.com/EasyTier/EasyTier.git
git fetch --all --prune
git switch main
git pull --ff-only origin main
git switch -c feature/h3cam-transport
```

Use the Rust version pinned by `rust-toolchain.toml`. Install `protoc` because the P2P
transport negotiation changes `easytier-proto/proto/peer_rpc.proto`.

## Read in this order

1. `docs/camouflage-transport-roadmap.md` — complete delivery plan and boundaries.
2. `docs/rtls.md` — current configuration, security model, and verification procedure.
3. `_handoff/rtls-milestone-1/FILES.md` — useful source files and why they matter.
4. `_handoff/rtls-milestone-1/NEXT_STEPS.md` — safe continuation sequence.
5. `_handoff/rtls-milestone-1/configs/` — sanitized runnable templates.

## Fast validation

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --features full --all -- -D warnings
cargo nextest run --package easytier --package easytier-core --features full
```

The full suite contains privileged Linux network tests. When only changing RTLS, first
run the focused tests, then rely on the pull-request workflow for the complete suite:

```sh
cargo test --package easytier --features full tunnel::rtls::tests
cargo test --package easytier-core --features full protocol_policy_negotiates_or_fails_closed
```

## Important operational rule

`camouflage.p2p_mode = "require"` prevents raw TCP downgrade, but EasyTier may still
choose its original UDP P2P path. Set `flags.disable_udp_hole_punching = true` when all
direct links must use RTLS.

This handoff directory may be deleted after the next developer has cloned the repo and
confirmed the baseline.
