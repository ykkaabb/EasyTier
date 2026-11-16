# RTLS 开发交接文档

最后更新：2026-11-16（Asia/Shanghai）

本文是当前 RTLS 分支的正式开发交接入口。运行配置和安全模型见
[`docs/rtls.md`](rtls.md)，长期路线见
[`docs/camouflage-transport-roadmap.md`](camouflage-transport-roadmap.md)。
`_handoff/rtls-milestone-1/` 仅保留为第一阶段的历史资料，不再代表当前状态。

## 1. 仓库与版本基线

| 项目 | 当前值 |
| --- | --- |
| Fork | <https://github.com/ykkaabb/EasyTier> |
| 开发分支 | `main` |
| 官方上游 | <https://github.com/EasyTier/EasyTier.git> |
| 上游固定基线 | `0009db4c226b3c34b0ec5350ec9dfba83252f5da` |
| RTLS 里程碑合并提交 | `99d5a0af379b95f954b7a4ab39e5e05e98917b5a` |
| 最新预发布标签 | `v2.7.0-rtls.2` |
| 标签对应提交 | `2ad4519a8a6112ac3e38ef5b9fc819bf01d5b8f3` |
| Windows GUI 内部版本 | `2.7.0-2` |

注意：该分支以当时的 `upstream/main` 提交为基线，并不是从官方 `v2.7.0`
标签直接分叉。版本名称沿用 `2.7.0-rtls.*`，但不能据此宣称已经完成与官方
2.7.0 所有组合的二进制互操作测试。

预发布资产：

- [`v2.7.0-rtls.1`](https://github.com/ykkaabb/EasyTier/releases/tag/v2.7.0-rtls.1)：
  第一阶段独立 Core 资产；其中 Windows GUI 没有 RTLS 配置界面，不应再提供给桌面用户。
- [`v2.7.0-rtls.2`](https://github.com/ykkaabb/EasyTier/releases/tag/v2.7.0-rtls.2)：
  Windows GUI 修正版，包含完整 RTLS 配置界面。该 Release 只发布 GUI 安装器和校验文件。
- `.2` 安装器的 SHA-256：
  `30c140ea4d3002d00275fcbcd4d86c5ecdd401973048178632511e9a33c6cf6e`。

Windows 安装包尚未代码签名，SmartScreen 显示未知发布者属于已知现象。

## 2. 已完成范围

### 2.1 RTLS 中继/固定 Peer

- 新增显式的 `rtls://` scheme；不会加入默认监听器集合。
- 在普通 TCP 字节流之上完成 TLS 1.3 伪装，EasyTier 的路由、虚拟 IP、子网代理、
  ACL、Peer 加密和转发模型保持不变。
- ClientHello 使用配置的 SNI，并在 TLS 兼容 session ID 中携带短时 HMAC 凭据。
- TLS 建立后通过 exporter material 完成双向共享密钥证明；不把临时证书本身当作信任根。
- 包含时间窗口、重放保护、握手超时和并发边界。
- 未通过 RTLS 认证但语法正确的 TLS ClientHello 会原样转发到 `tcp_target`。
- 中继鉴权使用独立 `relay_secret`，不要求服务节点知道业务网络密码。

### 2.2 TCP 打洞后的 RTLS P2P

- 在 `peer_rpc.proto` 中用追加字段协商打洞后的传输类型。
- `p2p_mode` 支持 `disabled`、`allow`、`require`。
- P2P 凭据从 `network_name` 和 `network_secret` 做域分离派生，不复用中继密码。
- `require` 模式禁止静默降级为裸 TCP；`allow` 模式可与旧 Peer 回退到裸 TCP。
- 保留原有连接评分、重复连接抑制和中继兜底逻辑。

### 2.3 配置、管理 API 与 Windows GUI

- TOML `[camouflage]` 已实现并带默认值、校验和敏感字段脱敏。
- 管理 Protobuf 新增可选 `CamouflageConfig`，字段号为 `81`，保持追加式演进。
- 管理 API 与 TOML 已实现双向转换及校验。
- 共享前端配置页新增独立 RTLS 区域，位于基础网络设置与普通高级设置之间。
- GUI 可配置：SNI、回落目标、中继密码、TCP P2P 策略、认证时间窗口、握手超时。
- Peer/Listener 协议选择支持 `rtls://`。
- `require` 模式下，如果 UDP 打洞仍启用，GUI 会显示绕过警告，并提供就地禁用开关。
- GUI 沿用 Core 管理配置，不引入第二份配置存储。

## 3. 未完成范围

- `h3cam`/QUIC/HTTP/3 伪装尚未实现。
- UDP 打洞后的伪装传输尚未实现；当前 UDP P2P 仍是上游原协议。
- Android 产品集成和 VpnService 公网 socket 保护尚未为 RTLS 做专项验收。
- 尚未完成 Linux、Windows、Android 的长期真 NAT soak test。
- 尚未完成丢包、切网、时钟偏差、服务重启和远程桌面并发流量的系统化回归。
- Windows 二进制未签名。
- 当前 HEAD 的前端和 Windows GUI 已验证，但最后几次连续推送触发的完整 Core 工作流
  被并发策略取消过；需要补跑一次当前 `main` 的完整绿色 CI 作为发布门禁。

## 4. 兼容性边界

| 组合 | 预期行为 | 说明 |
| --- | --- | --- |
| Fork ↔ Fork，普通协议 | 与上游行为一致 | 未启用伪装时不改变 wire format。 |
| Fork ↔ 官方 2.7.0，普通协议 | 设计上兼容 | 仍需保留自动化 mixed-version E2E 证据，不能表述为“全量验证”。 |
| Fork ↔ Fork，`rtls://` | 支持 | 两端的 SNI、服务密码和时间配置必须匹配。 |
| Fork ↔ 官方 2.7.0，`rtls://` | 不支持 | 官方版本不认识 `rtls` scheme。 |
| TCP P2P `allow` ↔ 旧 Peer | 可回退裸 TCP | 连接成功不代表流量仍有 RTLS 伪装。 |
| TCP P2P `require` ↔ 旧 Peer | 失败关闭 | 这是有意的安全策略。 |
| TCP P2P `require` + UDP 打洞开启 | 仍可能走原生 UDP | 要保证直连不绕过 RTLS，必须禁用 UDP 打洞。 |

新增管理 Protobuf 字段是 optional/additive，旧实现可以忽略未知字段；但旧 Core 不会执行
RTLS 配置。不要把“能解码配置”误认为“支持 RTLS”。

## 5. 关键代码地图

| 文件 | 责任 |
| --- | --- |
| `easytier/src/tunnel/rtls.rs` | TLS 引擎、ClientHello 凭据、exporter proof、重放缓存、回落代理、端到端测试。 |
| `easytier/src/tunnel/protocol/adapters/rtls.rs` | 把全局配置装配为中继和 P2P RTLS adapter。 |
| `easytier/src/tunnel/protocol.rs` | 注册原生协议能力。 |
| `easytier/src/tunnel/mod.rs` | `IpScheme::Rtls` 和模块入口。 |
| `easytier-core/src/config/toml.rs` | `[camouflage]` 模型、默认值、解析和脱敏。 |
| `easytier-core/src/config/api_input.rs` | 管理 API ↔ TOML 映射、RTLS URL 校验。 |
| `easytier-core/src/connectivity/hole_punch/tcp.rs` | TCP P2P 能力协商、策略交集、打洞 socket 的 RTLS 升级。 |
| `easytier-core/src/connectivity/protocol/mod.rs` | `rtls` 到 TCP 的协议元数据映射。 |
| `easytier-core/src/listener/transport.rs` | Listener scheme 识别。 |
| `easytier-proto/proto/peer_rpc.proto` | P2P 传输能力追加字段。 |
| `easytier-proto/proto/api_manage.proto` | GUI/管理端使用的 `CamouflageConfig`。 |
| `easytier-web/frontend-lib/src/components/Config.vue` | RTLS 配置 UI、校验、UDP 绕过警告。 |
| `easytier-web/frontend-lib/src/types/network.ts` | 前端 RTLS 协议和配置类型。 |
| `easytier-web/frontend-lib/src/locales/{cn,en}.yaml` | 中英文 RTLS 文案。 |
| `.github/workflows/gui-windows-release.yml` | 未签名 Windows x64 GUI 构建。 |
| `.github/workflows/publish-windows-gui-release.yml` | 从指定成功 run 发布 GUI prerelease。 |

不要手改生成的 Protobuf 代码。修改 `.proto` 后使用仓库现有构建脚本重新生成。

## 6. 配置与运行要点

完整模板位于 `_handoff/rtls-milestone-1/configs/`。最小关系如下：

```toml
[[peer]]
uri = "rtls://relay.example.com:20260"

[camouflage]
server_name = "authorized-cover.example.com"
tcp_target = "authorized-cover.example.com:443"
relay_secret = "REPLACE_WITH_A_RANDOM_SERVICE_SECRET"
p2p_mode = "require"
time_window_seconds = 30
handshake_timeout_seconds = 5

[flags]
disable_udp_hole_punching = true
disable_tcp_hole_punching = false
```

操作约束：

1. Relay 必须显式配置 `listeners = ["rtls://0.0.0.0:PORT"]`。
2. 云安全组和主机防火墙都要放行对应 TCP 端口。
3. 两端 `server_name` 必须一致，中继连接的 `relay_secret` 必须一致。
4. 使用 NTP 保持时钟同步；窗口边缘的偏差会造成间歇性认证失败。
5. `tcp_target` 必须是部署者有权使用且 Relay 能访问的服务。
6. 不得把真实密码、生产地址或私钥提交到仓库。

## 7. 新电脑接手步骤

```sh
git clone https://github.com/ykkaabb/EasyTier.git
cd EasyTier
git remote add upstream https://github.com/EasyTier/EasyTier.git
git fetch --all --prune --tags
git switch main
git pull --ff-only origin main
```

仓库通过 `rust-toolchain.toml` 固定 Rust 工具链。还需要 Node.js、pnpm、`protoc`
以及平台编译依赖。前端 package manager 版本记录在 `easytier-gui/package.json`。

建议从新分支开始后续里程碑：

```sh
git switch -c feature/h3cam-transport
```

不要直接把 `feature/camouflage-transports` 当作新基线；该分支停在 GUI 集成前的
`8ccf0fe4`，当前源代码以 `main` 为准。

## 8. 验证命令与已知证据

Rust 聚焦验证：

```sh
cargo fmt --all -- --check
cargo test --package easytier --features full tunnel::rtls::tests
cargo test --package easytier-core --features full protocol_policy_negotiates_or_fails_closed
cargo clippy --all-targets --features full --all -- -D warnings
```

前端和桌面验证：

```sh
pnpm install --frozen-lockfile
pnpm --filter easytier-frontend-lib test
pnpm --filter tauri-plugin-vpnservice-api build
pnpm --filter easytier-gui build
```

当前证据：

- RTLS 里程碑合并提交 `99d5a0af` 的 Core、Test、GUI、Mobile、OHOS、JavaScript
  Hosts 六组工作流均通过。
- GUI 配置提交后，本地 `easytier-frontend-lib` 通过 9 个测试文件、56 个测试及生产构建。
- `tauri-plugin-vpnservice-api` 与 `easytier-gui` 本地构建通过。
- Windows x64 Tauri/NSIS 构建 run
  [`43798662673`](https://github.com/ykkaabb/EasyTier/actions/runs/43798662673) 通过。
- GUI 发布 run
  [`43800793004`](https://github.com/ykkaabb/EasyTier/actions/runs/43800793004) 通过。
- `.2` 安装器从 Release 重新下载后，SHA-256 与 `SHA256SUMS.txt` 一致。
- 本机 Rust 原生测试曾受错误的 `link.exe`（GNU coreutils 而不是 MSVC linker）阻断；
  Windows 的权威原生编译证据来自上述 GitHub Actions。

发布前仍应重新运行当前 `main` 的完整 CI，不要只依赖历史 merge commit 的绿色状态。

## 9. Windows GUI 构建与发布

构建工作流只支持手动触发：

```sh
gh workflow run gui-windows-release.yml --ref main
gh run list --workflow gui-windows-release.yml --limit 5
gh run watch RUN_ID --exit-status
```

确认 artifact `easytier-gui-windows-x86_64` 非空后，再发布：

```sh
gh workflow run publish-windows-gui-release.yml --ref main \
  -f tag=v2.7.0-rtls.N \
  -f gui_run_id=SUCCESSFUL_GUI_RUN_ID \
  -f target_commit=COMMIT_USED_BY_THAT_RUN
```

关键陷阱：WiX/MSI 不接受 `2.7.0-rtls.2` 这种包含文字的 prerelease identifier。
应用内部 SemVer 必须使用类似 `2.7.0-2` 的纯数字预发布标识；GitHub Release 标签仍可用
`v2.7.0-rtls.2`。构建 run 和 `target_commit` 必须指向同一提交，禁止把旧 artifact
挂到新提交标签上。

发布后必须：

1. 检查 Release 不是 draft，且 prerelease 标记正确。
2. 检查 `.exe` 与 `SHA256SUMS.txt` 均存在且非空。
3. 重新下载 `.exe`，本地计算 SHA-256 并与发布文件比较。
4. 在干净 Windows VM 验证安装、启动、保存 RTLS 配置、重启持久化和卸载。

## 10. 建议的后续顺序

### P0：把 RTLS 变成可长期使用的基线

1. 补跑当前 `main` 的完整 CI，并记录 run URL。
2. 建立 Fork ↔ Fork、Fork ↔ 官方 2.7.0 的 mixed-version 自动化矩阵。
3. 在真实家庭 NAT/云中继上做双向吞吐、TCP P2P、切网重连、服务重启和时钟边界测试。
4. 对远程桌面场景同时记录一秒粒度 RTT、丢包、抖动、重传和传输路径，不能只看峰值吞吐。
5. 增加 RTLS parser/fallback 的 fuzz、资源上限和主动探测安全审查。
6. 合并 Core 与 GUI 的统一发布流程，淘汰 `.1` 中不完整的 GUI 资产说明。
7. 配置 Windows 代码签名并在干净系统验证升级/卸载路径。

### P1：后续伪装传输

1. 先实现 Relay-only `h3cam`，保持上游 `quic://` wire behavior 不变。
2. 完成 HTTP/3 request + HTTP Datagram 数据面、队列、背压、MTU 和丢包测试。
3. Relay 稳定后再接入 UDP 打洞协商，必须定义严格的 downgrade policy。
4. 最后做 Android VpnService socket protection、移动网络切换和漫游测试。

## 11. 提交与上游同步纪律

- 每个提交只覆盖一个架构变化，保证可编译、可回滚。
- 协议、测试、文档、UI 和发布脚本尽量拆成独立原子提交。
- 新字段只追加，不能复用已发布的 Protobuf field number。
- 新协议使用新 scheme，不改变 `tcp://`、`udp://`、`quic://` 的现有 wire format。
- 合并上游前先检查 RTLS seam，避免大范围重写上游核心。
- 合并/变基前建立临时分支，并在完成后重新运行 mixed-version 和 RTLS E2E。
- 文档和 Release notes 不得把 RTLS 描述为 Xray REALITY、sing-box AnyTLS 或 Hysteria
  的 wire-compatible 实现；它只是借鉴了主动探测回落和伪装思路。

