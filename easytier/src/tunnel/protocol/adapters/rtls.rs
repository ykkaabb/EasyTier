use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use easytier_core::{
    config::toml::{ConfigLoader, P2pCamouflageMode},
    connectivity::{
        protocol::{
            ClientProtocolUpgrader, ServerProtocolAdmission, ServerProtocolUpgrade,
            ServerProtocolUpgrader,
        },
        transport::ConnectedTransport,
    },
    socket::udp::UdpSession,
    tunnel::Tunnel,
};

use crate::{
    common::global_ctx::ArcGlobalCtx,
    socket::tcp::RuntimeTcpSocket,
    tunnel::rtls::{RtlsEngine, RtlsSettings, derive_p2p_secret},
};

use super::{ClientAdapter, ServerAdapter};

#[derive(Debug)]
struct RtlsAdapter {
    relay_engine: Result<Arc<RtlsEngine>, Arc<str>>,
    p2p_engine: Result<Arc<RtlsEngine>, Arc<str>>,
    handshake_timeout: Duration,
}

impl RtlsAdapter {
    fn new(global_ctx: &ArcGlobalCtx) -> Self {
        let Some(config) = global_ctx.config.get_camouflage() else {
            let error: Arc<str> = Arc::from("rtls requires a [camouflage] configuration");
            return Self {
                relay_engine: Err(error.clone()),
                p2p_engine: Err(error),
                handshake_timeout: Duration::from_secs(5),
            };
        };
        let handshake_timeout = Duration::from_secs(config.handshake_timeout_seconds);
        let create_engine = |secret: Vec<u8>| {
            RtlsEngine::new(RtlsSettings {
                server_name: config.server_name.clone(),
                fallback_target: config.tcp_target.clone(),
                secret: Arc::from(secret),
                time_window: Duration::from_secs(config.time_window_seconds),
                handshake_timeout,
            })
            .map(Arc::new)
            .map_err(|error| Arc::from(error.to_string()))
        };
        let relay_engine = config
            .relay_secret
            .as_deref()
            .filter(|secret| !secret.is_empty())
            .ok_or_else(|| Arc::from("rtls requires camouflage.relay_secret"))
            .and_then(|secret| create_engine(secret.as_bytes().to_vec()));
        let network = global_ctx.config.get_network_identity();
        let p2p_engine = if config.p2p_mode == P2pCamouflageMode::Disabled {
            Err(Arc::from("RTLS P2P transport is disabled"))
        } else {
            network
                .network_secret
                .as_deref()
                .filter(|secret| !secret.is_empty())
                .ok_or_else(|| Arc::from("RTLS P2P requires a non-empty network_secret"))
                .and_then(|secret| {
                    create_engine(derive_p2p_secret(&network.network_name, secret).to_vec())
                })
        };
        Self {
            relay_engine,
            p2p_engine,
            handshake_timeout,
        }
    }

    fn engine(&self, url: &url::Url) -> anyhow::Result<&Arc<RtlsEngine>> {
        let p2p = url
            .query_pairs()
            .any(|(key, value)| key == "auth" && value == "p2p");
        let engine = if p2p {
            &self.p2p_engine
        } else {
            &self.relay_engine
        };
        engine
            .as_ref()
            .map_err(|error| anyhow::anyhow!(error.to_string()))
    }
}

pub(super) fn client_adapter(global_ctx: &ArcGlobalCtx) -> ClientAdapter {
    Arc::new(RtlsAdapter::new(global_ctx))
}

pub(super) fn server_adapter(global_ctx: &ArcGlobalCtx) -> ServerAdapter {
    Arc::new(RtlsAdapter::new(global_ctx))
}

#[async_trait]
impl ClientProtocolUpgrader<RuntimeTcpSocket> for RtlsAdapter {
    fn supports_scheme(&self, scheme: &str) -> bool {
        scheme == "rtls"
    }

    fn connect_timeout(&self, scheme: &str) -> Option<Duration> {
        (scheme == "rtls").then_some(self.handshake_timeout)
    }

    async fn upgrade_client(
        &self,
        connected: ConnectedTransport<RuntimeTcpSocket>,
        requested_url: url::Url,
    ) -> anyhow::Result<Box<dyn Tunnel>> {
        let ConnectedTransport::Tcp(socket) = connected else {
            anyhow::bail!("RTLS protocol requires a TCP transport");
        };
        Ok(tokio::time::timeout(
            self.handshake_timeout,
            self.engine(&requested_url)?.connect(socket, requested_url),
        )
        .await??)
    }
}

#[async_trait]
impl ServerProtocolUpgrader<RuntimeTcpSocket> for RtlsAdapter {
    fn supports_scheme(&self, scheme: &str) -> bool {
        scheme == "rtls"
    }

    async fn upgrade_tcp(
        &self,
        socket: RuntimeTcpSocket,
        local_url: url::Url,
    ) -> anyhow::Result<ServerProtocolUpgrade> {
        let tunnel = self.engine(&local_url)?.accept(socket, local_url).await?;
        Ok(match tunnel {
            Some(tunnel) => ServerProtocolUpgrade::Tunnel(tunnel),
            None => ServerProtocolUpgrade::Handled,
        })
    }

    async fn upgrade_udp(
        &self,
        _session: UdpSession,
        _local_url: url::Url,
        _admission: Option<ServerProtocolAdmission>,
    ) -> anyhow::Result<ServerProtocolUpgrade> {
        anyhow::bail!("RTLS protocol requires a TCP transport")
    }

    async fn upgrade_byte_stream(
        &self,
        _socket: RuntimeTcpSocket,
        _local_url: url::Url,
        _remote_url: Option<url::Url>,
    ) -> anyhow::Result<ServerProtocolUpgrade> {
        anyhow::bail!("RTLS protocol requires a TCP transport")
    }
}
