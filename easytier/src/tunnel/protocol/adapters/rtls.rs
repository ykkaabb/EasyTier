use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use easytier_core::{
    config::toml::ConfigLoader,
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
    tunnel::rtls::{RtlsEngine, RtlsSettings},
};

use super::{ClientAdapter, ServerAdapter};

#[derive(Debug)]
struct RtlsAdapter {
    engine: Result<Arc<RtlsEngine>, Arc<str>>,
    handshake_timeout: Duration,
}

impl RtlsAdapter {
    fn new(global_ctx: &ArcGlobalCtx) -> Self {
        let result = (|| {
            let config = global_ctx
                .config
                .get_camouflage()
                .ok_or_else(|| anyhow::anyhow!("rtls requires a [camouflage] configuration"))?;
            let secret = config
                .relay_secret
                .filter(|secret| !secret.is_empty())
                .ok_or_else(|| anyhow::anyhow!("rtls requires camouflage.relay_secret"))?;
            let handshake_timeout = Duration::from_secs(config.handshake_timeout_seconds);
            Ok((
                Arc::new(RtlsEngine::new(RtlsSettings {
                    server_name: config.server_name,
                    fallback_target: config.tcp_target,
                    secret: Arc::from(secret.into_bytes()),
                    time_window: Duration::from_secs(config.time_window_seconds),
                    handshake_timeout,
                })?),
                handshake_timeout,
            ))
        })();
        match result {
            Ok((engine, handshake_timeout)) => Self {
                engine: Ok(engine),
                handshake_timeout,
            },
            Err(error) => Self {
                engine: Err(Arc::from(error.to_string())),
                handshake_timeout: Duration::from_secs(5),
            },
        }
    }

    fn engine(&self) -> anyhow::Result<&Arc<RtlsEngine>> {
        self.engine
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
            self.engine()?.connect(socket, requested_url),
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
        let tunnel = self.engine()?.accept(socket, local_url).await?;
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
