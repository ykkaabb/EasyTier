use std::{
    collections::HashMap,
    fmt, io,
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use hmac::{Hmac, Mac};
use rcgen::generate_simple_self_signed;
use rustls::{
    ClientConfig, ServerConfig,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::{CryptoProvider, GetRandomFailed, SecureRandom},
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime},
};
use sha2::Sha256;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::TcpStream,
};
use tokio_rustls::{TlsAcceptor, TlsConnector, TlsStream};

use crate::{proto::common::TunnelInfo, socket::tcp::RuntimeTcpSocket};
use easytier_core::{
    socket::tcp::{VirtualTcpSocket, VirtualTcpSplit},
    tunnel::{Tunnel, TunnelError, tcp::TcpTunnelUpgrader},
};

type HmacSha256 = Hmac<Sha256>;

const TOKEN_BYTES: usize = 32;
const TOKEN_NONCE_BYTES: usize = 12;
const TOKEN_TAG_BYTES: usize = 16;
const MAX_CLIENT_HELLO_BYTES: usize = 64 * 1024;
const EXPORTER_LABEL: &[u8] = b"EXPORTER-EasyTier-RTLS-v1";
const TOKEN_LABEL: &[u8] = b"easytier-rtls-route-v1";
const SERVER_PROOF_LABEL: &[u8] = b"easytier-rtls-server-proof-v1";
const CLIENT_PROOF_LABEL: &[u8] = b"easytier-rtls-client-proof-v1";
const P2P_KEY_LABEL: &[u8] = b"easytier-rtls-p2p-key-v1";

pub(crate) fn derive_p2p_secret(network_name: &str, network_secret: &str) -> [u8; 32] {
    let mut mac =
        HmacSha256::new_from_slice(network_secret.as_bytes()).expect("HMAC accepts every key size");
    mac.update(P2P_KEY_LABEL);
    mac.update(network_name.as_bytes());
    mac.finalize().into_bytes().into()
}

#[derive(Clone)]
pub(crate) struct RtlsSettings {
    pub server_name: String,
    pub fallback_target: Option<String>,
    pub secret: Arc<[u8]>,
    pub time_window: Duration,
    pub handshake_timeout: Duration,
}

impl fmt::Debug for RtlsSettings {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RtlsSettings")
            .field("server_name", &self.server_name)
            .field("fallback_target", &self.fallback_target)
            .field("secret", &"<redacted>")
            .field("time_window", &self.time_window)
            .field("handshake_timeout", &self.handshake_timeout)
            .finish()
    }
}

#[derive(Debug)]
struct TokenRandom {
    inner: &'static dyn SecureRandom,
    server_name: String,
    secret: Arc<[u8]>,
    time_window: Duration,
    tag_next_session_id: AtomicBool,
}

impl TokenRandom {
    fn arm(&self) {
        self.tag_next_session_id.store(true, Ordering::Release);
    }
}

impl SecureRandom for TokenRandom {
    fn fill(&self, bytes: &mut [u8]) -> Result<(), GetRandomFailed> {
        self.inner.fill(bytes)?;
        if bytes.len() == TOKEN_BYTES && self.tag_next_session_id.swap(false, Ordering::AcqRel) {
            let mut nonce = [0_u8; TOKEN_NONCE_BYTES];
            self.inner.fill(&mut nonce)?;
            bytes.copy_from_slice(&new_token(
                &self.secret,
                &self.server_name,
                self.time_window,
                SystemTime::now(),
                nonce,
            ));
        }
        Ok(())
    }
}

#[derive(Debug)]
struct RtlsServerVerifier(Arc<CryptoProvider>);

impl ServerCertVerifier for RtlsServerVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        // RTLS authenticates the complete TLS channel with an exporter proof below.
        // The certificate is deliberately ephemeral and is never accepted on its own.
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            certificate,
            signature,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            certificate,
            signature,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

#[derive(Debug, Default)]
struct ReplayCache {
    tokens: Mutex<HashMap<[u8; TOKEN_BYTES], Instant>>,
}

impl ReplayCache {
    fn admit(&self, token: [u8; TOKEN_BYTES], lifetime: Duration) -> bool {
        let mut tokens = self.tokens.lock().unwrap();
        tokens.retain(|_, inserted| inserted.elapsed() <= lifetime);
        if tokens.contains_key(&token) {
            return false;
        }
        tokens.insert(token, Instant::now());
        true
    }
}

pub(crate) struct RtlsEngine {
    settings: RtlsSettings,
    client_config: Arc<ClientConfig>,
    client_token_random: &'static TokenRandom,
    client_hello_lock: Mutex<()>,
    server_config: Arc<ServerConfig>,
    replay_cache: ReplayCache,
}

impl fmt::Debug for RtlsEngine {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RtlsEngine")
            .field("settings", &self.settings)
            .finish_non_exhaustive()
    }
}

impl RtlsEngine {
    pub(crate) fn new(settings: RtlsSettings) -> anyhow::Result<Self> {
        if settings.server_name.trim().is_empty() {
            anyhow::bail!("RTLS server_name must not be empty");
        }
        if settings.secret.is_empty() {
            anyhow::bail!("RTLS secret must not be empty");
        }
        if settings.time_window.is_zero() {
            anyhow::bail!("RTLS time window must be positive");
        }

        let base_provider = rustls::crypto::ring::default_provider();
        let token_random = Box::leak(Box::new(TokenRandom {
            inner: base_provider.secure_random,
            server_name: settings.server_name.clone(),
            secret: settings.secret.clone(),
            time_window: settings.time_window,
            tag_next_session_id: AtomicBool::new(false),
        }));
        let mut client_provider = base_provider.clone();
        client_provider.secure_random = token_random;
        let client_provider = Arc::new(client_provider);
        let mut client_config = ClientConfig::builder_with_provider(client_provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(RtlsServerVerifier(client_provider)))
            .with_no_client_auth();
        client_config.enable_sni = true;
        client_config.enable_early_data = false;
        client_config.resumption = rustls::client::Resumption::disabled();
        client_config.alpn_protocols = vec![b"http/1.1".to_vec()];

        let generated = generate_simple_self_signed(vec![settings.server_name.clone()])?;
        let certificate = generated.cert.der().clone();
        let private_key = PrivatePkcs8KeyDer::from(generated.signing_key.serialize_der());
        let mut server_config = ServerConfig::builder_with_provider(Arc::new(base_provider))
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_no_client_auth()
            .with_single_cert(vec![certificate], PrivateKeyDer::Pkcs8(private_key))?;
        server_config.alpn_protocols = vec![b"http/1.1".to_vec()];

        Ok(Self {
            settings,
            client_config: Arc::new(client_config),
            client_token_random: token_random,
            client_hello_lock: Mutex::new(()),
            server_config: Arc::new(server_config),
            replay_cache: ReplayCache::default(),
        })
    }

    pub(crate) async fn connect(
        &self,
        socket: RuntimeTcpSocket,
        requested_url: url::Url,
    ) -> Result<Box<dyn Tunnel>, TunnelError> {
        let local_addr = socket.local_addr()?;
        let peer_addr = socket.peer_addr()?;
        let server_name = ServerName::try_from(self.settings.server_name.clone())
            .map_err(|error| TunnelError::InvalidAddr(error.to_string()))?;
        // rustls builds ClientConnection synchronously in `connect`; serialize only
        // that construction so exactly its first 32-byte request (the TLS 1.3
        // compatibility session ID) receives the routing token. Client random and
        // key-exchange randomness continue to come directly from the provider.
        let connector = {
            let _guard = self.client_hello_lock.lock().unwrap();
            self.client_token_random.arm();
            TlsConnector::from(self.client_config.clone()).connect(server_name, socket)
        };
        let mut tls = connector.await.map_err(rt_error)?;
        let exporter = tls
            .get_ref()
            .1
            .export_keying_material([0_u8; 32], EXPORTER_LABEL, None)
            .map_err(rt_error)?;
        verify_server_proof(&mut tls, &self.settings.secret, &exporter).await?;
        send_proof(
            &mut tls,
            &self.settings.secret,
            CLIENT_PROOF_LABEL,
            &exporter,
        )
        .await?;

        let info = tunnel_info(requested_url, local_addr, peer_addr);
        TcpTunnelUpgrader::new(info).upgrade(RtlsSocket::new(
            TlsStream::Client(tls),
            local_addr,
            peer_addr,
        ))
    }

    pub(crate) async fn accept(
        &self,
        mut socket: RuntimeTcpSocket,
        local_url: url::Url,
    ) -> Result<Option<Box<dyn Tunnel>>, TunnelError> {
        let local_addr = socket.local_addr()?;
        let peer_addr = socket.peer_addr()?;
        let hello = tokio::time::timeout(
            self.settings.handshake_timeout,
            read_client_hello(&mut socket),
        )
        .await
        .map_err(rt_error)??;
        let authorized = hello
            .server_name
            .eq_ignore_ascii_case(&self.settings.server_name)
            && verify_token(
                &self.settings.secret,
                &self.settings.server_name,
                self.settings.time_window,
                SystemTime::now(),
                &hello.session_id,
            );

        if !authorized {
            self.fallback(socket, hello.raw).await?;
            return Ok(None);
        }

        let token: [u8; TOKEN_BYTES] = hello
            .session_id
            .as_slice()
            .try_into()
            .map_err(|_| TunnelError::ProtocolError("invalid RTLS token length".to_owned()))?;
        if !self
            .replay_cache
            .admit(token, self.settings.time_window.saturating_mul(3))
        {
            return Err(TunnelError::ProtocolError(
                "replayed RTLS ClientHello token".to_owned(),
            ));
        }

        let replay = ReplaySocket::new(socket, hello.raw);
        let mut tls = tokio::time::timeout(self.settings.handshake_timeout, async {
            let mut tls = TlsAcceptor::from(self.server_config.clone())
                .accept(replay)
                .await
                .map_err(rt_error)?;
            let exporter = tls
                .get_ref()
                .1
                .export_keying_material([0_u8; 32], EXPORTER_LABEL, None)
                .map_err(rt_error)?;
            send_proof(
                &mut tls,
                &self.settings.secret,
                SERVER_PROOF_LABEL,
                &exporter,
            )
            .await?;
            verify_client_proof(&mut tls, &self.settings.secret, &exporter).await?;
            Ok::<_, TunnelError>(tls)
        })
        .await
        .map_err(rt_error)??;

        let mut remote_url = local_url.clone();
        remote_url
            .set_ip_host(peer_addr.ip())
            .map_err(|_| TunnelError::InvalidAddr(peer_addr.to_string()))?;
        remote_url.set_port(Some(peer_addr.port())).map_err(|_| {
            TunnelError::InvalidAddr(format!("invalid RTLS peer port: {}", peer_addr.port()))
        })?;
        let info = TunnelInfo {
            tunnel_type: "rtls".to_owned(),
            local_addr: Some(local_url.into()),
            remote_addr: Some(remote_url.clone().into()),
            resolved_remote_addr: Some(remote_url.into()),
        };
        let tunnel = TcpTunnelUpgrader::new(info).upgrade(RtlsSocket::new(
            TlsStream::Server(tls),
            local_addr,
            peer_addr,
        ))?;
        Ok(Some(tunnel))
    }

    async fn fallback(
        &self,
        mut client: RuntimeTcpSocket,
        client_hello: Vec<u8>,
    ) -> Result<(), TunnelError> {
        let Some(target) = self.settings.fallback_target.as_deref() else {
            return Err(TunnelError::ProtocolError(
                "unauthorized RTLS connection and no fallback target configured".to_owned(),
            ));
        };
        let mut upstream = TcpStream::connect(target).await.map_err(rt_error)?;
        upstream.write_all(&client_hello).await.map_err(rt_error)?;
        tokio::io::copy_bidirectional(&mut client, &mut upstream)
            .await
            .map_err(rt_error)?;
        Ok(())
    }
}

fn tunnel_info(requested_url: url::Url, local: SocketAddr, peer: SocketAddr) -> TunnelInfo {
    let mut local_url = requested_url.clone();
    let _ = local_url.set_ip_host(local.ip());
    let _ = local_url.set_port(Some(local.port()));
    let mut resolved = requested_url.clone();
    let _ = resolved.set_ip_host(peer.ip());
    let _ = resolved.set_port(Some(peer.port()));
    TunnelInfo {
        tunnel_type: "rtls".to_owned(),
        local_addr: Some(local_url.into()),
        remote_addr: Some(requested_url.into()),
        resolved_remote_addr: Some(resolved.into()),
    }
}

fn rt_error(error: impl fmt::Display) -> TunnelError {
    TunnelError::ProtocolError(format!("RTLS error: {error}"))
}

fn time_bucket(now: SystemTime, window: Duration) -> u32 {
    let seconds = now.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let divisor = window.as_secs().max(1);
    (seconds / divisor) as u32
}

fn new_token(
    secret: &[u8],
    server_name: &str,
    window: Duration,
    now: SystemTime,
    nonce: [u8; TOKEN_NONCE_BYTES],
) -> [u8; TOKEN_BYTES] {
    let bucket = time_bucket(now, window);
    let mut token = [0_u8; TOKEN_BYTES];
    token[..4].copy_from_slice(&bucket.to_be_bytes());
    token[4..4 + TOKEN_NONCE_BYTES].copy_from_slice(&nonce);
    let tag = token_tag(secret, server_name, &token[..4 + TOKEN_NONCE_BYTES]);
    token[4 + TOKEN_NONCE_BYTES..].copy_from_slice(&tag[..TOKEN_TAG_BYTES]);
    token
}

fn verify_token(
    secret: &[u8],
    server_name: &str,
    window: Duration,
    now: SystemTime,
    token: &[u8],
) -> bool {
    if token.len() != TOKEN_BYTES {
        return false;
    }
    let bucket = u32::from_be_bytes(token[..4].try_into().unwrap());
    let current = time_bucket(now, window);
    if bucket.abs_diff(current) > 1 {
        return false;
    }
    let expected = token_tag(secret, server_name, &token[..4 + TOKEN_NONCE_BYTES]);
    constant_time_eq(
        &token[4 + TOKEN_NONCE_BYTES..],
        &expected[..TOKEN_TAG_BYTES],
    )
}

fn token_tag(secret: &[u8], server_name: &str, data: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts every key size");
    mac.update(TOKEN_LABEL);
    mac.update(server_name.as_bytes());
    mac.update(data);
    mac.finalize().into_bytes().into()
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

fn proof(secret: &[u8], label: &[u8], exporter: &[u8; 32]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts every key size");
    mac.update(label);
    mac.update(exporter);
    mac.finalize().into_bytes().into()
}

async fn send_proof<S>(
    stream: &mut S,
    secret: &[u8],
    label: &[u8],
    exporter: &[u8; 32],
) -> Result<(), TunnelError>
where
    S: AsyncWrite + Unpin,
{
    stream
        .write_all(&proof(secret, label, exporter))
        .await
        .map_err(rt_error)
}

async fn verify_proof<S>(
    stream: &mut S,
    secret: &[u8],
    label: &[u8],
    exporter: &[u8; 32],
) -> Result<(), TunnelError>
where
    S: AsyncRead + Unpin,
{
    let mut received = [0_u8; 32];
    stream.read_exact(&mut received).await.map_err(rt_error)?;
    let expected = proof(secret, label, exporter);
    if !constant_time_eq(&received, &expected) {
        return Err(TunnelError::ProtocolError(
            "RTLS channel proof did not verify".to_owned(),
        ));
    }
    Ok(())
}

async fn verify_server_proof<S>(
    stream: &mut S,
    secret: &[u8],
    exporter: &[u8; 32],
) -> Result<(), TunnelError>
where
    S: AsyncRead + Unpin,
{
    verify_proof(stream, secret, SERVER_PROOF_LABEL, exporter).await
}

async fn verify_client_proof<S>(
    stream: &mut S,
    secret: &[u8],
    exporter: &[u8; 32],
) -> Result<(), TunnelError>
where
    S: AsyncRead + Unpin,
{
    verify_proof(stream, secret, CLIENT_PROOF_LABEL, exporter).await
}

struct ClientHello {
    raw: Vec<u8>,
    server_name: String,
    session_id: Vec<u8>,
}

async fn read_client_hello<S>(stream: &mut S) -> Result<ClientHello, TunnelError>
where
    S: AsyncRead + Unpin,
{
    let mut raw = Vec::new();
    let mut handshake = Vec::new();
    loop {
        let mut header = [0_u8; 5];
        stream.read_exact(&mut header).await.map_err(rt_error)?;
        if header[0] != 22 {
            return Err(TunnelError::ProtocolError(format!(
                "unexpected TLS record type {} before ClientHello",
                header[0]
            )));
        }
        let length = u16::from_be_bytes([header[3], header[4]]) as usize;
        if raw.len() + 5 + length > MAX_CLIENT_HELLO_BYTES {
            return Err(TunnelError::ProtocolError(
                "RTLS ClientHello exceeds size limit".to_owned(),
            ));
        }
        let mut payload = vec![0_u8; length];
        stream.read_exact(&mut payload).await.map_err(rt_error)?;
        raw.extend_from_slice(&header);
        raw.extend_from_slice(&payload);
        handshake.extend_from_slice(&payload);
        if handshake.len() >= 4 {
            if handshake[0] != 1 {
                return Err(TunnelError::ProtocolError(
                    "first TLS handshake message is not ClientHello".to_owned(),
                ));
            }
            let expected = ((handshake[1] as usize) << 16)
                | ((handshake[2] as usize) << 8)
                | handshake[3] as usize;
            if expected + 4 > MAX_CLIENT_HELLO_BYTES {
                return Err(TunnelError::ProtocolError(
                    "RTLS ClientHello handshake exceeds size limit".to_owned(),
                ));
            }
            if handshake.len() >= expected + 4 {
                let (server_name, session_id) = parse_client_hello(&handshake[4..expected + 4])?;
                return Ok(ClientHello {
                    raw,
                    server_name,
                    session_id,
                });
            }
        }
    }
}

fn parse_client_hello(body: &[u8]) -> Result<(String, Vec<u8>), TunnelError> {
    if body.len() < 34 {
        return Err(rt_error("truncated ClientHello"));
    }
    let mut cursor = 34;
    let session_id = take_vector_u8(body, &mut cursor)?.to_vec();
    let _cipher_suites = take_vector_u16(body, &mut cursor)?;
    let _compression = take_vector_u8(body, &mut cursor)?;
    let extensions = take_vector_u16(body, &mut cursor)?;
    if cursor != body.len() {
        return Err(rt_error("trailing bytes after ClientHello extensions"));
    }

    let mut extension_cursor = 0;
    while extension_cursor < extensions.len() {
        if extension_cursor + 4 > extensions.len() {
            return Err(rt_error("truncated ClientHello extension"));
        }
        let kind = u16::from_be_bytes([
            extensions[extension_cursor],
            extensions[extension_cursor + 1],
        ]);
        let length = u16::from_be_bytes([
            extensions[extension_cursor + 2],
            extensions[extension_cursor + 3],
        ]) as usize;
        extension_cursor += 4;
        if extension_cursor + length > extensions.len() {
            return Err(rt_error("invalid ClientHello extension length"));
        }
        if kind == 0 {
            let server_name =
                parse_server_name(&extensions[extension_cursor..extension_cursor + length])?;
            return Ok((server_name, session_id));
        }
        extension_cursor += length;
    }
    Err(rt_error("ClientHello has no SNI extension"))
}

fn parse_server_name(extension: &[u8]) -> Result<String, TunnelError> {
    let mut cursor = 0;
    let names = take_vector_u16(extension, &mut cursor)?;
    let mut name_cursor = 0;
    while name_cursor < names.len() {
        if name_cursor + 3 > names.len() {
            return Err(rt_error("truncated SNI entry"));
        }
        let kind = names[name_cursor];
        let length = u16::from_be_bytes([names[name_cursor + 1], names[name_cursor + 2]]) as usize;
        name_cursor += 3;
        if name_cursor + length > names.len() {
            return Err(rt_error("invalid SNI entry length"));
        }
        if kind == 0 {
            return std::str::from_utf8(&names[name_cursor..name_cursor + length])
                .map(str::to_owned)
                .map_err(rt_error);
        }
        name_cursor += length;
    }
    Err(rt_error("SNI extension has no DNS name"))
}

fn take_vector_u8<'a>(body: &'a [u8], cursor: &mut usize) -> Result<&'a [u8], TunnelError> {
    if *cursor >= body.len() {
        return Err(rt_error("truncated u8 vector"));
    }
    let length = body[*cursor] as usize;
    *cursor += 1;
    take(body, cursor, length)
}

fn take_vector_u16<'a>(body: &'a [u8], cursor: &mut usize) -> Result<&'a [u8], TunnelError> {
    if *cursor + 2 > body.len() {
        return Err(rt_error("truncated u16 vector"));
    }
    let length = u16::from_be_bytes([body[*cursor], body[*cursor + 1]]) as usize;
    *cursor += 2;
    take(body, cursor, length)
}

fn take<'a>(body: &'a [u8], cursor: &mut usize, length: usize) -> Result<&'a [u8], TunnelError> {
    if *cursor + length > body.len() {
        return Err(rt_error("truncated vector payload"));
    }
    let output = &body[*cursor..*cursor + length];
    *cursor += length;
    Ok(output)
}

struct ReplaySocket<S> {
    inner: S,
    replay: io::Cursor<Vec<u8>>,
}

impl<S> ReplaySocket<S> {
    fn new(inner: S, replay: Vec<u8>) -> Self {
        Self {
            inner,
            replay: io::Cursor::new(replay),
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for ReplaySocket<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let position = self.replay.position() as usize;
        if position < self.replay.get_ref().len() {
            let remaining = &self.replay.get_ref()[position..];
            let amount = remaining.len().min(buffer.remaining());
            buffer.put_slice(&remaining[..amount]);
            self.replay.set_position((position + amount) as u64);
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(context, buffer)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for ReplaySocket<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(context, buffer)
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}

impl<S: VirtualTcpSocket> VirtualTcpSocket for ReplaySocket<S> {
    fn into_split(self) -> VirtualTcpSplit {
        let (read, write) = tokio::io::split(self);
        (Box::new(read), Box::new(write))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.inner.peer_addr()
    }
}

struct RtlsSocket<S> {
    inner: S,
    local_addr: SocketAddr,
    peer_addr: SocketAddr,
}

impl<S> RtlsSocket<S> {
    fn new(inner: S, local_addr: SocketAddr, peer_addr: SocketAddr) -> Self {
        Self {
            inner,
            local_addr,
            peer_addr,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for RtlsSocket<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(context, buffer)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for RtlsSocket<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(context, buffer)
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}

impl<S> VirtualTcpSocket for RtlsSocket<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    fn into_split(self) -> VirtualTcpSplit {
        let (read, write) = tokio::io::split(self.inner);
        (Box::new(read), Box::new(write))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local_addr)
    }

    fn peer_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.peer_addr)
    }
}

#[cfg(test)]
mod tests {
    use futures::{SinkExt, StreamExt};
    use tokio::net::TcpListener;

    use super::*;
    use easytier_core::packet::ZCPacket;

    #[derive(Debug)]
    struct FixedRandom;

    impl SecureRandom for FixedRandom {
        fn fill(&self, bytes: &mut [u8]) -> Result<(), GetRandomFailed> {
            bytes.fill(0xa5);
            Ok(())
        }
    }

    static FIXED_RANDOM: FixedRandom = FixedRandom;

    #[test]
    fn token_random_only_tags_the_armed_session_id() {
        let random = TokenRandom {
            inner: &FIXED_RANDOM,
            server_name: "www.example.com".to_owned(),
            secret: Arc::from(b"relay secret".as_slice()),
            time_window: Duration::from_secs(30),
            tag_next_session_id: AtomicBool::new(false),
        };
        random.arm();

        let mut session_id = [0_u8; TOKEN_BYTES];
        random.fill(&mut session_id).unwrap();
        assert!(verify_token(
            b"relay secret",
            "www.example.com",
            Duration::from_secs(30),
            SystemTime::now(),
            &session_id
        ));

        let mut client_random = [0_u8; TOKEN_BYTES];
        random.fill(&mut client_random).unwrap();
        assert_eq!(client_random, [0xa5; TOKEN_BYTES]);
    }

    #[test]
    fn token_round_trip_and_tamper_detection() {
        let secret = b"relay secret";
        let now = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let window = Duration::from_secs(30);
        let token = new_token(
            secret,
            "www.example.com",
            window,
            now,
            [7; TOKEN_NONCE_BYTES],
        );
        assert!(verify_token(secret, "www.example.com", window, now, &token));
        let mut tampered = token;
        tampered[20] ^= 1;
        assert!(!verify_token(
            secret,
            "www.example.com",
            window,
            now,
            &tampered
        ));
        assert!(!verify_token(
            secret,
            "other.example.com",
            window,
            now,
            &token
        ));
    }

    #[test]
    fn token_accepts_one_adjacent_window_only() {
        let secret = b"relay secret";
        let window = Duration::from_secs(30);
        let now = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let token = new_token(
            secret,
            "www.example.com",
            window,
            now,
            [3; TOKEN_NONCE_BYTES],
        );
        assert!(verify_token(
            secret,
            "www.example.com",
            window,
            now + window,
            &token
        ));
        assert!(!verify_token(
            secret,
            "www.example.com",
            window,
            now + window.saturating_mul(3),
            &token
        ));
    }

    #[test]
    fn replay_cache_rejects_duplicate_token() {
        let cache = ReplayCache::default();
        assert!(cache.admit([1; TOKEN_BYTES], Duration::from_secs(10)));
        assert!(!cache.admit([1; TOKEN_BYTES], Duration::from_secs(10)));
        assert!(cache.admit([2; TOKEN_BYTES], Duration::from_secs(10)));
    }

    #[tokio::test]
    async fn authenticated_engines_exchange_framed_packets() {
        tokio::time::timeout(Duration::from_secs(10), async {
            let settings = RtlsSettings {
                server_name: "www.example.com".to_owned(),
                fallback_target: None,
                secret: Arc::from(b"shared service secret".as_slice()),
                time_window: Duration::from_secs(30),
                handshake_timeout: Duration::from_secs(5),
            };
            let server = Arc::new(RtlsEngine::new(settings.clone()).unwrap());
            let client = RtlsEngine::new(settings).unwrap();
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let url: url::Url = format!("rtls://{address}").parse().unwrap();
            let server_url = url.clone();
            let server_task = tokio::spawn(async move {
                let (socket, _) = listener.accept().await.unwrap();
                server
                    .accept(RuntimeTcpSocket::new(socket), server_url)
                    .await
                    .unwrap()
                    .expect("authenticated RTLS connection")
            });

            let socket = TcpStream::connect(address).await.unwrap();
            let client_tunnel = client
                .connect(RuntimeTcpSocket::new(socket), url)
                .await
                .unwrap();
            let server_tunnel = server_task.await.unwrap();
            assert_eq!(client_tunnel.info().unwrap().tunnel_type, "rtls");
            assert_eq!(server_tunnel.info().unwrap().tunnel_type, "rtls");

            let (_client_stream, mut client_sink) = client_tunnel.split();
            let (mut server_stream, _server_sink) = server_tunnel.split();
            client_sink
                .send(ZCPacket::new_with_payload(b"rtls-e2e"))
                .await
                .unwrap();
            client_sink.flush().await.unwrap();
            let received = server_stream.next().await.unwrap().unwrap();
            assert_eq!(received.payload(), b"rtls-e2e");
        })
        .await
        .expect("RTLS end-to-end test timed out");
    }

    #[tokio::test]
    async fn unauthenticated_tls_is_forwarded_to_cover_target() {
        tokio::time::timeout(Duration::from_secs(10), async {
            let base_settings = RtlsSettings {
                server_name: "www.example.com".to_owned(),
                fallback_target: None,
                secret: Arc::from(b"relay service secret".as_slice()),
                time_window: Duration::from_secs(30),
                handshake_timeout: Duration::from_secs(5),
            };
            let cover_engine = RtlsEngine::new(base_settings.clone()).unwrap();
            let cover_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let cover_address = cover_listener.local_addr().unwrap();
            let cover_config = cover_engine.server_config.clone();
            let cover_task = tokio::spawn(async move {
                let (socket, _) = cover_listener.accept().await.unwrap();
                let mut tls = TlsAcceptor::from(cover_config)
                    .accept(socket)
                    .await
                    .unwrap();
                tls.write_all(b"cover-ok").await.unwrap();
                tls.shutdown().await.unwrap();
            });

            let relay = Arc::new(
                RtlsEngine::new(RtlsSettings {
                    fallback_target: Some(cover_address.to_string()),
                    ..base_settings
                })
                .unwrap(),
            );
            let relay_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let relay_address = relay_listener.local_addr().unwrap();
            let relay_url: url::Url = format!("rtls://{relay_address}").parse().unwrap();
            let relay_task = tokio::spawn(async move {
                let (socket, _) = relay_listener.accept().await.unwrap();
                relay
                    .accept(RuntimeTcpSocket::new(socket), relay_url)
                    .await
                    .unwrap()
            });

            let provider = Arc::new(rustls::crypto::ring::default_provider());
            let mut client_config = ClientConfig::builder_with_provider(provider.clone())
                .with_protocol_versions(&[&rustls::version::TLS13])
                .unwrap()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(RtlsServerVerifier(provider)))
                .with_no_client_auth();
            client_config.alpn_protocols = vec![b"http/1.1".to_vec()];
            let socket = TcpStream::connect(relay_address).await.unwrap();
            let mut tls = TlsConnector::from(Arc::new(client_config))
                .connect(
                    ServerName::try_from("www.example.com".to_owned()).unwrap(),
                    socket,
                )
                .await
                .unwrap();
            let mut response = [0_u8; 8];
            tls.read_exact(&mut response).await.unwrap();
            assert_eq!(&response, b"cover-ok");
            tls.shutdown().await.unwrap();

            cover_task.await.unwrap();
            assert!(relay_task.await.unwrap().is_none());
        })
        .await
        .expect("RTLS fallback test timed out");
    }
}
