//! Outgoing guest HTTP, connected to the address that was checked.
//!
//! The SSRF filter decides on the addresses a name resolves to. The connection
//! must then go to one of exactly those addresses: a send that resolved the
//! name again could reach a different address than the one the filter passed.
//! So the name is resolved once, every address is checked, and the TCP
//! connection is opened to the checked one. TLS still verifies the certificate
//! against the host name the guest asked for, and the request keeps its `Host`
//! header, so the far side sees an ordinary request.
//!
//! The rest follows `wasmtime_wasi_http::types::default_send_request_handler`
//! (28.0.1): same TLS roots, same HTTP/1 handshake, same timeouts and errors.

use std::net::{IpAddr, SocketAddr};

use http_body_util::BodyExt;
use tokio::net::TcpStream;
use tokio::time::timeout;
use wasmtime_wasi_http::bindings::http::types::ErrorCode;
use wasmtime_wasi_http::body::HyperOutgoingBody;
use wasmtime_wasi_http::io::TokioIo;
use wasmtime_wasi_http::types::{IncomingResponse, OutgoingRequestConfig};

/// The addresses to connect to, or `None` when the name must not be reached:
/// it resolved to nothing, or ANY of its addresses is one a guest may not
/// reach. Refusing the whole name, rather than skipping its blocked
/// addresses, keeps a name that points inside our infrastructure refused even
/// when it also lists a public address.
pub(crate) fn checked_addresses(
    addrs: Vec<SocketAddr>,
    is_blocked: impl Fn(IpAddr) -> bool,
) -> Option<Vec<SocketAddr>> {
    if addrs.is_empty() || addrs.iter().any(|a| is_blocked(a.ip())) {
        return None;
    }
    Some(addrs)
}

/// Send `request` over a connection to the first of `addrs` that answers —
/// all of them already checked, none resolved again — verifying TLS against
/// `host`.
pub(crate) async fn send_to(
    mut request: hyper::Request<HyperOutgoingBody>,
    OutgoingRequestConfig {
        use_tls,
        connect_timeout,
        first_byte_timeout,
        between_bytes_timeout,
    }: OutgoingRequestConfig,
    host: &str,
    addrs: &[SocketAddr],
) -> Result<IncomingResponse, ErrorCode> {
    let mut last = ErrorCode::ConnectionRefused;
    let mut connected = None;
    for addr in addrs {
        match timeout(connect_timeout, TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => {
                connected = Some(stream);
                break;
            }
            Ok(Err(_)) => last = ErrorCode::ConnectionRefused,
            Err(_) => last = ErrorCode::ConnectionTimeout,
        }
    }
    let tcp_stream = connected.ok_or(last)?;

    let (mut sender, worker) = if use_tls {
        use rustls::pki_types::ServerName;

        let root_cert_store = rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.into(),
        };
        let config = rustls::ClientConfig::builder()
            .with_root_certificates(root_cert_store)
            .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(config));
        // An IPv6 literal arrives bracketed in the URI; a server name has none.
        let name = host.trim_start_matches('[').trim_end_matches(']');
        let domain = ServerName::try_from(name)
            .map_err(|_| ErrorCode::DnsError(wasmtime_wasi_http::bindings::http::types::DnsErrorPayload {
                rcode: Some("invalid dns name".to_string()),
                info_code: Some(0),
            }))?
            .to_owned();
        let stream = connector
            .connect(domain, tcp_stream)
            .await
            .map_err(|_| ErrorCode::TlsProtocolError)?;

        let (sender, conn) = timeout(
            connect_timeout,
            hyper::client::conn::http1::handshake(TokioIo::new(stream)),
        )
        .await
        .map_err(|_| ErrorCode::ConnectionTimeout)?
        .map_err(wasmtime_wasi_http::hyper_request_error)?;
        let worker = wasmtime_wasi::runtime::spawn(async move {
            if let Err(e) = conn.await {
                tracing::warn!("dropping error {e}");
            }
        });
        (sender, worker)
    } else {
        let (sender, conn) = timeout(
            connect_timeout,
            hyper::client::conn::http1::handshake(TokioIo::new(tcp_stream)),
        )
        .await
        .map_err(|_| ErrorCode::ConnectionTimeout)?
        .map_err(wasmtime_wasi_http::hyper_request_error)?;
        let worker = wasmtime_wasi::runtime::spawn(async move {
            if let Err(e) = conn.await {
                tracing::warn!("dropping error {e}");
            }
        });
        (sender, worker)
    };

    // The request carries scheme and authority; on the wire to an origin
    // server only the path and query go in the request line.
    *request.uri_mut() = hyper::Uri::builder()
        .path_and_query(
            request
                .uri()
                .path_and_query()
                .map(|p| p.as_str())
                .unwrap_or("/"),
        )
        .build()
        .map_err(|_| ErrorCode::HttpRequestUriInvalid)?;

    let resp = timeout(first_byte_timeout, sender.send_request(request))
        .await
        .map_err(|_| ErrorCode::ConnectionReadTimeout)?
        .map_err(wasmtime_wasi_http::hyper_request_error)?
        .map(|body| body.map_err(wasmtime_wasi_http::hyper_request_error).boxed());

    Ok(IncomingResponse {
        resp,
        worker: Some(worker),
        between_bytes_timeout,
    })
}

#[cfg(test)]
mod tests {
    use super::checked_addresses;
    use std::net::{IpAddr, SocketAddr};

    fn private(ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => v4.is_private() || v4.is_loopback(),
            IpAddr::V6(v6) => v6.is_loopback(),
        }
    }

    fn a(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn every_address_of_a_public_name_is_kept_in_order() {
        let both = vec![a("[2606:2800:220:1::1]:443"), a("93.184.216.34:443")];
        assert_eq!(checked_addresses(both.clone(), private), Some(both));
    }

    #[test]
    fn a_name_with_any_blocked_address_is_refused_whole() {
        assert_eq!(checked_addresses(vec![a("93.184.216.34:443"), a("10.0.2.2:443")], private), None);
        assert_eq!(checked_addresses(vec![a("10.0.2.2:11000")], private), None);
        assert_eq!(checked_addresses(vec![a("127.0.0.1:80")], private), None);
    }

    #[test]
    fn a_name_that_resolves_to_nothing_is_refused() {
        assert_eq!(checked_addresses(vec![], private), None);
    }

    /// Live: a real HTTPS request over a connection to the checked address,
    /// with TLS verified against the host name. Needs the internet.
    /// `cargo test -- --ignored https_to_the_checked_address`
    #[tokio::test]
    #[ignore]
    async fn https_to_the_checked_address_verifies_the_host_name() {
        use http_body_util::BodyExt;
        use std::time::Duration;
        use wasmtime_wasi_http::types::OutgoingRequestConfig;

        let host = "example.com";
        let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, 443)).await.unwrap().collect();
        let addrs = checked_addresses(addrs, private).expect("example.com is public");
        let body = http_body_util::Empty::<hyper::body::Bytes>::new().map_err(|e| match e {}).boxed();
        let request = hyper::Request::builder()
            .uri(format!("https://{host}/"))
            .header(hyper::header::HOST, host)
            .body(body)
            .unwrap();
        let config = OutgoingRequestConfig {
            use_tls: true,
            connect_timeout: Duration::from_secs(10),
            first_byte_timeout: Duration::from_secs(10),
            between_bytes_timeout: Duration::from_secs(10),
        };
        let resp = super::send_to(request, config, host, &addrs).await.expect("request succeeds");
        assert!(resp.resp.status().is_success(), "status {}", resp.resp.status());
    }
}
