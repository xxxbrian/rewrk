use std::convert::TryFrom;
use std::net::{SocketAddr, ToSocketAddrs};

use anyhow::{anyhow, Result};
use http::header::HeaderValue;
use http::uri::Uri;
use http::{HeaderMap, Method};
use hyper::body::Bytes;
use tokio::task::spawn_blocking;
use tokio_native_tls::TlsConnector;

use super::BenchType;

#[derive(Clone, Debug)]
pub(crate) enum Scheme {
    Http,
    Https(TlsConnector),
}

impl Scheme {
    fn default_port(&self) -> u16 {
        match self {
            Self::Http => 80,
            Self::Https(_) => 443,
        }
    }
}

#[derive(Clone)]
pub(crate) struct UserInput {
    pub(crate) local_socket_addr: Option<SocketAddr>,
    pub(crate) addr: SocketAddr,
    pub(crate) scheme: Scheme,
    pub(crate) host: String,
    pub(crate) host_header: HeaderValue,
    pub(crate) uri: Uri,
    pub(crate) method: Method,
    pub(crate) headers: HeaderMap,
    pub(crate) body: Bytes,
}

impl UserInput {
    pub(crate) async fn new(
        interface: Option<String>,
        protocol: BenchType,
        string: String,
        method: Method,
        headers: HeaderMap,
        body: Bytes,
    ) -> Result<Self> {
        spawn_blocking(move || {
            Self::blocking_new(interface, protocol, string, method, headers, body)
        })
        .await
        .unwrap()
    }

    fn blocking_new(
        interface: Option<String>,
        protocol: BenchType,
        string: String,
        method: Method,
        headers: HeaderMap,
        body: Bytes,
    ) -> Result<Self> {
        let uri = Uri::try_from(string)?;
        let scheme = uri
            .scheme()
            .ok_or_else(|| anyhow!("scheme is not present on uri"))?
            .as_str();
        let scheme = match scheme {
            "http" => Scheme::Http,
            "https" => {
                let mut builder = native_tls::TlsConnector::builder();

                builder
                    .danger_accept_invalid_certs(true)
                    .danger_accept_invalid_hostnames(true);

                match protocol {
                    BenchType::HTTP1 => builder.request_alpns(&["http/1.1"]),
                    BenchType::HTTP2 => builder.request_alpns(&["h2"]),
                };

                let connector = TlsConnector::from(builder.build()?);
                Scheme::Https(connector)
            },
            _ => return Err(anyhow::Error::msg("invalid scheme")),
        };
        let authority = uri
            .authority()
            .ok_or_else(|| anyhow!("host not present on uri"))?;
        let host = authority.host().to_owned();
        let port = authority
            .port_u16()
            .unwrap_or_else(|| scheme.default_port());
        let host_header = HeaderValue::from_str(&host)?;

        // Bind to any local address.
        let (local_socket_addr, need_ipv4) = match interface {
            Some(interface) => {
                // TODO: Support interface name input.
                let addr = interface.parse()?;
                (Some(SocketAddr::new(addr, 0)), addr.is_ipv4())
            },
            None => (None, true), //default to ipv4
        };

        // Resolve the hostname to an IP address.
        // Chose by interface ip type.
        let addr_iter = (host.as_str(), port).to_socket_addrs()?;
        let mut last_addr = None;
        for addr in addr_iter {
            if addr.is_ipv4() && need_ipv4 {
                last_addr = Some(addr);
                break;
            }
            if addr.is_ipv6() && !need_ipv4 {
                last_addr = Some(addr);
                break;
            }
        }
        let addr = last_addr.ok_or_else(|| anyhow!("DNS lookup failed"))?;

        Ok(Self {
            local_socket_addr,
            addr,
            scheme,
            host,
            host_header,
            uri,
            method,
            headers,
            body,
        })
    }
}
