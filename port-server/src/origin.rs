//! Origin validation for browser mutations.
//!
//! Automatic mode accepts only an IPv4 address assigned to a local interface at
//! validation time, using the actual HTTP listener port. It does not resolve
//! DNS. Exact mode is for a deliberately configured external proxy origin.
//! Interface enumeration is blocking: invoke it in a bounded blocking task, and
//! treat enumeration errors as denial. PS5 `getifaddrs` support is unverified.
use axum::http::{header, HeaderMap};
use std::{
    io,
    net::{IpAddr, Ipv4Addr},
};

#[derive(Clone, Debug)]
pub(crate) enum OriginPolicy {
    Exact { origin: String, authority: String },
    AutomaticHttpV4 { port: u16, bind: Ipv4Addr },
}

impl OriginPolicy {
    /// The exact, externally visible canonical origin, with no trailing slash.
    /// A reverse proxy must preserve the matching Host header and strip untrusted
    /// forwarding headers; forwarded headers are never used by this module.
    pub(crate) fn exact(origin: &str) -> Result<Self, &'static str> {
        let authority = canonical_authority(origin)?;
        Ok(Self::Exact {
            origin: origin.to_owned(),
            authority,
        })
    }

    /// Returns true if the configured origin uses HTTPS.
    pub(crate) fn is_https(&self) -> bool {
        matches!(self, Self::Exact { origin, .. } if origin.starts_with("https://"))
    }

    /// Returns true if validation requires enumerating local network interfaces.
    pub(crate) fn requires_interface_lookup(&self) -> bool {
        matches!(self, Self::AutomaticHttpV4 { .. })
    }

    /// For an HTTP IPv4 listener, after binding so port 0 has been resolved.
    /// If bound to a specific address, only that interface is accepted.
    pub(crate) fn automatic_http_v4(bind: Ipv4Addr, port: u16) -> Result<Self, &'static str> {
        if port == 0 || bind.is_broadcast() || bind.is_multicast() {
            return Err("invalid listener address or port");
        }
        Ok(Self::AutomaticHttpV4 { port, bind })
    }

    /// `local_ipv4` must return a fresh enumeration, not a cached address.
    /// Never accept a caller-provided address from a request as that enumeration.
    pub(crate) fn validate<F>(&self, headers: &HeaderMap, local_ipv4: F) -> bool
    where
        F: FnOnce() -> io::Result<Vec<Ipv4Addr>>,
    {
        let Some(origin) = only_header(headers, header::ORIGIN) else {
            return false;
        };
        let Some(host) = only_header(headers, header::HOST) else {
            return false;
        };
        match self {
            Self::Exact {
                origin: expected,
                authority,
            } => origin == expected && host == authority,
            Self::AutomaticHttpV4 { port, bind } => {
                let Ok(addresses) = local_ipv4() else {
                    return false;
                };
                addresses.into_iter().any(|ip| {
                    if ip.is_unspecified()
                        || ip.is_multicast()
                        || ip.is_broadcast()
                        || (!bind.is_unspecified() && *bind != ip)
                    {
                        return false;
                    }
                    let authority = if *port == 80 {
                        ip.to_string()
                    } else {
                        format!("{ip}:{port}")
                    };
                    host == authority && origin == format!("http://{authority}")
                })
            }
        }
    }
}

fn canonical_authority(origin: &str) -> Result<String, &'static str> {
    let url = reqwest::Url::parse(origin).map_err(|_| "invalid origin")?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
        || url.origin().ascii_serialization() != origin
    {
        return Err("origin must be canonical HTTP(S), with no path or trailing slash");
    }
    origin
        .split_once("://")
        .map(|(_, authority)| authority.to_owned())
        .ok_or("invalid origin")
}

fn only_header(headers: &HeaderMap, name: axum::http::header::HeaderName) -> Option<&str> {
    let mut values = headers.get_all(name).iter();
    match (values.next(), values.next()) {
        (Some(value), None) => value.to_str().ok(),
        _ => None,
    }
}

/// Enumerates the actual interface addresses, without relying on DNS or a fixed IP.
/// Caches results for 5s so frequent mutation/WS origin checks avoid repeated
/// kernel `getifaddrs` allocations on PS5.
pub(crate) fn system_ipv4() -> io::Result<Vec<Ipv4Addr>> {
    use std::sync::Mutex;
    use std::time::{Duration, Instant};

    static CACHE: Mutex<Option<(Instant, Vec<Ipv4Addr>)>> = Mutex::new(None);
    const TTL: Duration = Duration::from_secs(5);

    if let Ok(guard) = CACHE.lock() {
        if let Some((at, ips)) = &*guard {
            if at.elapsed() < TTL {
                return Ok(ips.clone());
            }
        }
    }

    let ips: Vec<Ipv4Addr> = if_addrs::get_if_addrs()?
        .into_iter()
        .filter_map(|iface| {
            if let IpAddr::V4(ip) = iface.ip() {
                Some(ip)
            } else {
                None
            }
        })
        .collect();

    if let Ok(mut guard) = CACHE.lock() {
        *guard = Some((Instant::now(), ips.clone()));
    }
    Ok(ips)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;
    fn headers(origin: &str, host: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(header::ORIGIN, HeaderValue::from_str(origin).unwrap());
        h.insert(header::HOST, HeaderValue::from_str(host).unwrap());
        h
    }
    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }
    #[test]
    fn dynamic_addresses_are_fresh_and_match_host_origin_and_listener() {
        let p = OriginPolicy::automatic_http_v4(Ipv4Addr::UNSPECIFIED, 3010).unwrap();
        let h1 = headers("http://192.168.1.2:3010", "192.168.1.2:3010");
        let h2 = headers("http://192.168.1.3:3010", "192.168.1.3:3010");
        assert!(p.validate(&h1, || Ok(vec![ip("192.168.1.2")])));
        assert!(!p.validate(&h1, || Ok(vec![ip("192.168.1.3")])));
        assert!(p.validate(&h2, || Ok(vec![ip("192.168.1.3")])));
        assert!(!p.validate(&h1, || Err(io::Error::other("unavailable"))));
        assert!(!p.validate(
            &headers("http://attacker.test:3010", "attacker.test:3010"),
            || Ok(vec![ip("192.168.1.2")])
        ));
        assert!(!p.validate(
            &headers("http://192.168.1.2:3010", "attacker.test:3010"),
            || Ok(vec![ip("192.168.1.2")])
        ));
        assert!(!p.validate(
            &headers("https://192.168.1.2:3010", "192.168.1.2:3010"),
            || Ok(vec![ip("192.168.1.2")])
        ));
        assert!(!p.validate(
            &headers("http://192.168.1.2:3000", "192.168.1.2:3000"),
            || Ok(vec![ip("192.168.1.2")])
        ));
        assert!(!p.validate(
            &headers("http://192.168.001.002:3010", "192.168.001.002:3010"),
            || Ok(vec![ip("192.168.1.2")])
        ));
    }
    #[test]
    fn exact_origin_for_reverse_proxy_and_bound_interface_restriction() {
        let exact = OriginPolicy::exact("https://bot.example").unwrap();
        assert!(
            exact.validate(&headers("https://bot.example", "bot.example"), || panic!(
                "no enumeration"
            ))
        );
        assert!(
            !exact.validate(&headers("https://bot.example", "other.example"), || panic!(
                "no enumeration"
            ))
        );
        assert!(OriginPolicy::exact("https://bot.example/").is_err());
        let bound = OriginPolicy::automatic_http_v4(ip("192.168.1.2"), 3010).unwrap();
        assert!(!bound.validate(
            &headers("http://192.168.1.3:3010", "192.168.1.3:3010"),
            || Ok(vec![ip("192.168.1.2"), ip("192.168.1.3")])
        ));
        assert!(OriginPolicy::automatic_http_v4(Ipv4Addr::UNSPECIFIED, 0).is_err());
    }
    #[test]
    fn missing_and_multiple_headers_fail_closed() {
        let p = OriginPolicy::automatic_http_v4(Ipv4Addr::UNSPECIFIED, 3010).unwrap();
        assert!(!p.validate(&HeaderMap::new(), || Ok(vec![Ipv4Addr::LOCALHOST])));
        let mut h = headers("http://127.0.0.1:3010", "127.0.0.1:3010");
        h.append(
            header::ORIGIN,
            HeaderValue::from_static("http://127.0.0.1:3010"),
        );
        assert!(!p.validate(&h, || Ok(vec![Ipv4Addr::LOCALHOST])));
        let mut h = headers("http://127.0.0.1:3010", "127.0.0.1:3010");
        h.append(header::HOST, HeaderValue::from_static("127.0.0.1:3010"));
        assert!(!p.validate(&h, || Ok(vec![Ipv4Addr::LOCALHOST])));
    }
    #[test]
    fn exact_rejects_non_canonical_origins_and_reports_scheme() {
        for bad in [
            "https://Bot.Example",
            "https://bot.example:443",
            "http://bot.example:80",
            "https://user@bot.example",
            "https://bot.example/path",
            "https://bot.example?q=1",
            "https://bot.example#frag",
            "ftp://bot.example",
        ] {
            assert!(OriginPolicy::exact(bad).is_err(), "{bad}");
        }
        let https = OriginPolicy::exact("https://bot.example").unwrap();
        assert!(https.is_https());
        assert!(!https.requires_interface_lookup());
        let http = OriginPolicy::exact("http://bot.example:3010").unwrap();
        assert!(!http.is_https());
        assert!(!http.requires_interface_lookup());
        let auto = OriginPolicy::automatic_http_v4(Ipv4Addr::LOCALHOST, 3010).unwrap();
        assert!(!auto.is_https());
        assert!(auto.requires_interface_lookup());
    }
}
