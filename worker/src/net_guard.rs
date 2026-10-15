//! The one rule for where the worker may connect on someone else's behalf:
//! a guest's HTTP request, or a `wasm_url` fetch. Never an address inside our
//! own infrastructure or anyone's private network.

use std::net::SocketAddr;

/// True for addresses a sandboxed guest must not reach: loopback, RFC1918
/// private, link-local (incl. cloud metadata 169.254.169.254), CGNAT, ULA, etc.
pub fn is_blocked_ip(ip: std::net::IpAddr) -> bool {
    use std::net::IpAddr;
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_documentation()
                || o[0] == 0
                || (o[0] == 100 && (o[1] & 0xc0) == 0x40) // 100.64.0.0/10 CGNAT
                || (o[0] == 198 && (o[1] & 0xfe) == 18) // 198.18.0.0/15 benchmark
                || (o[0] == 192 && o[1] == 0 && o[2] == 0) // 192.0.0.0/24 IETF
                || (o[0] == 192 && o[1] == 88 && o[2] == 99) // 192.88.99.0/24 6to4 relay
                || (o[0] & 0xf0) == 0xe0 // 224.0.0.0/4 multicast
                || o[0] >= 240 // 240.0.0.0/4 reserved
        }
        IpAddr::V6(v6) => {
            // Unwrap BOTH IPv4-mapped (::ffff:a.b.c.d) AND the deprecated
            // IPv4-compatible (::a.b.c.d) forms: to_ipv4() covers both, whereas
            // to_ipv4_mapped() misses ::a.b.c.d and would let `::169.254.169.254`
            // (cloud metadata) through. Genuine global v6 returns None.
            if let Some(v4) = v6.to_ipv4() {
                return is_blocked_ip(IpAddr::V4(v4));
            }
            let s = v6.segments();
            v6.is_loopback()
                || v6.is_unspecified()
                || (s[0] & 0xfe00) == 0xfc00 // fc00::/7 ULA
                || (s[0] & 0xffc0) == 0xfe80 // fe80::/10 link-local
                || (s[0] & 0xff00) == 0xff00 // ff00::/8 multicast
                || (s[0] == 0x0064 && s[1] == 0xff9b) // 64:ff9b::/96 NAT64
                || (s[0] == 0x2001 && s[1] == 0x0db8) // 2001:db8::/32 documentation
        }
    }
}

/// The addresses to connect to, or `None` when the name must not be reached:
/// it resolved to nothing, or ANY of its addresses is one a guest may not
/// reach. Refusing the whole name, rather than skipping its blocked
/// addresses, keeps a name that points inside our infrastructure refused even
/// when it also lists a public address.
pub fn checked_addresses(addrs: Vec<SocketAddr>) -> Option<Vec<SocketAddr>> {
    if addrs.is_empty() || addrs.iter().any(|a| is_blocked_ip(a.ip())) {
        return None;
    }
    Some(addrs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("valid ip literal")
    }

    #[test]
    fn blocks_internal_and_metadata_addresses() {
        for s in [
            "127.0.0.1",
            "0.0.0.0",
            "10.0.0.5",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "169.254.169.254", // cloud metadata
            "169.254.0.1",     // link-local
            "100.64.0.1",      // CGNAT 100.64/10
            "198.18.0.1",      // benchmarking 198.18/15
            "240.0.0.1",       // reserved
            "::1",
            "fe80::1",
            "fc00::1",
            "fd12:3456::1",
            "::ffff:127.0.0.1", // IPv4-mapped IPv6
            "::ffff:10.0.0.1",
            "::169.254.169.254", // IPv4-COMPATIBLE IPv6 (the to_ipv4 gap) → metadata
            "::127.0.0.1",        // IPv4-compatible loopback
            "224.0.0.1",          // IPv4 multicast
            "192.0.0.1",          // 192.0.0.0/24
            "192.88.99.1",        // 6to4 relay
            "ff02::1",            // IPv6 multicast
            "64:ff9b::a9fe:a9fe", // NAT64 → 169.254.169.254
            "2001:db8::1",        // IPv6 documentation
        ] {
            assert!(is_blocked_ip(ip(s)), "should block {s}");
        }
    }

    #[test]
    fn allows_public_addresses() {
        for s in [
            "8.8.8.8",
            "1.1.1.1",
            "9.9.9.9",
            "208.67.222.222",
            "2606:4700:4700::1111",
            "2001:4860:4860::8888",
        ] {
            assert!(!is_blocked_ip(ip(s)), "should allow {s}");
        }
    }

    fn a(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn every_address_of_a_public_name_is_kept_in_order() {
        let both = vec![a("[2606:4700:4700::1111]:443"), a("1.1.1.1:443")];
        assert_eq!(checked_addresses(both.clone()), Some(both));
    }

    #[test]
    fn a_name_with_any_blocked_address_is_refused_whole() {
        assert_eq!(checked_addresses(vec![a("1.1.1.1:443"), a("10.0.2.2:443")]), None);
        assert_eq!(checked_addresses(vec![a("10.0.2.2:11000")]), None);
        assert_eq!(checked_addresses(vec![a("127.0.0.1:80")]), None);
    }

    #[test]
    fn a_name_that_resolves_to_nothing_is_refused() {
        assert_eq!(checked_addresses(vec![]), None);
    }
}
