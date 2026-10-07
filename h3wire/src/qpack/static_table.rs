// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 mp0rta
//! QPACK static table (RFC 9204 Appendix A).

type E = (&'static [u8], &'static [u8]);

pub const ENTRIES: [E; 99] = [
    (b":authority", b""),
    (b":path", b"/"),
    (b"age", b"0"),
    (b"content-disposition", b""),
    (b"content-length", b"0"),
    (b"cookie", b""),
    (b"date", b""),
    (b"etag", b""),
    (b"if-modified-since", b""),
    (b"if-none-match", b""),
    (b"last-modified", b""),
    (b"link", b""),
    (b"location", b""),
    (b"referer", b""),
    (b"set-cookie", b""),
    (b":method", b"CONNECT"),
    (b":method", b"DELETE"),
    (b":method", b"GET"),
    (b":method", b"HEAD"),
    (b":method", b"OPTIONS"),
    (b":method", b"POST"),
    (b":method", b"PUT"),
    (b":scheme", b"http"),
    (b":scheme", b"https"),
    (b":status", b"103"),
    (b":status", b"200"),
    (b":status", b"304"),
    (b":status", b"404"),
    (b":status", b"503"),
    (b"accept", b"*/*"),
    (b"accept", b"application/dns-message"),
    (b"accept-encoding", b"gzip, deflate, br"),
    (b"accept-ranges", b"bytes"),
    (b"access-control-allow-headers", b"cache-control"),
    (b"access-control-allow-headers", b"content-type"),
    (b"access-control-allow-origin", b"*"),
    (b"cache-control", b"max-age=0"),
    (b"cache-control", b"max-age=2592000"),
    (b"cache-control", b"max-age=604800"),
    (b"cache-control", b"no-cache"),
    (b"cache-control", b"no-store"),
    (b"cache-control", b"public, max-age=31536000"),
    (b"content-encoding", b"br"),
    (b"content-encoding", b"gzip"),
    (b"content-type", b"application/dns-message"),
    (b"content-type", b"application/javascript"),
    (b"content-type", b"application/json"),
    (b"content-type", b"application/x-www-form-urlencoded"),
    (b"content-type", b"image/gif"),
    (b"content-type", b"image/jpeg"),
    (b"content-type", b"image/png"),
    (b"content-type", b"text/css"),
    (b"content-type", b"text/html; charset=utf-8"),
    (b"content-type", b"text/plain"),
    (b"content-type", b"text/plain;charset=utf-8"),
    (b"range", b"bytes=0-"),
    (b"strict-transport-security", b"max-age=31536000"),
    (
        b"strict-transport-security",
        b"max-age=31536000; includesubdomains",
    ),
    (
        b"strict-transport-security",
        b"max-age=31536000; includesubdomains; preload",
    ),
    (b"vary", b"accept-encoding"),
    (b"vary", b"origin"),
    (b"x-content-type-options", b"nosniff"),
    (b"x-xss-protection", b"1; mode=block"),
    (b":status", b"100"),
    (b":status", b"204"),
    (b":status", b"206"),
    (b":status", b"302"),
    (b":status", b"400"),
    (b":status", b"403"),
    (b":status", b"421"),
    (b":status", b"425"),
    (b":status", b"500"),
    (b"accept-language", b""),
    (b"access-control-allow-credentials", b"FALSE"),
    (b"access-control-allow-credentials", b"TRUE"),
    (b"access-control-allow-headers", b"*"),
    (b"access-control-allow-methods", b"get"),
    (b"access-control-allow-methods", b"get, post, options"),
    (b"access-control-allow-methods", b"options"),
    (b"access-control-expose-headers", b"content-length"),
    (b"access-control-request-headers", b"content-type"),
    (b"access-control-request-method", b"get"),
    (b"access-control-request-method", b"post"),
    (b"alt-svc", b"clear"),
    (b"authorization", b""),
    (
        b"content-security-policy",
        b"script-src 'none'; object-src 'none'; base-uri 'none'",
    ),
    (b"early-data", b"1"),
    (b"expect-ct", b""),
    (b"forwarded", b""),
    (b"if-range", b""),
    (b"origin", b""),
    (b"purpose", b"prefetch"),
    (b"server", b""),
    (b"timing-allow-origin", b"*"),
    (b"upgrade-insecure-requests", b"1"),
    (b"user-agent", b""),
    (b"x-forwarded-for", b""),
    (b"x-frame-options", b"deny"),
    (b"x-frame-options", b"sameorigin"),
];

/// Look up a field: the first full match if any, else the first name match.
/// Returns `(index, value_matches)`.
pub fn find(name: &[u8], value: &[u8]) -> Option<(usize, bool)> {
    let mut name_hit = None;
    for (i, (n, v)) in ENTRIES.iter().enumerate() {
        if *n == name {
            if *v == value {
                return Some((i, true));
            }
            name_hit.get_or_insert((i, false));
        }
    }
    name_hit
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn static_table_spot_checks() {
        assert_eq!(ENTRIES[0], (&b":authority"[..], &b""[..]));
        assert_eq!(ENTRIES[17], (&b":method"[..], &b"GET"[..]));
        assert_eq!(ENTRIES[25], (&b":status"[..], &b"200"[..]));
        assert_eq!(ENTRIES[98], (&b"x-frame-options"[..], &b"sameorigin"[..]));
    }

    #[test]
    fn static_table_more_entries() {
        let cases: [(usize, &[u8], &[u8]); 15] = [
            (1, b":path", b"/"),
            (15, b":method", b"CONNECT"),
            (22, b":scheme", b"http"),
            (23, b":scheme", b"https"),
            (24, b":status", b"103"),
            (29, b"accept", b"*/*"),
            (31, b"accept-encoding", b"gzip, deflate, br"),
            (52, b"content-type", b"text/html; charset=utf-8"),
            (63, b":status", b"100"),
            (67, b":status", b"400"),
            (71, b":status", b"500"),
            (84, b"authorization", b""),
            (95, b"user-agent", b""),
            (96, b"x-forwarded-for", b""),
            (97, b"x-frame-options", b"deny"),
        ];
        for (i, n, v) in cases {
            assert_eq!(ENTRIES[i], (n, v), "index {i}");
        }
    }

    #[test]
    fn find_prefers_full_match() {
        assert_eq!(find(b":method", b"GET"), Some((17, true)));
        assert_eq!(find(b":method", b"PATCH"), Some((15, false)));
        assert_eq!(find(b"nope", b""), None);
    }
}
