//! Header field types, the received header block store, and HTTP/3 message validation.

use crate::error::{H3Code, UsageError};
use crate::qpack::decoder::{DecodedField, Span, decode_field_section};

/// A header field; `never_index` sets the QPACK 'N' bit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FieldRef<'a> {
    pub name: &'a [u8],
    pub value: &'a [u8],
    pub never_index: bool,
}

impl<'a> FieldRef<'a> {
    pub fn new(name: &'a [u8], value: &'a [u8]) -> Self {
        Self {
            name,
            value,
            never_index: false,
        }
    }
}

/// Handle to a received header block; stale after `release`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct HeaderBlockId {
    slot: u32,
    generation: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeadersKind {
    Request,
    Response,
    Informational,
    Trailers,
}

/// Pseudo-header fields of a block (first occurrence of each).
#[derive(Debug, Default)]
pub struct Pseudo<'a> {
    pub method: Option<&'a [u8]>,
    pub scheme: Option<&'a [u8]>,
    pub authority: Option<&'a [u8]>,
    pub path: Option<&'a [u8]>,
    pub protocol: Option<&'a [u8]>,
    /// Set only when `:status` is exactly three ASCII digits.
    pub status: Option<u16>,
}

const PSEUDO_NAMES: [&[u8]; 6] = [
    b":method",
    b":scheme",
    b":authority",
    b":path",
    b":protocol",
    b":status",
];
const STATUS: usize = 5;

type RawPseudo<'a> = [Option<&'a [u8]>; 6];

impl<'a> Pseudo<'a> {
    fn from_raw(r: RawPseudo<'a>) -> Self {
        Self {
            method: r[0],
            scheme: r[1],
            authority: r[2],
            path: r[3],
            protocol: r[4],
            status: r[STATUS].and_then(parse_status),
        }
    }
}

fn parse_status(v: &[u8]) -> Option<u16> {
    match v {
        [a, b, c] if v.iter().all(u8::is_ascii_digit) => {
            Some(u16::from(a - b'0') * 100 + u16::from(b - b'0') * 10 + u16::from(c - b'0'))
        }
        _ => None,
    }
}

/// A borrowed view of a received header block.
#[derive(Debug)]
pub struct HeaderBlockRef<'a> {
    arena: &'a [u8],
    fields: &'a [DecodedField],
    pseudo: Pseudo<'a>,
}

impl<'a> HeaderBlockRef<'a> {
    /// Regular (non-pseudo) fields in wire order.
    pub fn iter(&self) -> impl Iterator<Item = FieldRef<'a>> + use<'a> {
        self.all().filter(|f| !f.name.starts_with(b":"))
    }

    pub fn pseudo(&self) -> &Pseudo<'a> {
        &self.pseudo
    }

    /// Every field, pseudo and regular, in wire order.
    fn all(&self) -> impl Iterator<Item = FieldRef<'a>> + use<'a> {
        let arena = self.arena;
        let span = move |s: Span| match s {
            Span::Static(b) => b,
            Span::Arena(a, b) => arena.get(a as usize..b as usize).unwrap_or_default(),
        };
        self.fields.iter().map(move |f| FieldRef {
            name: span(f.name),
            value: span(f.value),
            never_index: f.never_index,
        })
    }
}

struct Slot {
    arena: Vec<u8>,
    fields: Vec<DecodedField>,
    generation: u32,
    live: bool,
}

/// Slab of decoded header blocks; free slots and their buffers are reused.
#[derive(Default)]
pub(crate) struct BlockStore {
    slots: Vec<Slot>,
    free: Vec<u32>,
}

impl BlockStore {
    /// Decode a field section into a free slot. On error the slot stays free.
    pub(crate) fn insert_decoded(&mut self, buf: &[u8]) -> Result<HeaderBlockId, H3Code> {
        let i = match self.free.pop() {
            Some(i) => i,
            None => {
                let i = u32::try_from(self.slots.len()).map_err(|_| H3Code::EXCESSIVE_LOAD)?;
                self.slots.push(Slot {
                    arena: Vec::new(),
                    fields: Vec::new(),
                    generation: 0,
                    live: false,
                });
                i
            }
        };
        let slot = &mut self.slots[i as usize];
        slot.arena.clear();
        slot.fields.clear();
        if let Err(e) = decode_field_section(buf, &mut slot.arena, &mut slot.fields) {
            self.free.push(i);
            return Err(e);
        }
        slot.live = true;
        Ok(HeaderBlockId {
            slot: i,
            generation: slot.generation,
        })
    }

    pub(crate) fn get(&self, id: HeaderBlockId) -> Result<HeaderBlockRef<'_>, UsageError> {
        let slot = self.live_slot(id).ok_or(UsageError::StaleBlock)?;
        let mut block = HeaderBlockRef {
            arena: &slot.arena,
            fields: &slot.fields,
            pseudo: Pseudo::default(),
        };
        let mut raw: RawPseudo = [None; 6];
        for f in block.all() {
            if let Some(i) = PSEUDO_NAMES.iter().position(|n| *n == f.name) {
                raw[i].get_or_insert(f.value);
            }
        }
        block.pseudo = Pseudo::from_raw(raw);
        Ok(block)
    }

    /// Release a block; a stale id is a no-op.
    pub(crate) fn release(&mut self, id: HeaderBlockId) {
        if self.live_slot(id).is_some() {
            free_slot(&mut self.slots[id.slot as usize], id.slot, &mut self.free);
        }
    }

    /// Release every block (buffers are kept for reuse).
    pub(crate) fn clear(&mut self) {
        for (i, slot) in self.slots.iter_mut().enumerate() {
            if slot.live {
                free_slot(slot, i as u32, &mut self.free);
            }
        }
    }

    pub(crate) fn live_blocks(&self) -> usize {
        self.slots.iter().filter(|s| s.live).count()
    }

    pub(crate) fn buffered_bytes(&self) -> usize {
        self.slots
            .iter()
            .map(|s| s.arena.capacity() + s.fields.capacity() * size_of::<DecodedField>())
            .sum()
    }

    fn live_slot(&self, id: HeaderBlockId) -> Option<&Slot> {
        self.slots
            .get(id.slot as usize)
            .filter(|s| s.live && s.generation == id.generation)
    }
}

fn free_slot(slot: &mut Slot, i: u32, free: &mut Vec<u32>) {
    slot.live = false;
    // ponytail: generation wraps after 2^32 reuses of one slot; an id that old could alias.
    slot.generation = slot.generation.wrapping_add(1);
    free.push(i);
}

/// What the connection needs to know about a valid message head.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct MessageCheck {
    pub kind: HeadersKind,
    pub content_length: Option<u64>,
    pub is_connect: bool,
    pub is_extended_connect: bool,
    pub method_is_head: bool,
    pub status: Option<u16>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ValidateCtx {
    Request { connect_protocol_enabled: bool },
    Response,
    Trailers,
}

/// Validate a received block; `Err(())` means malformed (`H3_MESSAGE_ERROR`).
pub(crate) fn validate(block: &HeaderBlockRef, ctx: ValidateCtx) -> Result<MessageCheck, ()> {
    check(block.all().map(|f| (f.name, f.value)), ctx)
}

/// Validate fields we are about to send (same rules as `validate`).
pub(crate) fn validate_outgoing(
    fields: &[FieldRef],
    ctx: ValidateCtx,
) -> Result<MessageCheck, UsageError> {
    check(fields.iter().map(|f| (f.name, f.value)), ctx).map_err(|()| UsageError::InvalidField)
}

/// RFC 9110 §5.6.2 `tchar`.
fn is_tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

fn is_token(v: &[u8]) -> bool {
    !v.is_empty() && v.iter().all(|&b| is_tchar(b))
}

/// RFC 9110 §5.5 `field-value`: visible/obs-text bytes, SP/HTAB only between them.
fn is_field_value(v: &[u8]) -> bool {
    let sp = |b: &u8| matches!(b, b' ' | b'\t');
    v.iter()
        .all(|&b| matches!(b, 0x21..=0x7e | 0x80..=0xff | b' ' | b'\t'))
        && !v.first().is_some_and(sp)
        && !v.last().is_some_and(sp)
}

/// RFC 3986 §3.1 `scheme`.
fn is_scheme(v: &[u8]) -> bool {
    v.first().is_some_and(u8::is_ascii_alphabetic)
        && v.iter()
            .all(|&b| b.is_ascii_alphanumeric() || b"+-.".contains(&b))
}

fn parse_content_length(v: &[u8]) -> Option<u64> {
    if v.is_empty() || !v.iter().all(u8::is_ascii_digit) {
        return None;
    }
    v.iter().try_fold(0u64, |n, &d| {
        n.checked_mul(10)?.checked_add(u64::from(d - b'0'))
    })
}

/// CONNECT authority-form: `host:port` (RFC 9114 §4.4).
fn is_host_port(v: &[u8]) -> bool {
    let Some(colon) = v.iter().rposition(|&b| b == b':') else {
        return false;
    };
    let (host, port) = (&v[..colon], &v[colon + 1..]);
    let host_ok = match host {
        [b'[', inner @ .., b']'] => !inner.is_empty() && !inner.contains(&b']'),
        _ => !host.is_empty() && !host.iter().any(|b| b":[]@".contains(b)),
    };
    host_ok && (1..=5).contains(&port.len()) && port.iter().all(u8::is_ascii_digit)
}

/// The single implementation of the message rules (RFC 9114 §4.2, §4.3, §4.4; RFC 9220).
fn check<'a>(
    fields: impl Iterator<Item = (&'a [u8], &'a [u8])>,
    ctx: ValidateCtx,
) -> Result<MessageCheck, ()> {
    let fail = |bad: bool| if bad { Err(()) } else { Ok(()) };
    let mut raw: RawPseudo = [None; 6];
    let mut seen_regular = false;
    let mut content_length = None;
    let mut host = None;
    for (name, value) in fields {
        fail(!is_field_value(value))?;
        if name.starts_with(b":") {
            let i = PSEUDO_NAMES.iter().position(|n| *n == name).ok_or(())?;
            fail(seen_regular || raw[i].is_some())?;
            raw[i] = Some(value);
            continue;
        }
        seen_regular = true;
        fail(!is_token(name) || name.iter().any(u8::is_ascii_uppercase))?;
        match name {
            b"connection" | b"keep-alive" | b"proxy-connection" | b"transfer-encoding"
            | b"upgrade" => return Err(()),
            b"te" => fail(
                !matches!(ctx, ValidateCtx::Request { .. })
                    || !value.eq_ignore_ascii_case(b"trailers"),
            )?,
            b"content-length" => {
                let n = parse_content_length(value).ok_or(())?;
                fail(content_length.is_some_and(|c| c != n))?;
                content_length = Some(n);
            }
            b"host" => {
                fail(host.is_some())?;
                host = Some(value);
            }
            _ => {}
        }
    }

    let mut out = MessageCheck {
        kind: HeadersKind::Request,
        content_length,
        is_connect: false,
        is_extended_connect: false,
        method_is_head: false,
        status: None,
    };
    let p = Pseudo::from_raw(raw);
    match ctx {
        ValidateCtx::Trailers => {
            fail(raw.iter().any(Option::is_some))?;
            out.kind = HeadersKind::Trailers;
        }
        ValidateCtx::Response => {
            fail(raw[..STATUS].iter().any(Option::is_some))?;
            let s = p.status.ok_or(())?;
            // RFC 9110 §15: below 100 is invalid; 600..=999 is tolerated as extension space.
            fail(!(100..=999).contains(&s) || s == 101)?;
            out.kind = if s < 200 {
                HeadersKind::Informational
            } else {
                HeadersKind::Response
            };
            out.status = Some(s);
        }
        ValidateCtx::Request {
            connect_protocol_enabled,
        } => {
            fail(raw[STATUS].is_some())?;
            let method = p.method.ok_or(())?;
            fail(!is_token(method) || p.scheme.is_some_and(|s| !is_scheme(s)))?;
            out.is_connect = method == b"CONNECT";
            out.method_is_head = method == b"HEAD";
            if let Some(protocol) = p.protocol {
                // RFC 8441 §4: :protocol carries an Upgrade token.
                fail(!is_token(protocol))?;
                // Extended CONNECT (RFC 9220 §3, RFC 8441 §4).
                fail(!out.is_connect || !connect_protocol_enabled || p.authority.is_none())?;
                out.is_extended_connect = true;
            } else if out.is_connect {
                fail(p.scheme.is_some() || p.path.is_some())?;
                fail(!p.authority.is_some_and(is_host_port))?;
                return Ok(out);
            }
            let (scheme, path) = (p.scheme.ok_or(())?, p.path.ok_or(())?);
            fail(path.is_empty() || path.iter().any(|b| matches!(b, b' ' | b'\t')))?;
            // RFC 3986 §3.1: schemes are case-insensitive.
            if scheme.eq_ignore_ascii_case(b"http") || scheme.eq_ignore_ascii_case(b"https") {
                let options_star = path == b"*" && method == b"OPTIONS";
                fail(!path.starts_with(b"/") && !options_star)?;
                let authority = p.authority.or(host).ok_or(())?;
                fail(authority.is_empty() || authority.contains(&b'@'))?;
                fail(host.is_some_and(|h| h != authority))?;
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::qpack::encoder::encode_field_section;

    type F<'a> = (&'a [u8], &'a [u8]);

    const REQ: ValidateCtx = ValidateCtx::Request {
        connect_protocol_enabled: false,
    };
    const REQ_EXT: ValidateCtx = ValidateCtx::Request {
        connect_protocol_enabled: true,
    };
    const RESP: ValidateCtx = ValidateCtx::Response;
    const TRAILERS: ValidateCtx = ValidateCtx::Trailers;

    fn encode(fields: &[FieldRef]) -> Vec<u8> {
        let mut buf = Vec::new();
        encode_field_section(fields, &mut buf);
        buf
    }

    fn insert(store: &mut BlockStore, fields: &[F]) -> HeaderBlockId {
        let f: Vec<FieldRef> = fields.iter().map(|&(n, v)| FieldRef::new(n, v)).collect();
        store.insert_decoded(&encode(&f)).unwrap()
    }

    /// Validates both as received and as outgoing; asserts the verdicts agree.
    fn verdict(fields: &[F], ctx: ValidateCtx) -> Result<MessageCheck, ()> {
        let mut store = BlockStore::default();
        let id = insert(&mut store, fields);
        let rx = validate(&store.get(id).unwrap(), ctx);
        let f: Vec<FieldRef> = fields.iter().map(|&(n, v)| FieldRef::new(n, v)).collect();
        let tx = validate_outgoing(&f, ctx);
        match &tx {
            Ok(c) => assert_eq!(rx, Ok(*c), "{fields:?}"),
            Err(e) => {
                assert_eq!(*e, UsageError::InvalidField);
                assert_eq!(rx, Err(()), "{fields:?}");
            }
        }
        rx
    }

    fn ok(fields: &[F], ctx: ValidateCtx) -> MessageCheck {
        verdict(fields, ctx).unwrap_or_else(|()| panic!("expected valid: {fields:?}"))
    }

    fn bad(fields: &[F], ctx: ValidateCtx) {
        assert_eq!(
            verdict(fields, ctx),
            Err(()),
            "expected malformed: {fields:?}"
        );
    }

    fn get_req<'a>(path: &'a [u8], extra: &[F<'a>]) -> Vec<F<'a>> {
        let mut v: Vec<F> = vec![
            (b":method", b"GET"),
            (b":scheme", b"https"),
            (b":authority", b"example.com"),
            (b":path", path),
        ];
        v.extend_from_slice(extra);
        v
    }

    fn ext_connect<'a>(path: &'a [u8], authority: &'a [u8]) -> Vec<F<'a>> {
        vec![
            (b":method", b"CONNECT"),
            (b":protocol", b"websocket"),
            (b":scheme", b"https"),
            (b":authority", authority),
            (b":path", path),
        ]
    }

    fn plain_connect(authority: &[u8]) -> Vec<F<'_>> {
        vec![(b":method", b"CONNECT"), (b":authority", authority)]
    }

    #[test]
    fn valid_get_request() {
        let fields = get_req(b"/index?q=1", &[(b"accept", b"*/*")]);
        let c = ok(&fields, REQ);
        assert_eq!(
            c,
            MessageCheck {
                kind: HeadersKind::Request,
                content_length: None,
                is_connect: false,
                is_extended_connect: false,
                method_is_head: false,
                status: None,
            }
        );
        let mut store = BlockStore::default();
        let id = insert(&mut store, &fields);
        let b = store.get(id).unwrap();
        let p = b.pseudo();
        assert_eq!(p.method, Some(&b"GET"[..]));
        assert_eq!(p.scheme, Some(&b"https"[..]));
        assert_eq!(p.authority, Some(&b"example.com"[..]));
        assert_eq!(p.path, Some(&b"/index?q=1"[..]));
        assert_eq!(p.protocol, None);
        assert_eq!(p.status, None);
        let regular: Vec<FieldRef> = b.iter().collect();
        assert_eq!(regular, [FieldRef::new(b"accept", b"*/*")]);
        assert!(
            ok(
                &[
                    (b":method", b"HEAD"),
                    (b":scheme", b"http"),
                    (b":authority", b"a"),
                    (b":path", b"/")
                ],
                REQ
            )
            .method_is_head
        );
    }

    #[test]
    fn valid_extended_connect_when_enabled() {
        let c = ok(&ext_connect(b"/chat", b"example.com"), REQ_EXT);
        assert!(c.is_connect && c.is_extended_connect);
        assert_eq!(c.kind, HeadersKind::Request);
    }

    #[test]
    fn extended_connect_rejected_when_not_enabled() {
        bad(&ext_connect(b"/chat", b"example.com"), REQ);
    }

    #[test]
    fn plain_connect_rejects_scheme_and_path() {
        let c = ok(&plain_connect(b"example.com:443"), REQ);
        assert!(c.is_connect && !c.is_extended_connect);
        let mut f = plain_connect(b"example.com:443");
        f.push((b":scheme", b"https"));
        bad(&f, REQ);
        let mut f = plain_connect(b"example.com:443");
        f.push((b":path", b"/"));
        bad(&f, REQ);
        // :authority is required.
        bad(&[(b":method", b"CONNECT")], REQ);
    }

    #[test]
    fn method_and_scheme_syntax() {
        let mut f = get_req(b"/", &[]);
        f[0].1 = b"GET POST";
        bad(&f, REQ);
        let mut f = get_req(b"/", &[]);
        f[1].1 = b"1https";
        bad(&f, REQ);
        let mut f = get_req(b"/", &[]);
        f[0].1 = b"";
        bad(&f, REQ);
        // Methods are case-sensitive tokens; any token is fine.
        let mut f = get_req(b"/", &[]);
        f[0].1 = b"get";
        ok(&f, REQ);
        // Non-http schemes with a valid syntax are allowed.
        let mut f = get_req(b"/", &[]);
        f[1].1 = b"coap+tcp.x-1";
        ok(&f, REQ);
    }

    #[test]
    fn extended_connect_path_checked() {
        bad(&ext_connect(b"", b"example.com"), REQ_EXT);
        bad(&ext_connect(b"relative", b"example.com"), REQ_EXT);
        bad(&ext_connect(b"/chat", b"user@example.com"), REQ_EXT);
        for proto in [&b""[..], b"web socket"] {
            let mut f = ext_connect(b"/chat", b"example.com");
            f[1].1 = proto;
            bad(&f, REQ_EXT);
        }
        for missing in [b":scheme" as &[u8], b":path", b":authority"] {
            let f: Vec<F> = ext_connect(b"/chat", b"example.com")
                .into_iter()
                .filter(|(n, _)| *n != missing)
                .collect();
            bad(&f, REQ_EXT);
        }
    }

    #[test]
    fn plain_connect_requires_port() {
        bad(&plain_connect(b"example.com"), REQ);
        ok(&plain_connect(b"example.com:443"), REQ);
        ok(&plain_connect(b"[::1]:443"), REQ);
        for a in [
            &b":443"[..],
            b"example.com:",
            b"example.com:123456",
            b"example.com:44a",
            b"::1:443",
            b"[::1:443",
            b"[]:443",
            b"u@example.com:443",
        ] {
            bad(&plain_connect(a), REQ);
        }
    }

    #[test]
    fn protocol_on_get_rejected() {
        bad(
            &get_req(b"/", &[])
                .into_iter()
                .chain([(&b":protocol"[..], &b"websocket"[..])])
                .collect::<Vec<_>>(),
            REQ_EXT,
        );
    }

    #[test]
    fn uppercase_name_rejected() {
        bad(&get_req(b"/", &[(b"Accept", b"*/*")]), REQ);
    }

    #[test]
    fn invalid_name_chars_rejected() {
        for n in [&b""[..], b"a/b", b"a:b", b"a b"] {
            bad(&get_req(b"/", &[(n, b"x")]), REQ);
        }
        ok(&get_req(b"/", &[(b"x-!#$%&'*+-.^_`|~09", b"x")]), REQ);
    }

    #[test]
    fn invalid_value_chars_rejected() {
        for v in [
            &b"a\x01b"[..],
            b"a\x7fb",
            b"a\rb",
            b" a",
            b"a ",
            b"\ta",
            b"a\nb",
            b"a\0",
        ] {
            bad(&get_req(b"/", &[(b"x", v)]), REQ);
        }
        // Pseudo values are checked too.
        bad(&get_req(b"/a\x00", &[]), REQ);
    }

    #[test]
    fn value_inner_space_ok() {
        ok(
            &get_req(
                b"/",
                &[
                    (b"x", b"a b"),
                    (b"y", b"a\tb"),
                    (b"z", b""),
                    (b"w", b"\x80\xff"),
                ],
            ),
            REQ,
        );
    }

    #[test]
    fn pseudo_after_regular_rejected() {
        bad(
            &[
                (b":method", b"GET"),
                (b":scheme", b"https"),
                (b":authority", b"a"),
                (b"x", b"y"),
                (b":path", b"/"),
            ],
            REQ,
        );
    }

    #[test]
    fn duplicate_pseudo_rejected() {
        bad(
            &get_req(b"/", &[])
                .into_iter()
                .chain([(&b":path"[..], &b"/"[..])])
                .collect::<Vec<_>>(),
            REQ,
        );
        // Unknown pseudo-headers too.
        let mut f = get_req(b"/", &[]);
        f.insert(0, (b":foo", b"x"));
        bad(&f, REQ);
        let mut f = get_req(b"/", &[]);
        f.insert(0, (b":", b"x"));
        bad(&f, REQ);
    }

    #[test]
    fn connection_specific_rejected() {
        for n in [
            &b"connection"[..],
            b"keep-alive",
            b"proxy-connection",
            b"transfer-encoding",
            b"upgrade",
        ] {
            bad(&get_req(b"/", &[(n, b"x")]), REQ);
            bad(&[(b":status", b"200"), (n, b"x")], RESP);
        }
    }

    #[test]
    fn te_trailers_only() {
        ok(&get_req(b"/", &[(b"te", b"trailers")]), REQ);
        bad(&get_req(b"/", &[(b"te", b"gzip")]), REQ);
        bad(&get_req(b"/", &[(b"te", b"trailers, gzip")]), REQ);
    }

    #[test]
    fn te_rejected_in_response_and_trailers() {
        bad(&[(b":status", b"200"), (b"te", b"trailers")], RESP);
        bad(&[(b"te", b"trailers")], TRAILERS);
    }

    #[test]
    fn path_must_be_absolute() {
        bad(&get_req(b"relative", &[]), REQ);
        bad(&get_req(b"*", &[]), REQ);
        bad(&get_req(b"", &[]), REQ);
        bad(&get_req(b"/a b", &[]), REQ);
        // Scheme is case-insensitive: HTTPS gets the http/https rules.
        let mut f = get_req(b"relative", &[]);
        f[1].1 = b"HTTPS";
        bad(&f, REQ);
        let mut f = get_req(b"*", &[]);
        f[0].1 = b"OPTIONS";
        ok(&f, REQ);
        // Missing required pseudo-headers.
        for missing in [b":method" as &[u8], b":scheme", b":path"] {
            let f: Vec<F> = get_req(b"/", &[])
                .into_iter()
                .filter(|(n, _)| *n != missing)
                .collect();
            bad(&f, REQ);
        }
    }

    #[test]
    fn authority_userinfo_rejected() {
        let mut f = get_req(b"/", &[]);
        f[2].1 = b"user@a";
        bad(&f, REQ);
        let f: Vec<F> = get_req(b"/", &[(b"host", b"user@a")])
            .into_iter()
            .filter(|(n, _)| *n != b":authority")
            .collect();
        bad(&f, REQ);
    }

    #[test]
    fn authority_host_mismatch_rejected() {
        bad(&get_req(b"/", &[(b"host", b"other.com")]), REQ);
        ok(&get_req(b"/", &[(b"host", b"example.com")]), REQ);
        let no_authority = |extra: &[F<'static>]| -> Vec<F<'static>> {
            get_req(b"/", extra)
                .into_iter()
                .filter(|(n, _)| *n != b":authority")
                .collect()
        };
        ok(&no_authority(&[(b"host", b"example.com")]), REQ);
        bad(&no_authority(&[]), REQ);
        bad(&no_authority(&[(b"host", b"")]), REQ);
        let mut f = get_req(b"/", &[]);
        f[2].1 = b"";
        bad(&f, REQ);
    }

    #[test]
    fn status_101_rejected() {
        bad(&[(b":status", b"101")], RESP);
    }

    #[test]
    fn status_103_is_informational() {
        let c = ok(&[(b":status", b"103"), (b"link", b"</a>")], RESP);
        assert_eq!(c.kind, HeadersKind::Informational);
        assert_eq!(c.status, Some(103));
        let c = ok(&[(b":status", b"204")], RESP);
        assert_eq!((c.kind, c.status), (HeadersKind::Response, Some(204)));
        for s in [&b"20"[..], b"2000", b"2x0", b"+20", b"099"] {
            bad(&[(b":status", s)], RESP);
        }
        bad(&[], RESP);
        // Request pseudo-headers in a response and :status in a request are malformed.
        bad(&[(b":status", b"200"), (b":path", b"/")], RESP);
        bad(
            &get_req(b"/", &[])
                .into_iter()
                .chain([(&b":status"[..], &b"200"[..])])
                .collect::<Vec<_>>(),
            REQ,
        );
    }

    #[test]
    fn content_length_conflict_rejected() {
        let c = ok(
            &[
                (b":status", b"200"),
                (b"content-length", b"5"),
                (b"content-length", b"5"),
            ],
            RESP,
        );
        assert_eq!(c.content_length, Some(5));
        bad(
            &[
                (b":status", b"200"),
                (b"content-length", b"5"),
                (b"content-length", b"6"),
            ],
            RESP,
        );
        for v in [&b""[..], b"x", b"-1", b"5, 5", b"18446744073709551616"] {
            bad(&[(b":status", b"200"), (b"content-length", v)], RESP);
        }
    }

    #[test]
    fn trailers_reject_pseudo() {
        let c = ok(&[(b"x-checksum", b"abc")], TRAILERS);
        assert_eq!(c.kind, HeadersKind::Trailers);
        bad(&[(b":status", b"200")], TRAILERS);
        bad(&[(b":path", b"/")], TRAILERS);
    }

    #[test]
    fn outgoing_uses_same_rules() {
        let get = get_req(b"/", &[]);
        let mut f: Vec<FieldRef> = get.iter().map(|&(n, v)| FieldRef::new(n, v)).collect();
        assert!(validate_outgoing(&f, REQ).is_ok());
        f.push(FieldRef::new(b"a/b", b"x"));
        assert_eq!(validate_outgoing(&f, REQ), Err(UsageError::InvalidField));
        f.pop();
        f.push(FieldRef::new(b"x", b"\x7f"));
        assert_eq!(validate_outgoing(&f, REQ), Err(UsageError::InvalidField));
    }

    #[test]
    fn stale_block_after_release() {
        let mut store = BlockStore::default();
        let id = insert(&mut store, &[(b":status", b"200")]);
        assert_eq!(store.live_blocks(), 1);
        store.release(id);
        assert_eq!(store.live_blocks(), 0);
        assert_eq!(store.get(id).err(), Some(UsageError::StaleBlock));
        store.release(id); // stale: no-op
        let id2 = insert(&mut store, &[(b":status", b"204")]);
        assert_eq!(id2.slot, id.slot);
        assert_ne!(id2, id);
        assert_eq!(store.get(id).err(), Some(UsageError::StaleBlock));
        assert_eq!(store.get(id2).unwrap().pseudo().status, Some(204));
        assert_eq!(store.slots.len(), 1);
        store.clear();
        assert_eq!(store.live_blocks(), 0);
        assert_eq!(store.get(id2).err(), Some(UsageError::StaleBlock));
        assert!(store.buffered_bytes() > 0);
        // An id from another store's unknown slot is stale, not a panic.
        let foreign = HeaderBlockId {
            slot: 99,
            generation: 0,
        };
        assert_eq!(store.get(foreign).err(), Some(UsageError::StaleBlock));
        store.release(foreign);
    }

    #[test]
    fn decode_error_leaves_slot_free() {
        let mut store = BlockStore::default();
        assert_eq!(
            store.insert_decoded(&[0x00, 0x00, 0xff]).err(),
            Some(H3Code::QPACK_DECOMPRESSION_FAILED)
        );
        assert_eq!(store.live_blocks(), 0);
        let a = insert(&mut store, &[(b":status", b"200")]);
        let b = insert(&mut store, &[(b":status", b"200")]);
        assert_eq!(store.slots.len(), 2);
        assert!(store.get(a).is_ok() && store.get(b).is_ok());
    }

    #[test]
    fn never_index_exposed_by_iter() {
        let secret = FieldRef {
            name: b"authorization",
            value: b"secret",
            never_index: true,
        };
        let buf = encode(&[
            FieldRef::new(b":status", b"200"),
            secret,
            FieldRef::new(b"x", b"y"),
        ]);
        let mut store = BlockStore::default();
        let id = store.insert_decoded(&buf).unwrap();
        let fields: Vec<FieldRef> = store.get(id).unwrap().iter().collect();
        assert_eq!(fields, [secret, FieldRef::new(b"x", b"y")]);
    }
}
