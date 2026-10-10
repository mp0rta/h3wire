// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 mp0rta
//! `http` <-> QPACK field mapping.

use std::ops::Range;

use h3wire::{FieldRef, H3Code, HeaderBlockRef, UsageError};
use http::header::{CONNECTION, HOST, TE, TRANSFER_ENCODING, UPGRADE};
use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri, Version};

use crate::ext::Protocol;

/// Owned encoded fields: one buffer plus `(name, value, never_index)` ranges.
pub(crate) struct Fields {
    buf: Vec<u8>,
    entries: Vec<(Range<usize>, Range<usize>, bool)>,
}

impl Fields {
    fn new() -> Self {
        Self {
            buf: Vec::new(),
            entries: Vec::new(),
        }
    }

    fn push(&mut self, name: &[u8], value: &[u8], never_index: bool) {
        let a = self.buf.len();
        self.buf.extend_from_slice(name);
        let b = self.buf.len();
        self.buf.extend_from_slice(value);
        self.entries.push((a..b, b..self.buf.len(), never_index));
    }

    fn push_map(&mut self, map: &HeaderMap, skip_host: bool) {
        for (name, value) in map {
            if skip_host && name == HOST {
                continue;
            }
            let hop = name == CONNECTION
                || name == TRANSFER_ENCODING
                || name == UPGRADE
                || name.as_str() == "keep-alive"
                || name.as_str() == "proxy-connection"
                || (name == TE && value.as_bytes() != b"trailers");
            if !hop {
                self.push(
                    name.as_str().as_bytes(),
                    value.as_bytes(),
                    value.is_sensitive(),
                );
            }
        }
    }

    pub(crate) fn as_refs(&self) -> Vec<FieldRef<'_>> {
        self.entries
            .iter()
            .map(|(n, v, ni)| FieldRef {
                name: &self.buf[n.clone()],
                value: &self.buf[v.clone()],
                never_index: *ni,
            })
            .collect()
    }
}

pub(crate) fn request_fields(parts: &http::request::Parts) -> Result<Fields, UsageError> {
    let host = parts.headers.get(HOST);
    let authority = match parts.uri.authority() {
        Some(a) => a.as_str().as_bytes(),
        None => host.ok_or(UsageError::InvalidField)?.as_bytes(),
    };
    let used_host = parts.uri.authority().is_none();
    let mut f = Fields::new();
    f.push(b":method", parts.method.as_str().as_bytes(), false);
    let plain_connect =
        parts.method == Method::CONNECT && parts.extensions.get::<Protocol>().is_none();
    if !plain_connect {
        let scheme = parts.uri.scheme_str().unwrap_or("https");
        f.push(b":scheme", scheme.as_bytes(), false);
    }
    f.push(b":authority", authority, false);
    if !plain_connect {
        let path = parts.uri.path_and_query().map_or("/", |p| p.as_str());
        f.push(b":path", path.as_bytes(), false);
        if let Some(p) = parts.extensions.get::<Protocol>() {
            f.push(b":protocol", p.as_bytes(), false);
        }
    }
    f.push_map(&parts.headers, used_host);
    Ok(f)
}

pub(crate) fn response_fields(parts: &http::response::Parts) -> Fields {
    let mut f = Fields::new();
    f.push(b":status", parts.status.as_str().as_bytes(), false);
    f.push_map(&parts.headers, false);
    f
}

pub(crate) fn trailer_fields(map: &HeaderMap) -> Fields {
    let mut f = Fields::new();
    f.push_map(map, false);
    f
}

pub(crate) fn headers_from_block(b: &HeaderBlockRef<'_>) -> Result<HeaderMap, H3Code> {
    let mut map = HeaderMap::new();
    for f in b.iter() {
        let name = HeaderName::from_bytes(f.name).map_err(|_| H3Code::MESSAGE_ERROR)?;
        let mut value = HeaderValue::from_bytes(f.value).map_err(|_| H3Code::MESSAGE_ERROR)?;
        value.set_sensitive(f.never_index);
        map.append(name, value);
    }
    Ok(map)
}

pub(crate) fn request_from_block(b: &HeaderBlockRef<'_>) -> Result<http::Request<()>, H3Code> {
    let p = b.pseudo();
    fn bad<E>(_: E) -> H3Code {
        H3Code::MESSAGE_ERROR
    }
    let method = Method::from_bytes(p.method.ok_or(H3Code::MESSAGE_ERROR)?).map_err(bad)?;
    let mut up = http::uri::Parts::default();
    if let Some(s) = p.scheme {
        up.scheme = Some(s.try_into().map_err(bad)?);
    }
    if let Some(a) = p.authority {
        up.authority = Some(a.try_into().map_err(bad)?);
    }
    if let Some(path) = p.path {
        up.path_and_query = Some(path.try_into().map_err(bad)?);
    }
    let uri = Uri::from_parts(up).map_err(bad)?;
    let mut req = http::Request::new(());
    *req.method_mut() = method;
    *req.uri_mut() = uri;
    *req.version_mut() = Version::HTTP_3;
    *req.headers_mut() = headers_from_block(b)?;
    if let Some(proto) = p.protocol {
        req.extensions_mut()
            .insert(Protocol::new(bytes::Bytes::copy_from_slice(proto)));
    }
    Ok(req)
}

pub(crate) fn response_from_block(b: &HeaderBlockRef<'_>) -> Result<http::Response<()>, H3Code> {
    let status = b.pseudo().status.ok_or(H3Code::MESSAGE_ERROR)?;
    let mut resp = http::Response::new(());
    *resp.status_mut() = StatusCode::from_u16(status).map_err(|_| H3Code::MESSAGE_ERROR)?;
    *resp.version_mut() = Version::HTTP_3;
    *resp.headers_mut() = headers_from_block(b)?;
    Ok(resp)
}
