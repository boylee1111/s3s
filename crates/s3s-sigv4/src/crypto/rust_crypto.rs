// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2023-2026 The s3s Authors

use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};

pub(super) fn sha256(data: &[u8]) -> [u8; 32] {
    <Sha256 as Digest>::digest(data).into()
}

pub(super) fn sha256_chunk(chunk: &[impl AsRef<[u8]>]) -> [u8; 32] {
    let mut h = <Sha256 as Digest>::new();
    for data in chunk {
        h.update(data.as_ref());
    }
    h.finalize().into()
}

/// `hmac_sha256(key, data)`
///
/// # Panics
///
/// `HMAC-SHA256` accepts keys of any length, so `new_from_slice` never
/// fails. This `expect` is a structural invariant of the `hmac` crate API;
/// no request input can influence it.
#[allow(clippy::expect_used)]
pub(crate) fn hmac_sha256(key: impl AsRef<[u8]>, data: impl AsRef<[u8]>) -> [u8; 32] {
    let mut m = <Hmac<Sha256>>::new_from_slice(key.as_ref()).expect("Hmac accepts keys of any length");
    m.update(data.as_ref());
    m.finalize().into_bytes().into()
}
