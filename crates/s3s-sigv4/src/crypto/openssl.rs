// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2023-2026 The s3s Authors

use hmac::{Hmac, KeyInit, Mac};
use openssl::hash::{Hasher, MessageDigest};
use sha2::Sha256;

/// # Panics
///
/// `openssl` hash operations fail only on invalid internal state; a digest
/// over in-memory data cannot trigger it. The lint is allowed here and the
/// invariant is documented.
#[allow(clippy::unwrap_used)]
pub(super) fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Hasher::new(MessageDigest::sha256()).unwrap();
    h.update(data).unwrap();
    let digest = h.finish().unwrap();
    let mut ans = [0_u8; 32];
    ans.copy_from_slice(&digest);
    ans
}

/// # Panics
///
/// `openssl` hash operations fail only on invalid internal state; a digest
/// over in-memory data cannot trigger it. The lint is allowed here and the
/// invariant is documented.
#[allow(clippy::unwrap_used)]
pub(super) fn sha256_chunk(chunk: &[impl AsRef<[u8]>]) -> [u8; 32] {
    let mut h = Hasher::new(MessageDigest::sha256()).unwrap();
    for data in chunk {
        h.update(data.as_ref()).unwrap();
    }
    let digest = h.finish().unwrap();
    let mut ans = [0_u8; 32];
    ans.copy_from_slice(&digest);
    ans
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
