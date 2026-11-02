// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2023-2026 The s3s Authors

pub(super) fn sha256(data: &[u8]) -> [u8; 32] {
    let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, data);
    let mut ans = [0_u8; 32];
    ans.copy_from_slice(digest.as_ref());
    ans
}

pub(super) fn sha256_chunk(chunk: &[impl AsRef<[u8]>]) -> [u8; 32] {
    let mut h = aws_lc_rs::digest::Context::new(&aws_lc_rs::digest::SHA256);
    for data in chunk {
        h.update(data.as_ref());
    }
    let digest = h.finish();
    let mut ans = [0_u8; 32];
    ans.copy_from_slice(digest.as_ref());
    ans
}

pub(crate) fn hmac_sha256(key: impl AsRef<[u8]>, data: impl AsRef<[u8]>) -> [u8; 32] {
    let signing_key = aws_lc_rs::hmac::Key::new(aws_lc_rs::hmac::HMAC_SHA256, key.as_ref());
    let tag = aws_lc_rs::hmac::sign(&signing_key, data.as_ref());
    let mut ans = [0_u8; 32];
    ans.copy_from_slice(tag.as_ref());
    ans
}
