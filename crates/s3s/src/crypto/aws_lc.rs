// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2023-2026 The s3s Authors

use super::Checksum;

/// SHA-1 hash, used for `x-amz-checksum-sha1`.
///
/// Produces a 20-byte digest.
pub struct Sha1(aws_lc_rs::digest::Context);

impl Default for Sha1 {
    fn default() -> Self {
        Self(aws_lc_rs::digest::Context::new(&aws_lc_rs::digest::SHA1_FOR_LEGACY_USE_ONLY))
    }
}

impl Checksum for Sha1 {
    type Output = [u8; 20];

    fn new() -> Self {
        Self::default()
    }

    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    fn finalize(self) -> Self::Output {
        let digest = self.0.finish();
        let mut ans = [0_u8; 20];
        ans.copy_from_slice(digest.as_ref());
        ans
    }
}

/// SHA-256 hash, used for `x-amz-checksum-sha256`.
///
/// Produces a 32-byte digest.
pub struct Sha256(aws_lc_rs::digest::Context);

impl Default for Sha256 {
    fn default() -> Self {
        Self(aws_lc_rs::digest::Context::new(&aws_lc_rs::digest::SHA256))
    }
}

impl Checksum for Sha256 {
    type Output = [u8; 32];

    fn new() -> Self {
        Self::default()
    }

    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    fn finalize(self) -> Self::Output {
        let digest = self.0.finish();
        let mut ans = [0_u8; 32];
        ans.copy_from_slice(digest.as_ref());
        ans
    }
}

/// SHA-512 hash, used for `x-amz-checksum-sha512`.
///
/// Produces a 64-byte digest.
pub struct Sha512(aws_lc_rs::digest::Context);

impl Default for Sha512 {
    fn default() -> Self {
        Self(aws_lc_rs::digest::Context::new(&aws_lc_rs::digest::SHA512))
    }
}

impl Checksum for Sha512 {
    type Output = [u8; 64];

    fn new() -> Self {
        Self::default()
    }

    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    fn finalize(self) -> Self::Output {
        let digest = self.0.finish();
        let mut ans = [0_u8; 64];
        ans.copy_from_slice(digest.as_ref());
        ans
    }
}
