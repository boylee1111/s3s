// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2023-2026 The s3s Authors

use super::Checksum;

/// SHA-1 hash, used for `x-amz-checksum-sha1`.
///
/// Produces a 20-byte digest.
#[derive(Default)]
pub struct Sha1(sha1::Sha1);

impl Checksum for Sha1 {
    type Output = [u8; 20];

    fn new() -> Self {
        Self::default()
    }

    fn update(&mut self, data: &[u8]) {
        use sha1::Digest as _;
        self.0.update(data);
    }

    fn finalize(self) -> Self::Output {
        use sha1::Digest as _;
        self.0.finalize().into()
    }
}

/// SHA-256 hash, used for `x-amz-checksum-sha256`.
///
/// Produces a 32-byte digest.
#[derive(Default)]
pub struct Sha256(sha2::Sha256);

impl Checksum for Sha256 {
    type Output = [u8; 32];

    fn new() -> Self {
        Self::default()
    }

    fn update(&mut self, data: &[u8]) {
        use sha2::Digest as _;
        self.0.update(data);
    }

    fn finalize(self) -> Self::Output {
        use sha2::Digest as _;
        self.0.finalize().into()
    }
}

/// SHA-512 hash, used for `x-amz-checksum-sha512`.
///
/// Produces a 64-byte digest.
#[derive(Default)]
pub struct Sha512(sha2::Sha512);

impl Checksum for Sha512 {
    type Output = [u8; 64];

    fn new() -> Self {
        Self::default()
    }

    fn update(&mut self, data: &[u8]) {
        use sha2::Digest as _;
        self.0.update(data);
    }

    fn finalize(self) -> Self::Output {
        use sha2::Digest as _;
        self.0.finalize().into()
    }
}
