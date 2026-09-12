// trust-rs: dark bio ecosystem roots of trust
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Pull in the README as the package doc
#![doc = include_str!("../README.md")]
// The crate only composes the cryptography crate and never needs unsafe itself
#![forbid(unsafe_code)]

pub mod cloud;
pub mod device;
pub mod roots;

/// The cryptography crate this one builds on, re-exported so consumers can
/// name its types at the exact version this crate was compiled against.
pub use darkbio_crypto as crypto;

use darkbio_crypto::{cwt, xdsa};
use std::fmt;
use std::time::Duration;

/// Domain separator of device attestations, binding the signature of a root
/// to the attestation format so it cannot be replayed into other protocols
/// using the same key.
pub const CRYPTO_DOMAIN_DEVICE_ATTESTATION: &[u8] = b"device-attestation-v1";

/// Domain separator of cloud attestations, binding the signature of a cloud
/// root to the attestation format so it cannot be replayed into other protocols
/// using the same key.
pub const CRYPTO_DOMAIN_CLOUD_ATTESTATION: &[u8] = b"cloud-attestation-v1";

/// Longest validity period an emulator attestation may carry, bounding how
/// long an emulated device stays attested.
pub const EMULATOR_ATTESTATION_MAX_VALIDITY: Duration = Duration::from_secs(3600 * 24 * 30);

/// Longest validity period a cloud attestation may carry.
pub const CLOUD_ATTESTATION_MAX_VALIDITY: Duration = Duration::from_secs(3600 * 24 * 90);

/// Environment represents the deployments of the ecosystem, which devices are
/// built for and clouds run in, each with its own roots. Every environment can
/// be named in every build, but its root keys are only embedded when the crate
/// feature of the same name is enabled. An environment without keys has empty
/// root sets, so nothing verifies under it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Environment {
    /// The environment serving actual users, with devices manufactured for it.
    Release,
    /// The pre-release verification environment.
    Staging,
    /// The development deployments.
    Develop,
}

impl fmt::Display for Environment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Environment::Release => "release",
            Environment::Staging => "staging",
            Environment::Develop => "develop",
        })
    }
}

/// Realm separates the hardware device universe from the emulated one.
/// Hardware devices are attested once at manufacturing by the hardware roots and
/// never expire, emulated devices are attested online by the emulator roots
/// and always expire. The two realms never share trust.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Realm {
    /// Hardware Arks, attested once at manufacturing under the device root of
    /// their series.
    Hardware,
    /// Emulated Arks, attested online under the emulator root with an expiry.
    Emulator,
}

/// Failures during attestation verification.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The token names a signer outside the selected roots. This identifier
    /// and its optional root metadata have not been authenticated.
    #[error("attestation signed by {}, which is not among the trusted roots", describe_signer(.fingerprint, .root))]
    UntrustedSigner {
        /// Fingerprint of the signer, taken from the unverified header.
        fingerprint: xdsa::Fingerprint,
        /// Published root metadata matching the claimed signer fingerprint.
        root: Option<roots::Root>,
    },
    /// The claimed self-signer differs from the embedded identity key.
    #[error("attestation is not self-signed")]
    NotSelfSigned,
    /// The signed validity period is empty, inverted or longer than the cap.
    /// Enforced even when verification skips the clock check.
    #[error("invalid attestation validity; expected a positive duration of at most {} days", max.as_secs() / 86400)]
    InvalidValidity {
        /// The longest validity period accepted for the attestation's kind.
        max: Duration,
    },
    /// Signature, encoding, domain, claim-shape or clock-check failure.
    #[error("cwt: {0}")]
    Cwt(#[from] cwt::Error),
}

/// Enforces the lifetime cap independently of checks against the current time.
fn check_validity(nbf: u64, exp: u64, max: Duration) -> Result<(), Error> {
    if nbf >= exp || exp - nbf > max.as_secs() {
        return Err(Error::InvalidValidity { max });
    }
    Ok(())
}

fn describe_signer(fingerprint: &xdsa::Fingerprint, root: &Option<roots::Root>) -> String {
    match root {
        Some(info) => format!("the {info} ({})", hex::encode(fingerprint.to_bytes())),
        None => format!("unknown key {}", hex::encode(fingerprint.to_bytes())),
    }
}

impl Error {
    pub(crate) fn untrusted_signer(fingerprint: xdsa::Fingerprint) -> Self {
        Self::UntrustedSigner {
            root: roots::identify(&fingerprint),
            fingerprint,
        }
    }
}
