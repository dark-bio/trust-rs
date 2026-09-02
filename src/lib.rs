// trust-rs: dark bio ecosystem roots of trust
// Copyright 2026 Dark Bio AG. All rights reserved.

// Pull in the README as the package doc
#![doc = include_str!("../README.md")]

pub mod cloud;
pub mod device;
pub mod roots;

#[cfg(not(any(feature = "release", feature = "staging", feature = "develop")))]
compile_error!("at least one environment feature must be enabled: release, staging or develop");

use darkbio_crypto::{cwt, xdsa};
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

/// Longest validity period a cloud attestation may carry, forcing the cloud to
/// rotate its keys and bounding how long a leaked cloud key stays attested.
pub const CLOUD_ATTESTATION_MAX_VALIDITY: Duration = Duration::from_secs(3600 * 24 * 90);

/// Environment represents the deployments of the ecosystem, which devices are
/// built for and clouds run in, each with its own roots. Every environment is
/// gated behind a crate feature of the same name, so a build only ever embeds
/// the roots of the environments it is meant to trust.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Environment {
    #[cfg(feature = "release")]
    Release,
    #[cfg(feature = "staging")]
    Staging,
    #[cfg(feature = "develop")]
    Develop,
}

/// Realm separates the hardware device universe from the emulated one.
/// Hardware devices are attested once at manufacturing by the hardware roots and
/// never expire, emulated devices are attested online by the emulator roots
/// and always expire. The two realms never share trust.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Realm {
    Hardware,
    Emulator,
}

/// Error is the failures that can occur during attestation verification.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("unexpected attestation signer {}", hex::encode(.0.to_bytes()))]
    UnexpectedSigner(xdsa::Fingerprint),
    #[error("attestation is not self-signed")]
    NotSelfSigned,
    #[error("attestation validity exceeds allowed {} days", max.as_secs() / 86400)]
    InvalidValidity { max: Duration },
    #[error("cwt: {0}")]
    Cwt(#[from] cwt::Error),
}
