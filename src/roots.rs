// trust-rs: dark bio ecosystem roots of trust
// Copyright 2026 Dark Bio AG. All rights reserved.

//! Root keys of the Dark Bio ecosystem, embedded verbatim from the public keys
//! of the Dark Bio transparency report repository. Only the environments
//! enabled by the crate features are embedded.

#![cfg(any(feature = "release", feature = "staging", feature = "develop"))]

use crate::Environment;
use darkbio_crypto::{rsa, xdsa};
use std::sync::LazyLock;

/// Series is a manufacturing run of hardware Arks, along with the keys vouching
/// for them. The secure boot key is burnt into the compute modules and verifies
/// the boot images, the firmware update key verifies the update bundles and the
/// device root signs the device attestations.
pub struct Series {
    pub secure_boot: rsa::PublicKey, // RSA-2048 key verifying the boot images
    pub firmware_update: xdsa::PublicKey, // xDSA key verifying the firmware update bundles
    pub device_root: xdsa::PublicKey, // xDSA key signing the device attestations
}

/// Keyset is the set of roots of trusts of an environment.
struct Keyset {
    series: Vec<Series>,            // Hardware series, along with their keys
    hardware: Vec<xdsa::PublicKey>, // Hardware device roots, the device root of every series
    emulator: Vec<xdsa::PublicKey>, // Emulator roots attesting the emulated devices
    cloud: xdsa::PublicKey,         // Cloud root attesting the rotating cloud identities
}

impl Keyset {
    /// Assembles the keyset of an environment out of its series and roots, the
    /// hardware device roots being those of the series.
    fn new(series: Vec<Series>, emulator: Vec<xdsa::PublicKey>, cloud: xdsa::PublicKey) -> Self {
        let hardware = series.iter().map(|s| s.device_root.clone()).collect();
        Self {
            series,
            hardware,
            emulator,
            cloud,
        }
    }
}

/// Parses an embedded PEM public key, panicking on failure as the keys are
/// compile time constants.
fn parse(pem: &str) -> xdsa::PublicKey {
    xdsa::PublicKey::from_pem(pem).expect("embedded root key must parse")
}

/// Assembles a series out of its embedded PEM public keys, panicking on failure
/// as the keys are compile time constants.
fn series_of(secure_boot: &str, firmware_update: &str, device_root: &str) -> Series {
    Series {
        secure_boot: rsa::PublicKey::from_pem(secure_boot).expect("embedded root key must parse"),
        firmware_update: parse(firmware_update),
        device_root: parse(device_root),
    }
}

/// Roots of the release environment, the keys attesting devices manufactured for and
/// the cloud serving actual users.
#[cfg(feature = "release")]
static RELEASE: LazyLock<Keyset> = LazyLock::new(|| {
    Keyset::new(
        vec![
            series_of(
                include_str!("../roots/secureboot-ark1-alpha.rsa.pub"),
                include_str!("../roots/firmwareupdate-ark1-alpha.xdsa.pub"),
                include_str!("../roots/deviceattest-ark1-alpha.xdsa.pub"),
            ),
            series_of(
                include_str!("../roots/secureboot-ark1-friend.rsa.pub"),
                include_str!("../roots/firmwareupdate-ark1-friend.xdsa.pub"),
                include_str!("../roots/deviceattest-ark1-friend.xdsa.pub"),
            ),
            series_of(
                include_str!("../roots/secureboot-ark1-founder.rsa.pub"),
                include_str!("../roots/firmwareupdate-ark1-founder.xdsa.pub"),
                include_str!("../roots/deviceattest-ark1-founder.xdsa.pub"),
            ),
        ],
        vec![parse(include_str!(
            "../roots/deviceattest-emulator-release.xdsa.pub"
        ))],
        parse(include_str!("../roots/cloudattest-release.xdsa.pub")),
    )
});

/// Roots of the staging environment, the keys of the pre-release verification
/// environment. Published for reference, nothing in production trusts them.
#[cfg(feature = "staging")]
static STAGING: LazyLock<Keyset> = LazyLock::new(|| {
    Keyset::new(
        vec![series_of(
            include_str!("../roots/internal/secureboot-ark1-staging.rsa.pub"),
            include_str!("../roots/internal/firmwareupdate-ark1-staging.xdsa.pub"),
            include_str!("../roots/internal/deviceattest-ark1-staging.xdsa.pub"),
        )],
        vec![parse(include_str!(
            "../roots/internal/deviceattest-emulator-staging.xdsa.pub"
        ))],
        parse(include_str!(
            "../roots/internal/cloudattest-staging.xdsa.pub"
        )),
    )
});

/// Roots of the develop environment, the keys of the development deployments.
/// Published for reference, nothing in production trusts them.
#[cfg(feature = "develop")]
static DEVELOP: LazyLock<Keyset> = LazyLock::new(|| {
    Keyset::new(
        vec![series_of(
            include_str!("../roots/internal/secureboot-ark1-develop.rsa.pub"),
            include_str!("../roots/internal/firmwareupdate-ark1-develop.xdsa.pub"),
            include_str!("../roots/internal/deviceattest-ark1-develop.xdsa.pub"),
        )],
        vec![parse(include_str!(
            "../roots/internal/deviceattest-emulator-develop.xdsa.pub"
        ))],
        parse(include_str!(
            "../roots/internal/cloudattest-develop.xdsa.pub"
        )),
    )
});

/// Retrieves the roots of an environment.
fn keyset(environment: Environment) -> &'static Keyset {
    match environment {
        #[cfg(feature = "release")]
        Environment::Release => &RELEASE,
        #[cfg(feature = "staging")]
        Environment::Staging => &STAGING,
        #[cfg(feature = "develop")]
        Environment::Develop => &DEVELOP,
    }
}

/// Series of hardware Arks of an environment, along with the keys vouching for
/// each. A device identifies its own series through the secure boot key burnt
/// into it.
pub fn series(environment: Environment) -> &'static [Series] {
    &keyset(environment).series
}

/// Roots attesting the hardware devices of an environment, the device root of
/// every series. A device attestation is verified against whichever root matches
/// its signer.
pub fn hardware(environment: Environment) -> &'static [xdsa::PublicKey] {
    &keyset(environment).hardware
}

/// Roots attesting the emulated devices of an environment. An emulator
/// attestation is verified against whichever root matches its signer.
pub fn emulator(environment: Environment) -> &'static [xdsa::PublicKey] {
    &keyset(environment).emulator
}

/// Root attesting the rotating signing and encryption identities of the cloud
/// of an environment.
pub fn cloud(environment: Environment) -> &'static xdsa::PublicKey {
    &keyset(environment).cloud
}

#[cfg(test)]
mod tests {
    use super::*;

    // Tests that every embedded root parses, so a bad key cannot get committed
    // accidentally, that the environments hold the expected number of series and
    // roots, and that the hardware roots are the device roots of the series.
    #[test]
    fn test_embedded_roots() {
        fn check(environment: Environment, count: usize) {
            assert_eq!(series(environment).len(), count, "series count mismatch");
            assert_eq!(
                hardware(environment).len(),
                count,
                "hardware root count mismatch"
            );
            for (series, root) in series(environment).iter().zip(hardware(environment)) {
                assert_eq!(
                    series.device_root.fingerprint(),
                    root.fingerprint(),
                    "hardware root is not the series device root"
                );
            }
            assert_eq!(
                emulator(environment).len(),
                1,
                "emulator root count mismatch"
            );
            let _ = cloud(environment);
        }
        #[cfg(feature = "release")]
        check(Environment::Release, 3);
        #[cfg(feature = "staging")]
        check(Environment::Staging, 1);
        #[cfg(feature = "develop")]
        check(Environment::Develop, 1);
    }
}
