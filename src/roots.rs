// trust-rs: roots of trust for the Dark Bio ecosystem
// Copyright 2026 Dark Bio AG. All rights reserved.

//! Root keys of the Dark Bio ecosystem, embedded verbatim from the public keys
//! of the Dark Bio transparency report repository.

use crate::Environment;
use darkbio_crypto::xdsa;
use std::sync::LazyLock;

/// Keyset is the set of roots of trusts of an environment.
struct Keyset {
    hardware: Vec<xdsa::PublicKey>, // Hardware device roots, one per manufactured series
    emulator: Vec<xdsa::PublicKey>, // Emulator roots attesting the emulated devices
    cloud: xdsa::PublicKey,         // Cloud root attesting the rotating cloud identities
}

/// Parses an embedded PEM public key, panicking on failure as the keys are
/// compile time constants.
fn parse(pem: &str) -> xdsa::PublicKey {
    xdsa::PublicKey::from_pem(pem).expect("embedded root key must parse")
}

/// Roots of the release environment, the keys attesting devices manufactured for and
/// the cloud serving actual users.
static RELEASE: LazyLock<Keyset> = LazyLock::new(|| Keyset {
    hardware: vec![
        parse(include_str!("../roots/deviceattest-ark1-alpha.xdsa.pub")),
        parse(include_str!("../roots/deviceattest-ark1-friend.xdsa.pub")),
        parse(include_str!("../roots/deviceattest-ark1-founder.xdsa.pub")),
    ],
    emulator: vec![parse(include_str!(
        "../roots/deviceattest-emulator-release.xdsa.pub"
    ))],
    cloud: parse(include_str!("../roots/cloudattest-release.xdsa.pub")),
});

/// Roots of the staging environment, the keys of the pre-release verification
/// environment. Published for reference, nothing in production trusts them.
static STAGING: LazyLock<Keyset> = LazyLock::new(|| Keyset {
    hardware: vec![parse(include_str!(
        "../roots/internal/deviceattest-ark1-staging.xdsa.pub"
    ))],
    emulator: vec![parse(include_str!(
        "../roots/internal/deviceattest-emulator-staging.xdsa.pub"
    ))],
    cloud: parse(include_str!(
        "../roots/internal/cloudattest-staging.xdsa.pub"
    )),
});

/// Roots of the develop environment, the keys of the development deployments.
/// Published for reference, nothing in production trusts them.
static DEVELOP: LazyLock<Keyset> = LazyLock::new(|| Keyset {
    hardware: vec![parse(include_str!(
        "../roots/internal/deviceattest-ark1-develop.xdsa.pub"
    ))],
    emulator: vec![parse(include_str!(
        "../roots/internal/deviceattest-emulator-develop.xdsa.pub"
    ))],
    cloud: parse(include_str!(
        "../roots/internal/cloudattest-develop.xdsa.pub"
    )),
});

/// Retrieves the roots of an environment.
fn keyset(environment: Environment) -> &'static Keyset {
    match environment {
        Environment::Release => &RELEASE,
        Environment::Staging => &STAGING,
        Environment::Develop => &DEVELOP,
    }
}

/// Roots attesting the hardware devices of an environment, one per manufactured
/// series. A device attestation is verified against whichever root matches its
/// signer.
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
    // accidentally, and that the environments hold the expected number of roots.
    #[test]
    fn test_embedded_roots() {
        for (environment, count) in [
            (Environment::Release, 3),
            (Environment::Staging, 1),
            (Environment::Develop, 1),
        ] {
            assert_eq!(
                hardware(environment).len(),
                count,
                "hardware root count mismatch"
            );
            assert_eq!(
                emulator(environment).len(),
                1,
                "emulator root count mismatch"
            );
            let _ = cloud(environment);
        }
    }
}
