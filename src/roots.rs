// trust-rs: dark bio ecosystem roots of trust
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! Root keys of the Dark Bio ecosystem, embedded verbatim from the public keys
//! of the Dark Bio transparency report repository. Only the environments
//! enabled by the crate features embed their keys, the others have empty root
//! sets. The fingerprints of every root are present in every build, so a
//! signer can be named even when its key is not trusted.
//!
//! ```
//! use darkbio_trust::{Environment, roots};
//!
//! // Empty without the release feature, and then nothing verifies under it
//! for series in roots::series(Environment::Release) {
//!     let root = roots::identify(&series.device_root.fingerprint()).unwrap();
//!     assert_eq!(root.series, Some(series.name));
//! }
//! ```

use crate::Environment;
use darkbio_crypto::{rsa, xdsa};
use std::fmt;
#[cfg(any(feature = "release", feature = "staging", feature = "develop"))]
use std::sync::LazyLock;

/// Series is a manufacturing run of hardware Arks, along with the keys vouching
/// for them. The secure boot key is burnt into the compute modules and verifies
/// the boot images, the firmware update key verifies the update bundles and the
/// device root signs the device attestations.
#[derive(Clone, Debug)]
pub struct Series {
    /// Name of the series, as in the transparency report.
    pub name: &'static str,
    /// RSA-2048 key verifying the boot images.
    pub secure_boot: rsa::PublicKey,
    /// xDSA key verifying the firmware update bundles.
    pub firmware_update: xdsa::PublicKey,
    /// xDSA key signing the device attestations.
    pub device_root: xdsa::PublicKey,
}

/// Keyset is the set of roots of trusts of an environment.
struct Keyset {
    series: Vec<Series>,            // Hardware series, along with their keys
    hardware: Vec<xdsa::PublicKey>, // Hardware device roots, the device root of every series
    emulator: Vec<xdsa::PublicKey>, // Emulator roots attesting the emulated devices
    cloud: Option<xdsa::PublicKey>, // Cloud root attesting the rotating cloud identities
}

impl Keyset {
    /// Assembles the keyset of an environment out of its series and roots, the
    /// hardware device roots being those of the series.
    #[cfg(any(feature = "release", feature = "staging", feature = "develop"))]
    fn new(series: Vec<Series>, emulator: Vec<xdsa::PublicKey>, cloud: xdsa::PublicKey) -> Self {
        let hardware = series.iter().map(|s| s.device_root.clone()).collect();
        Self {
            series,
            hardware,
            emulator,
            cloud: Some(cloud),
        }
    }
}

/// Keyset of an environment whose feature is disabled, trusting nothing.
#[cfg(not(all(feature = "release", feature = "staging", feature = "develop")))]
static EMPTY: Keyset = Keyset {
    series: Vec::new(),
    hardware: Vec::new(),
    emulator: Vec::new(),
    cloud: None,
};

/// Parses an embedded PEM public key, panicking on failure as the keys are
/// compile time constants.
#[cfg(any(feature = "release", feature = "staging", feature = "develop"))]
fn parse(pem: &str) -> xdsa::PublicKey {
    xdsa::PublicKey::from_pem(pem).expect("embedded root key must parse")
}

/// Assembles a series out of its embedded PEM public keys, panicking on failure
/// as the keys are compile time constants.
#[cfg(any(feature = "release", feature = "staging", feature = "develop"))]
fn series_of(
    name: &'static str,
    secure_boot: &str,
    firmware_update: &str,
    device_root: &str,
) -> Series {
    Series {
        name,
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
                "ark1-alpha",
                include_str!("../roots/secureboot-ark1-alpha.rsa.pub"),
                include_str!("../roots/firmwareupdate-ark1-alpha.xdsa.pub"),
                include_str!("../roots/deviceattest-ark1-alpha.xdsa.pub"),
            ),
            series_of(
                "ark1-friend",
                include_str!("../roots/secureboot-ark1-friend.rsa.pub"),
                include_str!("../roots/firmwareupdate-ark1-friend.xdsa.pub"),
                include_str!("../roots/deviceattest-ark1-friend.xdsa.pub"),
            ),
            series_of(
                "ark1-founder",
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
            "ark1-staging",
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
            "ark1-develop",
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

/// Retrieves the roots of an environment, an empty set for an environment
/// whose feature is disabled.
fn keyset(environment: Environment) -> &'static Keyset {
    match environment {
        #[cfg(feature = "release")]
        Environment::Release => &RELEASE,
        #[cfg(not(feature = "release"))]
        Environment::Release => &EMPTY,
        #[cfg(feature = "staging")]
        Environment::Staging => &STAGING,
        #[cfg(not(feature = "staging"))]
        Environment::Staging => &EMPTY,
        #[cfg(feature = "develop")]
        Environment::Develop => &DEVELOP,
        #[cfg(not(feature = "develop"))]
        Environment::Develop => &EMPTY,
    }
}

/// Series of hardware Arks of an environment, along with the keys vouching for
/// each. A device identifies its own series through the secure boot key burnt
/// into it. Empty for an environment this build does not embed.
pub fn series(environment: Environment) -> &'static [Series] {
    &keyset(environment).series
}

/// Roots attesting the hardware devices of an environment, the device root of
/// every series. A device attestation is verified against whichever root matches
/// its signer. Empty for an environment this build does not embed.
pub fn hardware(environment: Environment) -> &'static [xdsa::PublicKey] {
    &keyset(environment).hardware
}

/// Roots attesting the emulated devices of an environment. An emulator
/// attestation is verified against whichever root matches its signer. Empty for
/// an environment this build does not embed.
pub fn emulator(environment: Environment) -> &'static [xdsa::PublicKey] {
    &keyset(environment).emulator
}

/// Root attesting the rotating signing and encryption identities of the cloud
/// of an environment. Returns `None` when the environment's keys are not embedded.
pub fn cloud(environment: Environment) -> Option<&'static xdsa::PublicKey> {
    keyset(environment).cloud.as_ref()
}

/// Role is what a root signs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Role {
    /// Verifies boot images for a hardware series, using RSA.
    SecureBoot,
    /// Signs the device attestations of a hardware series.
    DeviceAttester,
    /// Signs the firmware update bundles of a hardware series.
    FirmwareUpdate,
    /// Signs the attestations of emulated devices.
    EmulatorAttester,
    /// Signs the attestations of the rotating cloud identities.
    CloudAttester,
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Role::SecureBoot => "secure boot root",
            Role::DeviceAttester => "device attester",
            Role::FirmwareUpdate => "firmware update root",
            Role::EmulatorAttester => "emulator attester",
            Role::CloudAttester => "cloud attester",
        })
    }
}

/// Root is a root of the ecosystem identified by its fingerprint, whether or
/// not this build embeds its key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Root {
    /// Environment the root belongs to.
    pub env: Environment,
    /// What the root signs.
    pub role: Role,
    /// Hardware series the root belongs to, for the roles bound to one.
    pub series: Option<&'static str>,
}

impl fmt::Display for Root {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.env, self.role)?;
        if let Some(series) = self.series {
            write!(f, " of series {series}")?;
        }
        Ok(())
    }
}

/// Builds a table entry.
const fn known(environment: Environment, role: Role, series: Option<&'static str>) -> Root {
    Root {
        env: environment,
        role,
        series,
    }
}

/// Fingerprints of every root of the ecosystem, present in every build so
/// a signer can be named even when its key is not embedded. A fingerprint alone
/// cannot verify anything. The tests check the table against the embedded keys,
/// which the roots workflow checks against the transparency report in turn.
const KNOWN: &[(&str, Root)] = &[
    (
        "fe56b1de20bde6010569c90e611197356ad521c5e3d27f7afbbb65b5600bbb12",
        known(
            Environment::Release,
            Role::DeviceAttester,
            Some("ark1-alpha"),
        ),
    ),
    (
        "70dc7fb4c0cf661b4dd894bfcfd940513a0ef79e967b14f59d5338ed3dda7636",
        known(
            Environment::Release,
            Role::FirmwareUpdate,
            Some("ark1-alpha"),
        ),
    ),
    (
        "8b842c20bb8083a1635140e58675f3b95a100ac0e39ab82fa6cb2ef23eb532fb",
        known(
            Environment::Release,
            Role::DeviceAttester,
            Some("ark1-friend"),
        ),
    ),
    (
        "867dfb0f09b7b6346686c5f6a93870f2acf576e641092c2af808f3af638882cf",
        known(
            Environment::Release,
            Role::FirmwareUpdate,
            Some("ark1-friend"),
        ),
    ),
    (
        "a7ddc4a37dd02c147fa2ea19558e3bf589efd1fa6aa6a40e37c22fa218004880",
        known(
            Environment::Release,
            Role::DeviceAttester,
            Some("ark1-founder"),
        ),
    ),
    (
        "b70951cbe159ce0c02a5b18500422ce70a3bd13de05cd272949d9f9913507720",
        known(
            Environment::Release,
            Role::FirmwareUpdate,
            Some("ark1-founder"),
        ),
    ),
    (
        "b237c4d700573b12d432fddf886a90736fd5be9fa189a90813f16c2357989128",
        known(Environment::Release, Role::EmulatorAttester, None),
    ),
    (
        "a5744fb0ea234d9544375c521baf8935a2e5ac328e7e39581516de233e66009d",
        known(Environment::Release, Role::CloudAttester, None),
    ),
    (
        "7d725c5cb3f80ef4e17bb98ea1f14683714a7eaffaa78cded17ff0e2c0c96ffa",
        known(
            Environment::Staging,
            Role::DeviceAttester,
            Some("ark1-staging"),
        ),
    ),
    (
        "15aa1b4f642e0f668ce5d340cca7943c0b58e44cfbd4d0252201f67d22d4473d",
        known(
            Environment::Staging,
            Role::FirmwareUpdate,
            Some("ark1-staging"),
        ),
    ),
    (
        "766b72dde4e83505e2329a4f8ebcd0ec60e4266544051a7bcdcaaff4f2b909f4",
        known(Environment::Staging, Role::EmulatorAttester, None),
    ),
    (
        "2b9295a7ae239c64d9a659d1146251a4211867e79d8d4423ad47dc269eb18f93",
        known(Environment::Staging, Role::CloudAttester, None),
    ),
    (
        "456df8b670cbe2c1c95368f2678ddf66671826542d742cfb5aee2f30e194b2ed",
        known(
            Environment::Develop,
            Role::DeviceAttester,
            Some("ark1-develop"),
        ),
    ),
    (
        "ca54c1934fca875f9f5f39d7306b0c2736b2dbb70c80c098d4d5e3c73a48efd7",
        known(
            Environment::Develop,
            Role::FirmwareUpdate,
            Some("ark1-develop"),
        ),
    ),
    (
        "4ae00e993329f6f46e350b247a8e2b38b915ade524ceca70d6530c859d1f69ef",
        known(Environment::Develop, Role::EmulatorAttester, None),
    ),
    (
        "9dfa577f0938f11f9df9a5eadcdc8e57353702dca6d23291cf5cc71a403d67a8",
        known(Environment::Develop, Role::CloudAttester, None),
    ),
    (
        "684f319c13b255356b369da93654a113349cc5d4f7147c9560f6cdf4432cc5d6",
        known(Environment::Release, Role::SecureBoot, Some("ark1-alpha")),
    ),
    (
        "77c9e0b43b6c53de06ff8016ffabce99620248e2f6ba14bb105fa08d9203549b",
        known(Environment::Release, Role::SecureBoot, Some("ark1-friend")),
    ),
    (
        "2294e18a562d7bda90c3ef0f4c44f3a0f86a3db6ef45a31cad1b2d049cb74610",
        known(Environment::Release, Role::SecureBoot, Some("ark1-founder")),
    ),
    (
        "c7d482a7c9031cb6a09ad3e3d04a6a5f46bcb29d0e53bb2f4c969291445e6b2f",
        known(Environment::Staging, Role::SecureBoot, Some("ark1-staging")),
    ),
    (
        "17b159894026ea3fa905c7da60fa239fbeaf83855b10ceffa37d5564c1d70877",
        known(Environment::Develop, Role::SecureBoot, Some("ark1-develop")),
    ),
];

mod sealed {
    pub trait Fingerprint {
        fn identify(&self) -> Option<super::Root>;
    }
}

/// Fingerprint accepted by [`identify`]. Implemented for [`rsa::Fingerprint`]
/// and [`xdsa::Fingerprint`], preserving their algorithm namespaces.
/// This trait is sealed; external crates cannot implement it.
pub trait Fingerprint: sealed::Fingerprint {}

impl Fingerprint for rsa::Fingerprint {}
impl Fingerprint for xdsa::Fingerprint {}

impl sealed::Fingerprint for rsa::Fingerprint {
    fn identify(&self) -> Option<Root> {
        identify_bytes(self.to_bytes(), true)
    }
}

impl sealed::Fingerprint for xdsa::Fingerprint {
    fn identify(&self) -> Option<Root> {
        identify_bytes(self.to_bytes(), false)
    }
}

/// Identifies an RSA or xDSA root without requiring its public key to be embedded.
/// The caller must authenticate a token separately before trusting its signer.
pub fn identify(fingerprint: &impl Fingerprint) -> Option<Root> {
    fingerprint.identify()
}

fn identify_bytes(bytes: [u8; 32], rsa: bool) -> Option<Root> {
    let encoded = hex::encode(bytes);
    KNOWN
        .iter()
        .find(|(candidate, info)| *candidate == encoded && (info.role == Role::SecureBoot) == rsa)
        .map(|(_, info)| *info)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Environments whose roots this build embeds.
    const EMBEDDED: &[Environment] = &[
        #[cfg(feature = "release")]
        Environment::Release,
        #[cfg(feature = "staging")]
        Environment::Staging,
        #[cfg(feature = "develop")]
        Environment::Develop,
    ];

    /// Environments whose roots this build leaves out.
    const ABSENT: &[Environment] = &[
        #[cfg(not(feature = "release"))]
        Environment::Release,
        #[cfg(not(feature = "staging"))]
        Environment::Staging,
        #[cfg(not(feature = "develop"))]
        Environment::Develop,
    ];

    /// Number of hardware series of an environment.
    fn series_count(environment: Environment) -> usize {
        match environment {
            Environment::Release => 3,
            Environment::Staging => 1,
            Environment::Develop => 1,
        }
    }

    // Tests that every embedded root parses, so a bad key cannot get committed
    // accidentally, that the environments hold the expected number of series and
    // roots, and that the hardware roots are the device roots of the series.
    #[test]
    fn test_embedded_roots() {
        for &environment in EMBEDDED {
            let count = series_count(environment);
            assert_eq!(series(environment).len(), count, "{environment}");
            assert_eq!(hardware(environment).len(), count, "{environment}");
            for (series, root) in series(environment).iter().zip(hardware(environment)) {
                assert_eq!(
                    series.device_root.fingerprint(),
                    root.fingerprint(),
                    "{}",
                    series.name
                );
            }
            assert_eq!(emulator(environment).len(), 1, "{environment}");
            assert!(cloud(environment).is_some(), "{environment}");
        }
    }

    // Tests that an environment left out of the build has no roots at all, so
    // nothing can verify under it.
    #[test]
    fn test_absent_roots() {
        for &environment in ABSENT {
            assert!(series(environment).is_empty(), "{environment}");
            assert!(hardware(environment).is_empty(), "{environment}");
            assert!(emulator(environment).is_empty(), "{environment}");
            assert!(cloud(environment).is_none(), "{environment}");
        }
    }

    // Tests that the fingerprint table names every embedded root correctly,
    // holds one entry per root of the ecosystem and knows nothing about keys
    // outside it.
    #[test]
    fn test_known_roots() {
        for &environment in EMBEDDED {
            for series in series(environment) {
                let expected = |role| Root {
                    env: environment,
                    role,
                    series: Some(series.name),
                };
                assert_eq!(
                    identify(&series.secure_boot.fingerprint()),
                    Some(expected(Role::SecureBoot)),
                    "{}",
                    series.name
                );
                assert_eq!(
                    identify(&series.device_root.fingerprint()),
                    Some(expected(Role::DeviceAttester)),
                    "{}",
                    series.name
                );
                assert_eq!(
                    identify(&series.firmware_update.fingerprint()),
                    Some(expected(Role::FirmwareUpdate)),
                    "{}",
                    series.name
                );
            }
            for root in emulator(environment) {
                assert_eq!(
                    identify(&root.fingerprint()),
                    Some(known(environment, Role::EmulatorAttester, None)),
                    "{environment}"
                );
            }
            assert_eq!(
                identify(&cloud(environment).unwrap().fingerprint()),
                Some(known(environment, Role::CloudAttester, None)),
                "{environment}"
            );
        }
        assert_eq!(KNOWN.len(), 21, "root count mismatch");

        let stranger = xdsa::SecretKey::generate().public_key();
        assert_eq!(
            identify(&stranger.fingerprint()),
            None,
            "stranger identified"
        );
    }

    // Tests that a signer is named when it is a root of the ecosystem, whether
    // or not this build embeds its key, and carried as a fingerprint otherwise.
    #[test]
    fn test_untrusted_signer() {
        let (encoded, expected) = KNOWN[0];
        let mut bytes = [0u8; xdsa::FINGERPRINT_SIZE];
        hex::decode_to_slice(encoded, &mut bytes).unwrap();
        match crate::Error::untrusted_signer(xdsa::Fingerprint::from_bytes(&bytes)) {
            crate::Error::UntrustedSigner {
                root: Some(found), ..
            } => assert_eq!(found, expected),
            other => panic!("known root not named, got {other:?}"),
        }
        let stranger = xdsa::SecretKey::generate().public_key().fingerprint();
        assert!(
            matches!(crate::Error::untrusted_signer(stranger), crate::Error::UntrustedSigner { fingerprint: found, root: None } if found == stranger),
            "stranger named"
        );
    }

    // Tests the wording of a named root, with and without a series.
    #[test]
    fn test_known_display() {
        let root = known(
            Environment::Release,
            Role::DeviceAttester,
            Some("ark1-founder"),
        );
        assert_eq!(
            root.to_string(),
            "release device attester of series ark1-founder"
        );
        let root = known(Environment::Develop, Role::CloudAttester, None);
        assert_eq!(root.to_string(), "develop cloud attester");
    }

    // Fingerprint lookup works without embedded keys and separates algorithms.
    #[test]
    fn test_fingerprint_lookup() {
        let mut fingerprints = std::collections::HashSet::new();
        let mut rsa_count = 0;
        for &(encoded, info) in KNOWN {
            let mut bytes = [0; 32];
            hex::decode_to_slice(encoded, &mut bytes).unwrap();
            let rsa = rsa::Fingerprint::from_bytes(&bytes);
            let xdsa = xdsa::Fingerprint::from_bytes(&bytes);
            if info.role == Role::SecureBoot {
                rsa_count += 1;
                assert_eq!(identify(&rsa), Some(info));
                assert_eq!(identify(&xdsa), None);
            } else {
                assert_eq!(identify(&xdsa), Some(info));
                assert_eq!(identify(&rsa), None);
            }
            assert!(fingerprints.insert(bytes), "duplicate fingerprint");
        }
        assert_eq!(rsa_count, 5);
        assert_eq!(fingerprints.len(), 21);
        assert_eq!(identify(&rsa::Fingerprint::from_bytes(&[0; 32])), None);
    }
}
