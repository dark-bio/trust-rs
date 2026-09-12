// trust-rs: dark bio ecosystem roots of trust
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! Device attestations, the identities of Ark enclaves and of their emulated
//! counterparts.
//!
//! An attestation is a CWT signed by a root, binding the identity key of a
//! device to its serial and hardware details. Hardware devices are attested
//! once at manufacturing and never expire, emulated devices are attested
//! online with an expiry. Verification takes the roots the caller trusts, and
//! the set the signer belongs to decides which shape the claims must have.
//!
//! Verify an attestation against a trusted hardware root:
//!
//! ```
//! # use darkbio_crypto::cwt::{self, claims, claims::eat};
//! # use darkbio_crypto::xdsa;
//! use darkbio_trust::{Realm, device};
//! # use darkbio_trust::CRYPTO_DOMAIN_DEVICE_ATTESTATION;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # // Stand-ins for a manufacturing root and a device identity
//! # let root = xdsa::SecretKey::generate();
//! # let identity = xdsa::SecretKey::generate();
//! #
//! # let claims = device::HardwareClaims {
//! #     sub: claims::Subject { sub: "ark-0001".into() },
//! #     cnf: claims::Confirm::new(identity.public_key()),
//! #     nbf: claims::NotBefore { nbf: 1_700_000_000 },
//! #     iat: claims::IssuedAt { iat: 1_700_000_000 },
//! #     oem: eat::Oemid::new_pen(65145),
//! #     hwm: eat::HwModel { hw_model: b"Ark I".to_vec() },
//! #     hwv: eat::HwVersion::new("1.0.0".into()),
//! # };
//! # let attestation = cwt::issue(&claims, &root, CRYPTO_DOMAIN_DEVICE_ATTESTATION)?;
//! # let root = root.public_key();
//!
//! let device = device::verify(&attestation, &[root], &[], Some(1_700_000_100))?;
//! assert_eq!(device.realm, Realm::Hardware);
//! assert_eq!(device.serial, "ark-0001");
//! # assert_eq!(device.identity.fingerprint(), identity.fingerprint());
//! # Ok(())
//! # }
//! ```

use crate::{
    CRYPTO_DOMAIN_DEVICE_ATTESTATION, EMULATOR_ATTESTATION_MAX_VALIDITY, Error, Realm,
    check_validity,
};
use darkbio_crypto::cbor::Cbor;
use darkbio_crypto::cwt::claims::{self, eat};
use darkbio_crypto::{cwt, xdsa};

/// HardwareClaims are the attestation claims of a hardware Ark, issued once at
/// manufacturing and signed by a hardware root. Hardware attestations carry no
/// expiration, the identity being bound to the hardware for its lifetime.
#[derive(Cbor)]
pub struct HardwareClaims {
    /// Serial number of the device.
    #[cbor(embed)]
    pub sub: claims::Subject,
    /// xDSA identity key of the device, which the transport must prove the
    /// peer holds.
    #[cbor(embed)]
    pub cnf: claims::Confirm<xdsa::PublicKey>,
    /// Start of validity, seconds since the Unix epoch.
    #[cbor(embed)]
    pub nbf: claims::NotBefore,
    /// Time of issuance, seconds since the Unix epoch.
    #[cbor(embed)]
    pub iat: claims::IssuedAt,
    /// Manufacturer of the device.
    #[cbor(embed)]
    pub oem: eat::Oemid,
    /// Hardware model of the device.
    #[cbor(embed)]
    pub hwm: eat::HwModel,
    /// Hardware revision of the device.
    #[cbor(embed)]
    pub hwv: eat::HwVersion,
}

/// EmulatorClaims are the attestation claims of an emulated Ark, issued online
/// by the cloud sandbox and signed by an emulator root. Emulator attestations
/// always carry an expiration so emulated devices age out, their validity
/// capped at EMULATOR_ATTESTATION_MAX_VALIDITY.
#[derive(Cbor)]
pub struct EmulatorClaims {
    /// Serial number of the emulated device.
    #[cbor(embed)]
    pub sub: claims::Subject,
    /// xDSA identity key of the emulated device, which the transport must
    /// prove the peer holds.
    #[cbor(embed)]
    pub cnf: claims::Confirm<xdsa::PublicKey>,
    /// Start of validity, seconds since the Unix epoch.
    #[cbor(embed)]
    pub nbf: claims::NotBefore,
    /// End of validity, seconds since the Unix epoch, at most
    /// [`EMULATOR_ATTESTATION_MAX_VALIDITY`] after the start.
    #[cbor(embed)]
    pub exp: claims::Expiration,
    /// Time of issuance, seconds since the Unix epoch.
    #[cbor(embed)]
    pub iat: claims::IssuedAt,
    /// Manufacturer of the emulated device.
    #[cbor(embed)]
    pub oem: eat::Oemid,
    /// Hardware model of the emulated device.
    #[cbor(embed)]
    pub hwm: eat::HwModel,
    /// Hardware revision of the emulated device.
    #[cbor(embed)]
    pub hwv: eat::HwVersion,
}

/// Identity claims authenticated by a selected root. A peer must separately
/// prove possession of `identity`, typically through the wire handshake.
#[derive(Clone, Debug)]
pub struct Device {
    /// Realm determined by the root set containing the signer.
    pub realm: Realm,
    /// Attested key to use for the peer's proof of possession.
    pub identity: xdsa::PublicKey,
    /// Device serial number from the subject claim.
    pub serial: String,
    /// Manufacturer identifier qualifying the hardware model.
    pub oem: eat::Oemid,
    /// Hardware model identifier in the manufacturer's namespace.
    pub model: Vec<u8>,
    /// Hardware revision identifier.
    pub version: String,
    /// Time of issuance, seconds since the Unix epoch.
    pub issued: u64,
    /// Time of expiry, seconds since the Unix epoch, absent for hardware
    /// devices.
    pub expiry: Option<u64>,
}

/// Verifies a device attestation against the supplied hardware and emulator
/// roots. The set containing its signer determines the accepted claim shape.
/// Hardware attestations have no expiration; emulator lifetimes are capped at
/// [`EMULATOR_ATTESTATION_MAX_VALIDITY`], even without a trusted clock.
///
/// When `now` is given, the attestation must also be valid at that Unix time.
/// Callers supplying their own keys must place them in the correct, disjoint
/// root sets.
/// A signer outside both sets yields an unauthenticated [`Error::UntrustedSigner`] hint.
pub fn verify(
    attestation: &[u8],
    hardware: &[xdsa::PublicKey],
    emulator: &[xdsa::PublicKey],
    now: Option<u64>,
) -> Result<Device, Error> {
    // Find the signer among the permitted roots of trust
    let signer = cwt::signer(attestation)?;

    // Verify the attestation and retrieve the device claims
    if let Some(root) = hardware.iter().find(|root| root.fingerprint() == signer) {
        // Hardware devices must not have an expiration claim
        let claims: HardwareClaims =
            cwt::verify(attestation, root, CRYPTO_DOMAIN_DEVICE_ATTESTATION, now)?;

        return Ok(Device {
            realm: Realm::Hardware,
            identity: claims.cnf.key().clone(),
            serial: claims.sub.sub,
            oem: claims.oem,
            model: claims.hwm.hw_model,
            version: claims.hwv.version().to_string(),
            issued: claims.iat.iat,
            expiry: None,
        });
    }
    if let Some(root) = emulator.iter().find(|root| root.fingerprint() == signer) {
        // Emulators must have an expiration claim, bounded by the maximum validity
        let claims: EmulatorClaims =
            cwt::verify(attestation, root, CRYPTO_DOMAIN_DEVICE_ATTESTATION, now)?;

        check_validity(
            claims.nbf.nbf,
            claims.exp.exp,
            EMULATOR_ATTESTATION_MAX_VALIDITY,
        )?;
        return Ok(Device {
            realm: Realm::Emulator,
            identity: claims.cnf.key().clone(),
            serial: claims.sub.sub,
            oem: claims.oem,
            model: claims.hwm.hw_model,
            version: claims.hwv.version().to_string(),
            issued: claims.iat.iat,
            expiry: Some(claims.exp.exp),
        });
    }
    Err(Error::untrusted_signer(signer))
}

/// Verifies a token's signature under its embedded identity key. Only that key
/// is returned; the self-asserted identity claims confer no provisioning trust.
///
/// This does not establish whether a device has ever been onboarded or whether
/// the current presenter holds the private key. A copied token also verifies;
/// a live handshake or challenge must establish possession separately. Validity
/// timestamps are ignored, since self-asserted lifetimes confer no authority.
pub fn verify_self_signed(attestation: &[u8]) -> Result<xdsa::PublicKey, Error> {
    // Figure out the realm based on attestation shape
    let (identity, hardware) = match cwt::peek::<HardwareClaims>(attestation) {
        Ok(claims) => (claims.cnf.key().clone(), true),
        Err(_) => {
            let claims: EmulatorClaims = cwt::peek(attestation)?;
            (claims.cnf.key().clone(), false)
        }
    };
    // Ensure it's truly a self-signed attestation
    let signer = cwt::signer(attestation)?;
    if identity.fingerprint() != signer {
        return Err(Error::NotSelfSigned);
    }
    // Verify the attestation and retrieve the device claims
    match hardware {
        true => {
            cwt::verify::<HardwareClaims>(
                attestation,
                &identity,
                CRYPTO_DOMAIN_DEVICE_ATTESTATION,
                None,
            )?;
        }
        false => {
            cwt::verify::<EmulatorClaims>(
                attestation,
                &identity,
                CRYPTO_DOMAIN_DEVICE_ATTESTATION,
                None,
            )?;
        }
    }
    Ok(identity)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Attestation claims of a hardware device, valid from time 1000 onwards.
    fn hardware_claims(identity: xdsa::PublicKey) -> HardwareClaims {
        HardwareClaims {
            sub: claims::Subject {
                sub: "ark-1234".into(),
            },
            cnf: claims::Confirm::new(identity),
            nbf: claims::NotBefore { nbf: 1000 },
            iat: claims::IssuedAt { iat: 1000 },
            oem: eat::Oemid::new_pen(65145),
            hwm: eat::HwModel {
                hw_model: b"Ark I".to_vec(),
            },
            hwv: eat::HwVersion::new("Ark I - 1.0.0".into()),
        }
    }

    /// Attestation claims of an emulated device, valid for the given period.
    fn emulator_claims(identity: xdsa::PublicKey, nbf: u64, exp: u64) -> EmulatorClaims {
        EmulatorClaims {
            sub: claims::Subject {
                sub: "emu-1234".into(),
            },
            cnf: claims::Confirm::new(identity),
            nbf: claims::NotBefore { nbf },
            exp: claims::Expiration { exp },
            iat: claims::IssuedAt { iat: 1000 },
            oem: eat::Oemid::new_pen(65145),
            hwm: eat::HwModel {
                hw_model: b"Ark I".to_vec(),
            },
            hwv: eat::HwVersion::new("Ark I - 1.0.0".into()),
        }
    }

    // Tests that a hardware attestation verifies under its hardware root, yielding
    // the attested identity that never expires.
    #[test]
    fn test_hardware_verification() {
        let root = xdsa::SecretKey::generate();
        let identity = xdsa::SecretKey::generate().public_key();
        let attestation = cwt::issue(
            &hardware_claims(identity.clone()),
            &root,
            CRYPTO_DOMAIN_DEVICE_ATTESTATION,
        )
        .unwrap();

        let device = verify(&attestation, &[root.public_key()], &[], Some(1500)).unwrap();
        assert_eq!(device.realm, Realm::Hardware, "realm mismatch");
        assert_eq!(
            device.identity.fingerprint(),
            identity.fingerprint(),
            "identity mismatch"
        );
        assert_eq!(device.serial, "ark-1234", "serial mismatch");
        assert_eq!(device.model, b"Ark I", "model mismatch");
        assert_eq!(device.version, "Ark I - 1.0.0", "version mismatch");
        assert_eq!(device.issued, 1000, "issuance mismatch");
        assert_eq!(device.expiry, None, "hardware attestation must not expire");
    }

    // Tests that an emulator attestation verifies under its emulator root,
    // yielding the attested identity along with its expiry.
    #[test]
    fn test_emulator_verification() {
        let root = xdsa::SecretKey::generate();
        let identity = xdsa::SecretKey::generate().public_key();
        let attestation = cwt::issue(
            &emulator_claims(identity.clone(), 1000, 2000),
            &root,
            CRYPTO_DOMAIN_DEVICE_ATTESTATION,
        )
        .unwrap();

        let device = verify(&attestation, &[], &[root.public_key()], Some(1500)).unwrap();
        assert_eq!(device.realm, Realm::Emulator, "realm mismatch");
        assert_eq!(
            device.identity.fingerprint(),
            identity.fingerprint(),
            "identity mismatch"
        );
        assert_eq!(device.serial, "emu-1234", "serial mismatch");
        assert_eq!(device.expiry, Some(2000), "expiry mismatch");
    }

    // Tests that the set a root belongs to dictates the shape of the attestation,
    // an expiring attestation being rejected under a hardware root and a
    // permanent one under an emulator root, even if the signatures are valid.
    #[test]
    fn test_shape_mismatch() {
        let root = xdsa::SecretKey::generate();
        let identity = xdsa::SecretKey::generate().public_key();

        let expiring = cwt::issue(
            &emulator_claims(identity.clone(), 1000, 2000),
            &root,
            CRYPTO_DOMAIN_DEVICE_ATTESTATION,
        )
        .unwrap();
        assert!(
            matches!(
                verify(&expiring, &[root.public_key()], &[], None),
                Err(Error::Cwt(cwt::Error::Cbor(_)))
            ),
            "hardware root accepted an expiring attestation"
        );

        let permanent = cwt::issue(
            &hardware_claims(identity),
            &root,
            CRYPTO_DOMAIN_DEVICE_ATTESTATION,
        )
        .unwrap();
        assert!(
            matches!(
                verify(&permanent, &[], &[root.public_key()], None),
                Err(Error::Cwt(cwt::Error::Cbor(_)))
            ),
            "emulator root accepted a permanent attestation"
        );
    }

    // Tests that the signer of an attestation is matched against both root sets,
    // the containing one deciding the realm, and that an attestation from an
    // unknown signer is rejected, naming the signer.
    #[test]
    fn test_root_selection() {
        let hardware = xdsa::SecretKey::generate().public_key();
        let emulator = xdsa::SecretKey::generate();
        let identity = xdsa::SecretKey::generate().public_key();
        let attestation = cwt::issue(
            &emulator_claims(identity, 1000, 2000),
            &emulator,
            CRYPTO_DOMAIN_DEVICE_ATTESTATION,
        )
        .unwrap();

        let device = verify(
            &attestation,
            std::slice::from_ref(&hardware),
            &[emulator.public_key()],
            None,
        )
        .unwrap();
        assert_eq!(device.realm, Realm::Emulator, "realm mismatch");

        match verify(&attestation, &[hardware], &[], None) {
            Err(Error::UntrustedSigner {
                fingerprint: signer,
                root: None,
            }) => {
                assert_eq!(
                    signer,
                    emulator.public_key().fingerprint(),
                    "signer mismatch"
                );
            }
            other => panic!("signer not rejected as unexpected, got {other:?}"),
        }
    }

    // Tests that the validity period is enforced when a time is given, hardware
    // attestations staying valid indefinitely and emulator ones expiring.
    #[test]
    fn test_validity_period() {
        let root = xdsa::SecretKey::generate();
        let identity = xdsa::SecretKey::generate().public_key();
        let attestation = cwt::issue(
            &hardware_claims(identity.clone()),
            &root,
            CRYPTO_DOMAIN_DEVICE_ATTESTATION,
        )
        .unwrap();
        assert!(
            matches!(
                verify(&attestation, &[root.public_key()], &[], Some(999)),
                Err(Error::Cwt(cwt::Error::NotYetValid { .. }))
            ),
            "attestation accepted before validity"
        );
        verify(&attestation, &[root.public_key()], &[], Some(u64::MAX))
            .expect("hardware attestation expired");

        let attestation = cwt::issue(
            &emulator_claims(identity, 1000, 2000),
            &root,
            CRYPTO_DOMAIN_DEVICE_ATTESTATION,
        )
        .unwrap();
        assert!(
            matches!(
                verify(&attestation, &[], &[root.public_key()], Some(2000)),
                Err(Error::Cwt(cwt::Error::AlreadyExpired { .. }))
            ),
            "attestation accepted after expiry"
        );
        verify(&attestation, &[], &[root.public_key()], None)
            .expect("timeless verification failed");
    }

    // Tests that an attestation self-signed by its embedded identity is accepted
    // in either shape, yielding the identity, and that it is never mistaken for
    // a root attested device.
    #[test]
    fn test_self_signed() {
        let secret = xdsa::SecretKey::generate();
        let identity = secret.public_key();
        let root = xdsa::SecretKey::generate().public_key();

        for attestation in [
            cwt::issue(
                &hardware_claims(identity.clone()),
                &secret,
                CRYPTO_DOMAIN_DEVICE_ATTESTATION,
            )
            .unwrap(),
            cwt::issue(
                &emulator_claims(identity.clone(), 1000, 2000),
                &secret,
                CRYPTO_DOMAIN_DEVICE_ATTESTATION,
            )
            .unwrap(),
        ] {
            assert_eq!(
                verify_self_signed(&attestation).unwrap().fingerprint(),
                identity.fingerprint(),
                "identity mismatch"
            );
            assert!(
                matches!(
                    verify(&attestation, std::slice::from_ref(&root), &[], None),
                    Err(Error::UntrustedSigner { .. })
                ),
                "self-signed attestation accepted as attested"
            );
        }
    }

    // Tests that an attestation signed by anyone other than its embedded
    // identity is not self-signed, whether by a root or by a third party.
    #[test]
    fn test_self_signed_rejects_foreign_signer() {
        let identity = xdsa::SecretKey::generate().public_key();
        let attestation = cwt::issue(
            &hardware_claims(identity),
            &xdsa::SecretKey::generate(),
            CRYPTO_DOMAIN_DEVICE_ATTESTATION,
        )
        .unwrap();
        assert!(
            matches!(verify_self_signed(&attestation), Err(Error::NotSelfSigned)),
            "foreign signed attestation accepted as self-signed"
        );
        assert!(
            matches!(verify_self_signed(b"junk"), Err(Error::Cwt(_))),
            "junk accepted as self-signed"
        );
    }

    // Tests that the length of an emulator attestation's validity period is
    // capped whether or not a time is given, an empty or inverted period being
    // rejected too, with the cap itself being the longest period accepted. The
    // cap is checked after the time, so a period the time already fails is
    // reported as such.
    #[test]
    fn test_emulator_validity_cap() {
        let root = xdsa::SecretKey::generate();
        let identity = xdsa::SecretKey::generate().public_key();
        let max = EMULATOR_ATTESTATION_MAX_VALIDITY.as_secs();

        for (nbf, exp, accept) in [
            (1000, 1000 + max, true),
            (1000, 1000 + max + 1, false),
            (1000, 1000, false),
            (2000, 1000, false),
        ] {
            let attestation = cwt::issue(
                &emulator_claims(identity.clone(), nbf, exp),
                &root,
                CRYPTO_DOMAIN_DEVICE_ATTESTATION,
            )
            .unwrap();

            for now in [None, Some(1500)] {
                let timely = now.is_none_or(|now| nbf <= now && now < exp);
                let result = verify(&attestation, &[], &[root.public_key()], now);
                match (accept, timely) {
                    (true, _) => {
                        result.expect("valid attestation rejected");
                    }
                    (false, true) => assert!(
                        matches!(result, Err(Error::InvalidValidity { max }) if max == EMULATOR_ATTESTATION_MAX_VALIDITY),
                        "attestation accepted with validity {nbf} to {exp} at {now:?}"
                    ),
                    (false, false) => assert!(
                        matches!(result, Err(Error::Cwt(_))),
                        "untimely attestation not rejected by the time check at {now:?}"
                    ),
                }
            }
        }
    }

    // Verification returns the device fields and applies the clock through cwt
    // when requested, while always authenticating the signature.
    #[test]
    fn test_hardware_fields() {
        let root = xdsa::SecretKey::generate();
        let roots = [root.public_key()];
        let identity = xdsa::SecretKey::generate().public_key();
        let mut claims = hardware_claims(identity.clone());
        claims.nbf.nbf = 1400;
        let mut token = cwt::issue(&claims, &root, CRYPTO_DOMAIN_DEVICE_ATTESTATION).unwrap();
        let device = verify(&token, &roots, &[], None).unwrap();
        assert_eq!(device.identity.fingerprint(), identity.fingerprint());
        assert_eq!(device.issued, 1000);
        assert_eq!(device.oem.pen(), Some(65145));
        assert!(matches!(
            verify(&token, &roots, &[], Some(1399)),
            Err(Error::Cwt(cwt::Error::NotYetValid {
                nbf: 1400,
                now: 1399
            }))
        ));
        verify(&token, &roots, &[], Some(1400)).unwrap();
        *token.last_mut().unwrap() ^= 1;
        assert!(matches!(
            verify(&token, &roots, &[], None),
            Err(Error::Cwt(_))
        ));
    }

    #[test]
    fn test_emulator_fields() {
        let root = xdsa::SecretKey::generate();
        let roots = [root.public_key()];
        let identity = xdsa::SecretKey::generate().public_key();
        let max = EMULATOR_ATTESTATION_MAX_VALIDITY.as_secs();
        let token = cwt::issue(
            &emulator_claims(identity, 1000, 1000 + max),
            &root,
            CRYPTO_DOMAIN_DEVICE_ATTESTATION,
        )
        .unwrap();
        let device = verify(&token, &[], &roots, None).unwrap();
        assert_eq!(device.realm, Realm::Emulator);
        assert_eq!(device.expiry, Some(1000 + max));
        verify(&token, &[], &roots, Some(1000)).unwrap();
        verify(&token, &[], &roots, Some(1000 + max - 1)).unwrap();
        assert!(matches!(
            verify(&token, &[], &roots, Some(1000 + max)),
            Err(Error::Cwt(cwt::Error::AlreadyExpired { .. }))
        ));
    }

    // A forged header can name a known root. Its metadata is only a hint and
    // never authenticates the token, even when the claimed key is embedded.
    #[test]
    fn test_unverified_signer_hint() {
        let attacker = xdsa::SecretKey::generate();
        let mut token = cwt::issue(
            &hardware_claims(attacker.public_key()),
            &attacker,
            CRYPTO_DOMAIN_DEVICE_ATTESTATION,
        )
        .unwrap();
        let mut bytes = [0; 32];
        hex::decode_to_slice(
            "fe56b1de20bde6010569c90e611197356ad521c5e3d27f7afbbb65b5600bbb12",
            &mut bytes,
        )
        .unwrap();
        let claimed = xdsa::Fingerprint::from_bytes(&bytes);
        let claimed_root = crate::roots::identify(&claimed).unwrap();
        let fingerprint = attacker.fingerprint().to_bytes();
        let offsets: Vec<_> = token
            .windows(32)
            .enumerate()
            .filter(|(_, bytes)| *bytes == fingerprint)
            .map(|(i, _)| i)
            .collect();
        assert_eq!(offsets.len(), 1);
        token[offsets[0]..offsets[0] + 32].copy_from_slice(&claimed.to_bytes());
        let err = verify(&token, &[], &[], None).unwrap_err();
        assert!(
            matches!(&err, Error::UntrustedSigner { fingerprint, root: Some(info) } if *fingerprint == claimed && *info == claimed_root)
        );
        assert!(err.to_string().starts_with("attestation signed by the "));
        let roots = crate::roots::hardware(claimed_root.env);
        if !roots.is_empty() {
            assert!(matches!(
                verify(&token, roots, &[], None),
                Err(Error::Cwt(_))
            ));
        }
    }
}
