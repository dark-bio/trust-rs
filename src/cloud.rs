// trust-rs: dark bio ecosystem roots of trust
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! Cloud attestations, the rotating signing and encryption identities of the
//! Dark Bio cloud.
//!
//! The cloud root of an environment attests the cloud's current signing and
//! encryption keys. Each attestation has a validity period of at most
//! [`CLOUD_ATTESTATION_MAX_VALIDITY`]. Verification takes the root the caller
//! trusts and returns the attested claims.
//!
//! Verify a signing-key attestation against a trusted cloud root:
//!
//! ```
//! # use darkbio_crypto::cwt::{self, claims};
//! # use darkbio_crypto::xdsa;
//! use darkbio_trust::cloud;
//! # use darkbio_trust::CRYPTO_DOMAIN_CLOUD_ATTESTATION;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # // Stand-ins for a cloud root and the signing key it attests
//! # let root = xdsa::SecretKey::generate();
//! # let signing = xdsa::SecretKey::generate();
//! #
//! # let claims = cloud::SignerClaims {
//! #     iss: claims::Issuer { iss: "https://dark.bio".into() },
//! #     sub: claims::Subject { sub: "https://api.dark.bio".into() },
//! #     nbf: claims::NotBefore { nbf: 1_700_000_000 },
//! #     exp: claims::Expiration { exp: 1_700_000_000 + 30 * 86_400 },
//! #     cnf: claims::Confirm::new(signing.public_key()),
//! # };
//! # let attestation = cwt::issue(&claims, &root, CRYPTO_DOMAIN_CLOUD_ATTESTATION)?;
//! # let root = root.public_key();
//!
//! let verified = cloud::verify_signer(&attestation, &root, Some(1_700_000_100))?;
//! assert_eq!(verified.sub.sub, "https://api.dark.bio");
//! # assert_eq!(verified.cnf.key().fingerprint(), signing.fingerprint());
//! # Ok(())
//! # }
//! ```

use crate::{
    CLOUD_ATTESTATION_MAX_VALIDITY, CRYPTO_DOMAIN_CLOUD_ATTESTATION, Error, check_validity,
};
use darkbio_crypto::cbor::{Cbor, Decode};
use darkbio_crypto::cwt::claims;
use darkbio_crypto::{cwt, xdsa, xhpke};

/// SignerClaims are the attestation claims of the cloud's currently active
/// signing key, issued by the cloud root. The cloud rotates its keys
/// periodically, each attestation carrying the validity period of its key,
/// capped at CLOUD_ATTESTATION_MAX_VALIDITY.
#[derive(Cbor)]
pub struct SignerClaims {
    /// Operator of the cloud, as a URL such as `https://dark.bio`.
    #[cbor(embed)]
    pub iss: claims::Issuer,
    /// API endpoint the key serves, as a URL such as `https://api.dark.bio`.
    #[cbor(embed)]
    pub sub: claims::Subject,
    /// Start of the key's validity, seconds since the Unix epoch.
    #[cbor(embed)]
    pub nbf: claims::NotBefore,
    /// End of the key's validity, seconds since the Unix epoch, at most
    /// [`CLOUD_ATTESTATION_MAX_VALIDITY`] after the start.
    #[cbor(embed)]
    pub exp: claims::Expiration,
    /// xDSA key the cloud signs with while the attestation is valid.
    #[cbor(embed)]
    pub cnf: claims::Confirm<xdsa::PublicKey>,
}

/// CryptoClaims are the attestation claims of the cloud's currently active
/// encryption key, issued by the cloud root. The cloud rotates its keys
/// periodically, each attestation carrying the validity period of its key,
/// capped at CLOUD_ATTESTATION_MAX_VALIDITY.
#[derive(Cbor)]
pub struct CryptoClaims {
    /// Operator of the cloud, as a URL such as `https://dark.bio`.
    #[cbor(embed)]
    pub iss: claims::Issuer,
    /// API endpoint the key serves, as a URL such as `https://api.dark.bio`.
    #[cbor(embed)]
    pub sub: claims::Subject,
    /// Start of the key's validity, seconds since the Unix epoch.
    #[cbor(embed)]
    pub nbf: claims::NotBefore,
    /// End of the key's validity, seconds since the Unix epoch, at most
    /// [`CLOUD_ATTESTATION_MAX_VALIDITY`] after the start.
    #[cbor(embed)]
    pub exp: claims::Expiration,
    /// xHPKE key the cloud receives encrypted messages with while the
    /// attestation is valid.
    #[cbor(embed)]
    pub cnf: claims::Confirm<xhpke::PublicKey>,
}

/// Validity period carried by either cloud attestation shape.
trait CloudClaims {
    /// Validity period of the attestation as its start and end timestamps.
    fn validity(&self) -> (u64, u64);
}

impl CloudClaims for SignerClaims {
    fn validity(&self) -> (u64, u64) {
        (self.nbf.nbf, self.exp.exp)
    }
}

impl CloudClaims for CryptoClaims {
    fn validity(&self) -> (u64, u64) {
        (self.nbf.nbf, self.exp.exp)
    }
}

/// Verifies a cloud signer attestation against a cloud root, returning its
/// claims. The validity period must not exceed CLOUD_ATTESTATION_MAX_VALIDITY
/// and, when `now` is given, the attestation must also be valid at that time.
pub fn verify_signer(
    attestation: &[u8],
    root: &xdsa::PublicKey,
    now: Option<u64>,
) -> Result<SignerClaims, Error> {
    verify(attestation, root, now)
}

/// Verifies a cloud crypto attestation against a cloud root, returning its
/// claims. The validity period must not exceed CLOUD_ATTESTATION_MAX_VALIDITY
/// and, when `now` is given, the attestation must also be valid at that time.
pub fn verify_crypto(
    attestation: &[u8],
    root: &xdsa::PublicKey,
    now: Option<u64>,
) -> Result<CryptoClaims, Error> {
    verify(attestation, root, now)
}

/// Verifies a cloud attestation of the given shape against a cloud root. The
/// claimed signer is matched to the root before the signature is checked;
/// a mismatch yields an unauthenticated hint.
/// The length of the validity period is capped independently of `now`, so the
/// cap holds even for verifiers without a trusted clock.
fn verify<T: Decode + CloudClaims>(
    attestation: &[u8],
    root: &xdsa::PublicKey,
    now: Option<u64>,
) -> Result<T, Error> {
    // Peek at the embedded signer and reject if not what we expect
    let signer = cwt::signer(attestation)?;
    if signer != root.fingerprint() {
        return Err(Error::untrusted_signer(signer));
    }
    // Verify the signature and unpack the claims
    let claims: T = cwt::verify(attestation, root, CRYPTO_DOMAIN_CLOUD_ATTESTATION, now)?;

    // Enforce the maximum cloud attestation validity
    let (nbf, exp) = claims.validity();
    check_validity(nbf, exp, CLOUD_ATTESTATION_MAX_VALIDITY)?;
    Ok(claims)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Signer attestation claims of a cloud, valid for the given period.
    fn signer_claims(key: xdsa::PublicKey, nbf: u64, exp: u64) -> SignerClaims {
        SignerClaims {
            iss: claims::Issuer {
                iss: "https://dark.bio".into(),
            },
            sub: claims::Subject {
                sub: "https://api.dark.bio".into(),
            },
            nbf: claims::NotBefore { nbf },
            exp: claims::Expiration { exp },
            cnf: claims::Confirm::new(key),
        }
    }

    /// Crypto attestation claims of a cloud, valid for the given period.
    fn crypto_claims(key: xhpke::PublicKey, nbf: u64, exp: u64) -> CryptoClaims {
        CryptoClaims {
            iss: claims::Issuer {
                iss: "https://dark.bio".into(),
            },
            sub: claims::Subject {
                sub: "https://api.dark.bio".into(),
            },
            nbf: claims::NotBefore { nbf },
            exp: claims::Expiration { exp },
            cnf: claims::Confirm::new(key),
        }
    }

    // Tests that the cloud attestations verify under their root, yielding the
    // attested keys and validity periods, and are rejected under any other.
    #[test]
    fn test_cloud_verification() {
        let root = xdsa::SecretKey::generate();
        let signing = xdsa::SecretKey::generate().public_key();
        let encryption = xhpke::SecretKey::generate().public_key();

        let signer = cwt::issue(
            &signer_claims(signing.clone(), 1000, 2000),
            &root,
            CRYPTO_DOMAIN_CLOUD_ATTESTATION,
        )
        .unwrap();
        let crypto = cwt::issue(
            &crypto_claims(encryption.clone(), 1000, 2000),
            &root,
            CRYPTO_DOMAIN_CLOUD_ATTESTATION,
        )
        .unwrap();

        let claims = verify_signer(&signer, &root.public_key(), Some(1500)).unwrap();
        assert_eq!(
            claims.cnf.key().fingerprint(),
            signing.fingerprint(),
            "signing key mismatch"
        );
        assert_eq!(
            (claims.nbf.nbf, claims.exp.exp),
            (1000, 2000),
            "validity mismatch"
        );

        let claims = verify_crypto(&crypto, &root.public_key(), Some(1500)).unwrap();
        assert_eq!(
            claims.cnf.key().fingerprint(),
            encryption.fingerprint(),
            "encryption key mismatch"
        );
        assert_eq!(
            (claims.nbf.nbf, claims.exp.exp),
            (1000, 2000),
            "validity mismatch"
        );

        let other = xdsa::SecretKey::generate().public_key();
        assert!(
            matches!(
                verify_signer(&signer, &other, None),
                Err(Error::UntrustedSigner { .. })
            ),
            "signer attestation accepted under a foreign root"
        );
        assert!(
            matches!(
                verify_crypto(&crypto, &other, None),
                Err(Error::UntrustedSigner { .. })
            ),
            "crypto attestation accepted under a foreign root"
        );
    }

    // Tests that the two cloud attestations are not interchangeable, a signer
    // attestation never yielding an encryption key or vice versa.
    #[test]
    fn test_cloud_shape_mismatch() {
        let root = xdsa::SecretKey::generate();
        let signer = cwt::issue(
            &signer_claims(xdsa::SecretKey::generate().public_key(), 1000, 2000),
            &root,
            CRYPTO_DOMAIN_CLOUD_ATTESTATION,
        )
        .unwrap();
        let crypto = cwt::issue(
            &crypto_claims(xhpke::SecretKey::generate().public_key(), 1000, 2000),
            &root,
            CRYPTO_DOMAIN_CLOUD_ATTESTATION,
        )
        .unwrap();

        assert!(
            matches!(
                verify_crypto(&signer, &root.public_key(), None),
                Err(Error::Cwt(cwt::Error::Cbor(_)))
            ),
            "signer attestation accepted as crypto"
        );
        assert!(
            matches!(
                verify_signer(&crypto, &root.public_key(), None),
                Err(Error::Cwt(cwt::Error::Cbor(_)))
            ),
            "crypto attestation accepted as signer"
        );
    }

    // Tests that the validity period is enforced when a time is given.
    #[test]
    fn test_cloud_validity_period() {
        let root = xdsa::SecretKey::generate();
        let signer = cwt::issue(
            &signer_claims(xdsa::SecretKey::generate().public_key(), 1000, 2000),
            &root,
            CRYPTO_DOMAIN_CLOUD_ATTESTATION,
        )
        .unwrap();

        assert!(
            matches!(
                verify_signer(&signer, &root.public_key(), Some(999)),
                Err(Error::Cwt(cwt::Error::NotYetValid { .. }))
            ),
            "attestation accepted before validity"
        );
        assert!(
            matches!(
                verify_signer(&signer, &root.public_key(), Some(2000)),
                Err(Error::Cwt(cwt::Error::AlreadyExpired { .. }))
            ),
            "attestation accepted after expiry"
        );
        verify_signer(&signer, &root.public_key(), None).expect("timeless verification failed");
    }

    // Tests that the length of the validity period is capped whether or not a
    // time is given, an empty or inverted period being rejected too, with the
    // cap itself being the longest period accepted. The cap is checked after
    // the time, so a period the time already fails is reported as such.
    #[test]
    fn test_cloud_validity_cap() {
        let root = xdsa::SecretKey::generate();
        let max = CLOUD_ATTESTATION_MAX_VALIDITY.as_secs();

        for (nbf, exp, accept) in [
            (1000, 1000 + max, true),
            (1000, 1000 + max + 1, false),
            (1000, 1000, false),
            (2000, 1000, false),
        ] {
            let signer = cwt::issue(
                &signer_claims(xdsa::SecretKey::generate().public_key(), nbf, exp),
                &root,
                CRYPTO_DOMAIN_CLOUD_ATTESTATION,
            )
            .unwrap();
            let crypto = cwt::issue(
                &crypto_claims(xhpke::SecretKey::generate().public_key(), nbf, exp),
                &root,
                CRYPTO_DOMAIN_CLOUD_ATTESTATION,
            )
            .unwrap();

            for now in [None, Some(1500)] {
                let timely = now.is_none_or(|now| nbf <= now && now < exp);
                let results = [
                    verify_signer(&signer, &root.public_key(), now).map(|_| ()),
                    verify_crypto(&crypto, &root.public_key(), now).map(|_| ()),
                ];
                for result in results {
                    match (accept, timely) {
                        (true, _) => result.expect("valid attestation rejected"),
                        (false, true) => assert!(
                            matches!(result, Err(Error::InvalidValidity { max }) if max == CLOUD_ATTESTATION_MAX_VALIDITY),
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
    }

    // Verification returns both keys and the claims callers use to identify
    // the operator and endpoint, with clock checks applied when requested.
    #[test]
    fn test_cloud_claims() {
        let root = xdsa::SecretKey::generate();
        let root_key = root.public_key();
        let signing = xdsa::SecretKey::generate().public_key();
        let encryption = xhpke::SecretKey::generate().public_key();
        let signer = cwt::issue(
            &signer_claims(signing.clone(), 1000, 2000),
            &root,
            CRYPTO_DOMAIN_CLOUD_ATTESTATION,
        )
        .unwrap();
        let crypto = cwt::issue(
            &crypto_claims(encryption.clone(), 1000, 2000),
            &root,
            CRYPTO_DOMAIN_CLOUD_ATTESTATION,
        )
        .unwrap();
        let found = verify_signer(&signer, &root_key, None).unwrap();
        assert_eq!(found.cnf.key().fingerprint(), signing.fingerprint());
        assert_eq!(found.iss.iss, "https://dark.bio");
        assert_eq!(found.sub.sub, "https://api.dark.bio");
        let found = verify_crypto(&crypto, &root_key, None).unwrap();
        assert_eq!(found.cnf.key().fingerprint(), encryption.fingerprint());
        assert_eq!(found.iss.iss, "https://dark.bio");
        assert_eq!(found.sub.sub, "https://api.dark.bio");
        for now in [1000, 1999] {
            verify_signer(&signer, &root_key, Some(now)).unwrap();
            verify_crypto(&crypto, &root_key, Some(now)).unwrap();
        }
        for now in [999, 2000] {
            let results = [
                verify_signer(&signer, &root_key, Some(now)).map(|_| ()),
                verify_crypto(&crypto, &root_key, Some(now)).map(|_| ()),
            ];
            for result in results {
                match now {
                    999 => assert!(matches!(
                        result,
                        Err(Error::Cwt(cwt::Error::NotYetValid { .. }))
                    )),
                    2000 => assert!(matches!(
                        result,
                        Err(Error::Cwt(cwt::Error::AlreadyExpired { .. }))
                    )),
                    _ => unreachable!(),
                }
            }
        }
    }

    #[test]
    fn test_cloud_validity_at_timestamp_limit() {
        let root = xdsa::SecretKey::generate();
        let signing = xdsa::SecretKey::generate().public_key();
        let max = CLOUD_ATTESTATION_MAX_VALIDITY.as_secs();
        let root_key = root.public_key();
        let token = cwt::issue(
            &signer_claims(signing, u64::MAX - max, u64::MAX),
            &root,
            CRYPTO_DOMAIN_CLOUD_ATTESTATION,
        )
        .unwrap();
        super::verify_signer(&token, &root_key, Some(u64::MAX - 1)).unwrap();
        assert!(matches!(
            super::verify_signer(&token, &root_key, Some(u64::MAX)),
            Err(Error::Cwt(cwt::Error::AlreadyExpired { .. }))
        ));
    }
}
