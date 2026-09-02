// trust-rs: roots of trust for the Dark Bio ecosystem
// Copyright 2026 Dark Bio AG. All rights reserved.

//! Cloud attestations, the rotating signing and encryption identities of the
//! Dark Bio cloud.

use crate::{CLOUD_ATTESTATION_MAX_VALIDITY, CRYPTO_DOMAIN_CLOUD_ATTESTATION, Error};
use darkbio_crypto::cbor::{Cbor, Decode};
use darkbio_crypto::cwt::claims;
use darkbio_crypto::{cwt, xdsa, xhpke};

/// SignerClaims are the attestation claims of the cloud's currently active
/// signing key, issued by the cloud root. The cloud rotates its keys
/// periodically, each attestation carrying the validity period of its key,
/// capped at CLOUD_ATTESTATION_MAX_VALIDITY.
#[derive(Cbor)]
pub struct SignerClaims {
    #[cbor(embed)]
    pub iss: claims::Issuer, // Operator URL of the cloud (e.g. https://dark.bio)
    #[cbor(embed)]
    pub sub: claims::Subject, // API endpoint URL the key serves (e.g. https://api.dark.bio)
    #[cbor(embed)]
    pub nbf: claims::NotBefore, // Validity start
    #[cbor(embed)]
    pub exp: claims::Expiration, // Validity end
    #[cbor(embed)]
    pub cnf: claims::Confirm<xdsa::PublicKey>, // Cloud xDSA signing public key
}

/// CryptoClaims are the attestation claims of the cloud's currently active
/// encryption key, issued by the cloud root. The cloud rotates its keys
/// periodically, each attestation carrying the validity period of its key,
/// capped at CLOUD_ATTESTATION_MAX_VALIDITY.
#[derive(Cbor)]
pub struct CryptoClaims {
    #[cbor(embed)]
    pub iss: claims::Issuer, // Operator URL of the cloud (e.g. https://dark.bio)
    #[cbor(embed)]
    pub sub: claims::Subject, // API endpoint URL the key serves (e.g. https://api.dark.bio)
    #[cbor(embed)]
    pub nbf: claims::NotBefore, // Validity start
    #[cbor(embed)]
    pub exp: claims::Expiration, // Validity end
    #[cbor(embed)]
    pub cnf: claims::Confirm<xhpke::PublicKey>, // Cloud xHPKE encryption public key
}

/// Validity is the validity period carried by every cloud attestation shape.
trait Validity {
    /// Validity period of the attestation as its start and end timestamps.
    fn validity(&self) -> (u64, u64);
}

impl Validity for SignerClaims {
    fn validity(&self) -> (u64, u64) {
        (self.nbf.nbf, self.exp.exp)
    }
}

impl Validity for CryptoClaims {
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
/// signer is matched to the root before the signature is checked, so a foreign
/// root is reported as unexpected rather than as a bad signature. The length of
/// the validity period is capped independently of `now`, so the cap holds even
/// for verifiers without a trusted clock.
fn verify<T: Decode + Validity>(
    attestation: &[u8],
    root: &xdsa::PublicKey,
    now: Option<u64>,
) -> Result<T, Error> {
    // Peek at the embedded signer and reject if not what we expect
    let signer = cwt::signer(attestation)?;
    if signer != root.fingerprint() {
        return Err(Error::UnexpectedSigner(signer));
    }
    // Verify the signature and unpack the claims
    let claims: T = cwt::verify(attestation, root, CRYPTO_DOMAIN_CLOUD_ATTESTATION, now)?;

    // Enforce the maximum cloud attestation validity
    let (nbf, exp) = claims.validity();
    if nbf >= exp || exp - nbf > CLOUD_ATTESTATION_MAX_VALIDITY.as_secs() {
        return Err(Error::InvalidValidity { nbf, exp });
    }
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
                Err(Error::UnexpectedSigner(_))
            ),
            "signer attestation accepted under a foreign root"
        );
        assert!(
            matches!(
                verify_crypto(&crypto, &other, None),
                Err(Error::UnexpectedSigner(_))
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
                            matches!(result, Err(Error::InvalidValidity { nbf: n, exp: e }) if (n, e) == (nbf, exp)),
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
}
