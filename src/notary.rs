// trust-rs: dark bio ecosystem roots of trust
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! Notary attestations, the keys that notarize Ark apps.
//!
//! The notary root of an environment attests its notary keys. An attestation
//! names the key and the time it starts notarizing, and never expires.
//! Verification takes the root the caller trusts and returns the attested claims.
//!
//! Verify a notary attestation against a trusted notary root:
//!
//! ```
//! # use darkbio_crypto::cwt::{self, claims};
//! # use darkbio_crypto::xdsa;
//! use darkbio_trust::notary;
//! # use darkbio_trust::CRYPTO_DOMAIN_NOTARY_ATTESTATION;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # // Stand-ins for a notary root and the notary key it attests
//! # let root = xdsa::SecretKey::generate();
//! # let notarizing = xdsa::SecretKey::generate();
//! #
//! # let claims = notary::NotaryClaims {
//! #     nbf: claims::NotBefore { nbf: 1_700_000_000 },
//! #     cnf: claims::Confirm::new(notarizing.public_key()),
//! # };
//! # let attestation = cwt::issue(&claims, &root, CRYPTO_DOMAIN_NOTARY_ATTESTATION)?;
//! # let root = root.public_key();
//!
//! let verified = notary::verify(&attestation, &root, Some(1_700_000_100))?;
//! assert_eq!(verified.nbf.nbf, 1_700_000_000);
//! # assert_eq!(verified.cnf.key().fingerprint(), notarizing.fingerprint());
//! # Ok(())
//! # }
//! ```

use crate::{CRYPTO_DOMAIN_NOTARY_ATTESTATION, Error};
use darkbio_crypto::cbor::Cbor;
use darkbio_crypto::cwt::claims;
use darkbio_crypto::{cwt, xdsa};

/// NotaryClaims are the attestation claims of a notary key, issued by the
/// notary root. They carry no expiry.
#[derive(Cbor)]
pub struct NotaryClaims {
    /// Time from which the key notarizes apps, seconds since the Unix epoch.
    #[cbor(embed)]
    pub nbf: claims::NotBefore,
    /// xDSA key the notary signs app notarizations with.
    #[cbor(embed)]
    pub cnf: claims::Confirm<xdsa::PublicKey>,
}

/// Verifies a notary attestation against a notary root, returning its claims.
/// When `now` is given, the attestation must have started by then. It never
/// expires.
pub fn verify(
    attestation: &[u8],
    root: &xdsa::PublicKey,
    now: Option<u64>,
) -> Result<NotaryClaims, Error> {
    // Peek at the embedded signer and reject if not what we expect
    let signer = cwt::signer(attestation)?;
    if signer != root.fingerprint() {
        return Err(Error::untrusted_signer(signer));
    }
    // Verify the signature and unpack the claims
    Ok(cwt::verify(
        attestation,
        root,
        CRYPTO_DOMAIN_NOTARY_ATTESTATION,
        now,
    )?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CRYPTO_DOMAIN_CLOUD_ATTESTATION;

    /// Builds notary claims for a key and its start time.
    fn notary_claims(key: xdsa::PublicKey, nbf: u64) -> NotaryClaims {
        NotaryClaims {
            nbf: claims::NotBefore { nbf },
            cnf: claims::Confirm::new(key),
        }
    }

    /// Tests that only the trusted root authenticates the notary key and start time.
    #[test]
    fn test_notary_verification() {
        // Issue a notary attestation under the literal domain, pinning its value
        let root = xdsa::SecretKey::generate();
        let key = xdsa::SecretKey::generate().public_key();
        let token = cwt::issue(
            &notary_claims(key.clone(), 1000),
            &root,
            b"notary-attestation-v1",
        )
        .unwrap();

        // Check the attested claims from the start time onward and without a clock
        for now in [Some(1000), Some(u64::MAX), None] {
            let claims = verify(&token, &root.public_key(), now).unwrap();
            assert_eq!(claims.nbf.nbf, 1000, "{now:?}");
            assert_eq!(claims.cnf.key().fingerprint(), key.fingerprint(), "{now:?}");
        }

        // An unrelated root yields the fingerprint from the token
        let other = xdsa::SecretKey::generate().public_key();
        assert!(matches!(
            verify(&token, &other, None),
            Err(Error::UntrustedSigner { fingerprint, root: None }) if fingerprint == root.fingerprint()
        ));
    }

    /// Tests that a notary attestation is rejected before its start time.
    #[test]
    fn test_notary_not_yet_valid() {
        let root = xdsa::SecretKey::generate();
        let claims = notary_claims(xdsa::SecretKey::generate().public_key(), 1000);
        let token = cwt::issue(&claims, &root, CRYPTO_DOMAIN_NOTARY_ATTESTATION).unwrap();
        assert!(matches!(
            verify(&token, &root.public_key(), Some(999)),
            Err(Error::Cwt(cwt::Error::NotYetValid {
                nbf: 1000,
                now: 999
            }))
        ));
    }

    /// Tests that a signature under the cloud domain cannot attest a notary key.
    #[test]
    fn test_notary_wrong_domain() {
        let root = xdsa::SecretKey::generate();
        let claims = notary_claims(xdsa::SecretKey::generate().public_key(), 1000);
        let token = cwt::issue(&claims, &root, CRYPTO_DOMAIN_CLOUD_ATTESTATION).unwrap();
        assert!(matches!(
            verify(&token, &root.public_key(), None),
            Err(Error::Cwt(cwt::Error::Cose(_)))
        ));
    }

    /// Tests that an expiry claim is rejected even when the signature is valid.
    #[test]
    fn test_notary_shape_mismatch() {
        /// Notary claims with an extra expiration timestamp.
        #[derive(Cbor)]
        struct ExpiringClaims {
            /// Key and start time.
            #[cbor(embed)]
            notary: NotaryClaims,
            /// End of the key's validity.
            #[cbor(embed)]
            exp: claims::Expiration,
        }

        // Sign the extra claim under the trusted root and the notary domain
        let root = xdsa::SecretKey::generate();
        let claims = ExpiringClaims {
            notary: notary_claims(xdsa::SecretKey::generate().public_key(), 1000),
            exp: claims::Expiration { exp: 2000 },
        };
        let token = cwt::issue(&claims, &root, CRYPTO_DOMAIN_NOTARY_ATTESTATION).unwrap();

        // The claim shape must fail independently of the clock
        for now in [Some(1000), None] {
            assert!(
                matches!(
                    verify(&token, &root.public_key(), now),
                    Err(Error::Cwt(cwt::Error::Cbor(_)))
                ),
                "{now:?}"
            );
        }
    }
}
