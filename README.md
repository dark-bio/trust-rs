# Ecosystem Roots of Trust in Rust

[![](https://img.shields.io/crates/v/darkbio-trust.svg)](https://crates.io/crates/darkbio-trust)
[![](https://docs.rs/darkbio-trust/badge.svg)](https://docs.rs/darkbio-trust)
[![](https://github.com/dark-bio/trust-rs/workflows/tests/badge.svg)](https://github.com/dark-bio/trust-rs/actions/workflows/ci.yml)

This crate holds the root pubkeys of the [Dark Bio](https://dark.bio) ecosystem and the attestation formats issued under them, so that any party can verify the identity of an Ark enclave or of the Dark Bio cloud with nothing beyond the public keys published in our [transparency reports repository](https://github.com/dark-bio/transparency).

The crate has three parts:

- `roots` embeds the keys and knows every root by fingerprint.
- `cloud` verifies the attestations of the Dark Bio rotating cloud keys.
- `device` verifies the attestations of Arks, hardware and emulated alike.

## Environments and features

Devices and clouds belong to one of three environments: `release`, `staging` and `develop`, each with its own roots. Every environment can be named in every Rust feature combination, but its keys are only embedded when the crate feature of the same name is enabled. No environment feature is enabled by default. Verification uses the roots supplied by the caller.

```toml
[dependencies]
darkbio-trust = { version = "0.4", features = ["release"] }
```

Hardware and emulated Arks live in separate realms. Hardware devices are attested once at manufacturing by the device root of their series and never expire. Emulated devices are attested online by the emulator root and always expire. The two realms never share trust.

## Verifying a device

Pass the root pubkeys you accept (hardware, emulator, or both), along with the current time.

```rust
use darkbio_trust::{Environment, device, roots};

fn authenticate(attestation: &[u8], now: u64) -> Result<device::Device, darkbio_trust::Error> {
    let env = Environment::Release;

    device::verify(
        attestation,
        roots::hardware(env),
        roots::emulator(env),
        Some(now),
    )
}
```

The result carries the identity key of the device, its serial, manufacturer, model and hardware revision, the time of issuance and the validity period. An attestation only proves that a root vouched for the key. The transport still has to prove that the peer holds it.

A device that was never onboarded presents an attestation signed by its own identity key. `device::verify_self_signed` accepts such an attestation and returns nothing but that key. Whether to talk to such a device is up to the application.

## Verifying the cloud

The cloud root of an environment attests the cloud's current signing and encryption keys. `cloud::verify_signer` and `cloud::verify_crypto` take that root and return the claims, which name the operator, the endpoint the key serves, the key itself and its validity.

```rust
use darkbio_trust::{Environment, cloud, roots};

fn cloud_signer(attestation: &[u8], now: u64) -> Result<cloud::SignerClaims, Box<dyn std::error::Error>> {
    let root = roots::cloud(Environment::Release).ok_or("release roots are not embedded")?;

    let claims = cloud::verify_signer(attestation, root, Some(now))?;
    if claims.sub.sub != "https://api.dark.bio" {
        return Err("key serves another endpoint".into());
    }
    Ok(claims)
}
```

## Validity footnotes

Verification always checks the signature, the domain and the shape of the claims. Emulator attestations may be valid for at most 30 days; cloud attestations for at most 90 days; hardware attestations never expire. With a time specified, the attestation must also be valid at that moment. Without one, the clock check is skipped.

## Naming a signer

When an attestation names a key that is not among the roots passed in, the error identifies it if it is a root of the ecosystem. For example, a `develop` Ark presented to a `release` verifier would name a `develop` device or emulator attester. This is an unauthenticated hint for logs. The fingerprints of every root are compiled into every build, so a root can be named even when its key is not embedded. `roots::identify` answers the same question for RSA and xDSA fingerprints, the RSA secure boot keys included.

## License

This library is licensed under the [BSD 3-Clause License](https://github.com/dark-bio/trust-rs/blob/main/LICENSE).
