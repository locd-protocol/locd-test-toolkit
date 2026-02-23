use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use locd_crypto::{Ed25519KeyPair, X25519KeyPair};
use locd_delegation::{DelegationToken, current_timestamp};
use locd_verification::{Claimant, Verifier, HelloMessage, ChallengeMessage, ResponseMessage};
use locd_core::IdentityDomain;
use locd_revocation::RevocationChecker;

/// Mock revocation checker for benchmarking
struct NoOpRevocationChecker;

impl RevocationChecker for NoOpRevocationChecker {
    fn is_revoked(&self, _token_id: &uuid::Uuid) -> Result<bool, locd_core::Error> {
        Ok(false)
    }
}

/// Benchmark Hello message creation
/// Target: <1ms
fn bench_hello_message_create(c: &mut Criterion) {
    let device_key = Ed25519KeyPair::generate();
    let domain = IdentityDomain::new("alice.example.com").unwrap();
    let claimant = Claimant::new(device_key, domain);

    c.bench_function("hello_message_create", |b| {
        b.iter(|| {
            black_box(claimant.create_hello())
        })
    });
}

/// Benchmark Challenge message creation
/// Target: <0.5ms
fn bench_challenge_create(c: &mut Criterion) {
    let device_key = Ed25519KeyPair::generate();
    let domain = IdentityDomain::new("alice.example.com").unwrap();
    let claimant = Claimant::new(device_key, domain.clone());
    let hello = claimant.create_hello().unwrap();

    let wg_key = X25519KeyPair::generate();
    let service_domain = IdentityDomain::new("service.example.com").unwrap();
    let verifier = Verifier::new(service_domain, wg_key.public_key().to_bytes(), None);

    c.bench_function("challenge_create", |b| {
        b.iter(|| {
            black_box(verifier.handle_hello(&hello))
        })
    });
}

/// Benchmark Response message creation
/// Target: <2ms
fn bench_response_create(c: &mut Criterion) {
    let master_key = Ed25519KeyPair::generate();
    let device_key = Ed25519KeyPair::generate();
    let domain = IdentityDomain::new("alice.example.com").unwrap();

    // Create delegation token
    let token = DelegationToken::builder()
        .delegator(master_key.public_key().to_bytes())
        .delegate(device_key.public_key().to_bytes())
        .not_before(current_timestamp())
        .expires_at(current_timestamp() + 86400)
        .service("service.example.com")
        .action("read")
        .build()
        .unwrap();

    let signed_token = token.sign(&master_key).unwrap();

    let claimant = Claimant::new(device_key, domain.clone());
    let hello = claimant.create_hello().unwrap();

    let wg_key = X25519KeyPair::generate();
    let service_domain = IdentityDomain::new("service.example.com").unwrap();
    let verifier = Verifier::new(service_domain, wg_key.public_key().to_bytes(), None);
    let challenge = verifier.handle_hello(&hello).unwrap();

    c.bench_function("response_create", |b| {
        b.iter(|| {
            black_box(claimant.create_response(&challenge, signed_token.clone(), vec![]))
        })
    });
}

/// Benchmark full verification flow
/// Target: <10ms
fn bench_full_verification_flow(c: &mut Criterion) {
    let master_key = Ed25519KeyPair::generate();
    let device_key = Ed25519KeyPair::generate();
    let domain = IdentityDomain::new("alice.example.com").unwrap();

    // Create delegation token
    let token = DelegationToken::builder()
        .delegator(master_key.public_key().to_bytes())
        .delegate(device_key.public_key().to_bytes())
        .not_before(current_timestamp())
        .expires_at(current_timestamp() + 86400)
        .service("service.example.com")
        .action("read")
        .build()
        .unwrap();

    let signed_token = token.sign(&master_key).unwrap();

    let claimant = Claimant::new(device_key, domain.clone());
    let hello = claimant.create_hello().unwrap();

    let wg_key = X25519KeyPair::generate();
    let service_domain = IdentityDomain::new("service.example.com").unwrap();
    let verifier = Verifier::new(service_domain, wg_key.public_key().to_bytes(), Some(Box::new(NoOpRevocationChecker)));

    let challenge = verifier.handle_hello(&hello).unwrap();
    let response = claimant.create_response(&challenge, signed_token, vec![]).unwrap();

    c.bench_function("full_verification_flow", |b| {
        b.iter(|| {
            black_box(verifier.verify_response(
                &hello,
                &challenge,
                &response,
                "service.example.com",
                "read"
            ))
        })
    });
}

/// Benchmark verification with varying delegation chain depths
fn bench_verification_chain_depths(c: &mut Criterion) {
    let mut group = c.benchmark_group("verification_chain_depths");

    for depth in [1, 2, 3, 5].iter() {
        // Create delegation chain
        let (final_device_key, tokens) = create_verification_chain(*depth);

        let domain = IdentityDomain::new("alice.example.com").unwrap();
        let claimant = Claimant::new(final_device_key, domain.clone());
        let hello = claimant.create_hello().unwrap();

        let wg_key = X25519KeyPair::generate();
        let service_domain = IdentityDomain::new("service.example.com").unwrap();
        let verifier = Verifier::new(service_domain, wg_key.public_key().to_bytes(), Some(Box::new(NoOpRevocationChecker)));

        let challenge = verifier.handle_hello(&hello).unwrap();
        let response = claimant.create_response(&challenge, tokens[0].clone(), tokens[1..].to_vec()).unwrap();

        group.bench_with_input(BenchmarkId::from_parameter(depth), depth, |b, _| {
            b.iter(|| {
                black_box(verifier.verify_response(
                    &hello,
                    &challenge,
                    &response,
                    "service.example.com",
                    "read"
                ))
            });
        });
    }
    group.finish();
}

/// Helper: Create a verification chain with specified depth
fn create_verification_chain(depth: usize) -> (Ed25519KeyPair, Vec<locd_delegation::SignedDelegationToken>) {
    let mut tokens = Vec::new();
    let mut current_master = Ed25519KeyPair::generate();

    for _ in 0..depth {
        let delegate = Ed25519KeyPair::generate();

        let token = DelegationToken::builder()
            .delegator(current_master.public_key().to_bytes())
            .delegate(delegate.public_key().to_bytes())
            .not_before(current_timestamp())
            .expires_at(current_timestamp() + 86400)
            .service("service.example.com")
            .action("read")
            .build()
            .unwrap();

        let signed = token.sign(&current_master).unwrap();
        tokens.push(signed);

        current_master = delegate;
    }

    (current_master, tokens)
}

/// Benchmark message serialization
fn bench_message_serialization(c: &mut Criterion) {
    let device_key = Ed25519KeyPair::generate();
    let domain = IdentityDomain::new("alice.example.com").unwrap();
    let claimant = Claimant::new(device_key, domain);
    let hello = claimant.create_hello().unwrap();

    c.bench_function("hello_message_serialize", |b| {
        b.iter(|| {
            black_box(hello.to_cbor())
        })
    });

    let cbor = hello.to_cbor().unwrap();

    c.bench_function("hello_message_deserialize", |b| {
        b.iter(|| {
            black_box(HelloMessage::from_cbor(&cbor))
        })
    });
}

/// Benchmark timestamp validation overhead
fn bench_timestamp_validation(c: &mut Criterion) {
    let device_key = Ed25519KeyPair::generate();
    let domain = IdentityDomain::new("alice.example.com").unwrap();
    let claimant = Claimant::new(device_key, domain.clone());

    c.bench_function("timestamp_validation", |b| {
        b.iter(|| {
            let hello = claimant.create_hello().unwrap();
            black_box(hello.validate_timestamp())
        })
    });
}

/// Benchmark nonce generation and verification
fn bench_nonce_operations(c: &mut Criterion) {
    use rand::RngCore;
    use rand::rngs::OsRng;

    c.bench_function("nonce_generation", |b| {
        b.iter(|| {
            let mut nonce = [0u8; 32];
            OsRng.fill_bytes(&mut nonce);
            black_box(nonce)
        })
    });
}

criterion_group!(
    benches,
    bench_hello_message_create,
    bench_challenge_create,
    bench_response_create,
    bench_full_verification_flow,
    bench_verification_chain_depths,
    bench_message_serialization,
    bench_timestamp_validation,
    bench_nonce_operations,
);

criterion_main!(benches);
