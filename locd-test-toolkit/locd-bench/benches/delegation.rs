use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use locd_crypto::Ed25519KeyPair;
use locd_delegation::{DelegationToken, current_timestamp};
use locd_core::IdentityDomain;

/// Benchmark delegation token creation
/// Target: <5ms
fn bench_delegation_token_create(c: &mut Criterion) {
    let master_key = Ed25519KeyPair::generate();
    let device_key = Ed25519KeyPair::generate();

    c.bench_function("delegation_token_create", |b| {
        b.iter(|| {
            black_box(
                DelegationToken::builder()
                    .delegator(master_key.public_key().to_bytes())
                    .delegate(device_key.public_key().to_bytes())
                    .not_before(current_timestamp())
                    .expires_at(current_timestamp() + 86400)
                    .service("api.example.com")
                    .action("read")
                    .build()
            )
        })
    });
}

/// Benchmark delegation token signing with COSE Sign1
/// Target: <1ms
fn bench_delegation_token_sign(c: &mut Criterion) {
    let master_key = Ed25519KeyPair::generate();
    let device_key = Ed25519KeyPair::generate();

    let token = DelegationToken::builder()
        .delegator(master_key.public_key().to_bytes())
        .delegate(device_key.public_key().to_bytes())
        .not_before(current_timestamp())
        .expires_at(current_timestamp() + 86400)
        .service("api.example.com")
        .action("read")
        .build()
        .unwrap();

    c.bench_function("delegation_token_sign", |b| {
        b.iter(|| {
            black_box(token.sign(&master_key))
        })
    });
}

/// Benchmark delegation token verification
/// Target: <2ms
fn bench_delegation_token_verify(c: &mut Criterion) {
    let master_key = Ed25519KeyPair::generate();
    let device_key = Ed25519KeyPair::generate();

    let token = DelegationToken::builder()
        .delegator(master_key.public_key().to_bytes())
        .delegate(device_key.public_key().to_bytes())
        .not_before(current_timestamp())
        .expires_at(current_timestamp() + 86400)
        .service("api.example.com")
        .action("read")
        .build()
        .unwrap();

    let signed_token = token.sign(&master_key).unwrap();

    c.bench_function("delegation_token_verify", |b| {
        b.iter(|| {
            black_box(signed_token.verify())
        })
    });
}

/// Benchmark CBOR encoding
/// Target: <0.5ms
fn bench_cbor_encode(c: &mut Criterion) {
    let master_key = Ed25519KeyPair::generate();
    let device_key = Ed25519KeyPair::generate();

    let token = DelegationToken::builder()
        .delegator(master_key.public_key().to_bytes())
        .delegate(device_key.public_key().to_bytes())
        .not_before(current_timestamp())
        .expires_at(current_timestamp() + 86400)
        .service("api.example.com")
        .action("read")
        .build()
        .unwrap();

    c.bench_function("cbor_encode", |b| {
        b.iter(|| {
            black_box(token.to_cbor())
        })
    });
}

/// Benchmark CBOR decoding
/// Target: <0.5ms
fn bench_cbor_decode(c: &mut Criterion) {
    let master_key = Ed25519KeyPair::generate();
    let device_key = Ed25519KeyPair::generate();

    let token = DelegationToken::builder()
        .delegator(master_key.public_key().to_bytes())
        .delegate(device_key.public_key().to_bytes())
        .not_before(current_timestamp())
        .expires_at(current_timestamp() + 86400)
        .service("api.example.com")
        .action("read")
        .build()
        .unwrap();

    let cbor_bytes = token.to_cbor().unwrap();

    c.bench_function("cbor_decode", |b| {
        b.iter(|| {
            black_box(DelegationToken::from_cbor(&cbor_bytes))
        })
    });
}

/// Benchmark delegation token with varying chain depths
fn bench_delegation_chain_depths(c: &mut Criterion) {
    let mut group = c.benchmark_group("delegation_chain_depths");

    for depth in [1, 2, 3, 5, 10].iter() {
        let tokens = create_delegation_chain(*depth);

        group.bench_with_input(BenchmarkId::from_parameter(depth), depth, |b, _| {
            b.iter(|| {
                black_box(verify_delegation_chain(&tokens))
            });
        });
    }
    group.finish();
}

/// Helper: Create a delegation chain of specified depth
fn create_delegation_chain(depth: usize) -> Vec<Vec<u8>> {
    let mut chain = Vec::new();
    let mut current_master = Ed25519KeyPair::generate();

    for _ in 0..depth {
        let delegate = Ed25519KeyPair::generate();

        let token = DelegationToken::builder()
            .delegator(current_master.public_key().to_bytes())
            .delegate(delegate.public_key().to_bytes())
            .not_before(current_timestamp())
            .expires_at(current_timestamp() + 86400)
            .service("api.example.com")
            .action("read")
            .build()
            .unwrap();

        let signed = token.sign(&current_master).unwrap();
        chain.push(signed.to_cbor().unwrap());

        current_master = delegate;
    }

    chain
}

/// Helper: Verify a delegation chain
fn verify_delegation_chain(chain: &[Vec<u8>]) -> bool {
    chain.iter().all(|token_bytes| {
        if let Ok(signed_token) = locd_delegation::SignedDelegationToken::from_cbor(token_bytes) {
            signed_token.verify().is_ok()
        } else {
            false
        }
    })
}

/// Benchmark delegation token with different service/action counts
fn bench_delegation_constraints(c: &mut Criterion) {
    let mut group = c.benchmark_group("delegation_constraints");
    let master_key = Ed25519KeyPair::generate();
    let device_key = Ed25519KeyPair::generate();

    // Single service, single action
    group.bench_function("single_service_single_action", |b| {
        b.iter(|| {
            black_box(
                DelegationToken::builder()
                    .delegator(master_key.public_key().to_bytes())
                    .delegate(device_key.public_key().to_bytes())
                    .not_before(current_timestamp())
                    .expires_at(current_timestamp() + 86400)
                    .service("api.example.com")
                    .action("read")
                    .build()
            )
        })
    });

    // Multiple services, multiple actions
    group.bench_function("multi_service_multi_action", |b| {
        b.iter(|| {
            black_box(
                DelegationToken::builder()
                    .delegator(master_key.public_key().to_bytes())
                    .delegate(device_key.public_key().to_bytes())
                    .not_before(current_timestamp())
                    .expires_at(current_timestamp() + 86400)
                    .service("api.example.com")
                    .service("auth.example.com")
                    .service("data.example.com")
                    .action("read")
                    .action("write")
                    .action("delete")
                    .build()
            )
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_delegation_token_create,
    bench_delegation_token_sign,
    bench_delegation_token_verify,
    bench_cbor_encode,
    bench_cbor_decode,
    bench_delegation_chain_depths,
    bench_delegation_constraints,
);

criterion_main!(benches);
