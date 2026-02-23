use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use locd_crypto::{Ed25519KeyPair, X25519KeyPair, ChaCha20Poly1305};

/// Benchmark Ed25519 key generation
/// Target: <1ms
fn bench_ed25519_keygen(c: &mut Criterion) {
    c.bench_function("ed25519_keygen", |b| {
        b.iter(|| {
            black_box(Ed25519KeyPair::generate())
        })
    });
}

/// Benchmark Ed25519 signing
/// Target: <0.5ms
fn bench_ed25519_sign(c: &mut Criterion) {
    let keypair = Ed25519KeyPair::generate();
    let message = b"test message for benchmarking - this simulates a typical delegation token payload";

    c.bench_function("ed25519_sign", |b| {
        b.iter(|| {
            black_box(keypair.sign(message))
        })
    });
}

/// Benchmark Ed25519 signature verification
/// Target: <1ms
fn bench_ed25519_verify(c: &mut Criterion) {
    let keypair = Ed25519KeyPair::generate();
    let message = b"test message for benchmarking - this simulates a typical delegation token payload";
    let signature = keypair.sign(message);

    c.bench_function("ed25519_verify", |b| {
        b.iter(|| {
            black_box(keypair.verify(message, &signature).is_ok())
        })
    });
}

/// Benchmark Ed25519 signing with varying message sizes
fn bench_ed25519_sign_sizes(c: &mut Criterion) {
    let mut group = c.benchmark_group("ed25519_sign_sizes");
    let keypair = Ed25519KeyPair::generate();

    for size in [32, 128, 512, 1024, 4096, 16384].iter() {
        let message = vec![0u8; *size];
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            b.iter(|| {
                black_box(keypair.sign(&message))
            });
        });
    }
    group.finish();
}

/// Benchmark X25519 key agreement
/// Target: <0.5ms
fn bench_x25519_key_agreement(c: &mut Criterion) {
    let alice_keypair = X25519KeyPair::generate();
    let bob_keypair = X25519KeyPair::generate();

    c.bench_function("x25519_key_agreement", |b| {
        b.iter(|| {
            black_box(alice_keypair.key_agreement(&bob_keypair.public_key()))
        })
    });
}

/// Benchmark ChaCha20-Poly1305 encryption
/// Target: 1GB/s (for 1MB data = ~1ms)
fn bench_chacha20poly1305_encrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("chacha20poly1305_encrypt");

    // Test with different payload sizes
    for size in [128, 1024, 4096, 16384, 65536].iter() {
        let plaintext = vec![0u8; *size];
        let key = ChaCha20Poly1305::generate_key();

        group.throughput(criterion::Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            b.iter(|| {
                black_box(ChaCha20Poly1305::encrypt(&key, &plaintext, &[]))
            });
        });
    }
    group.finish();
}

/// Benchmark ChaCha20-Poly1305 decryption
/// Target: 1GB/s (for 1MB data = ~1ms)
fn bench_chacha20poly1305_decrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("chacha20poly1305_decrypt");

    for size in [128, 1024, 4096, 16384, 65536].iter() {
        let plaintext = vec![0u8; *size];
        let key = ChaCha20Poly1305::generate_key();
        let (ciphertext, nonce) = ChaCha20Poly1305::encrypt(&key, &plaintext, &[]).unwrap();

        group.throughput(criterion::Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            b.iter(|| {
                black_box(ChaCha20Poly1305::decrypt(&key, &ciphertext, &nonce, &[]))
            });
        });
    }
    group.finish();
}

/// Benchmark key serialization/deserialization
fn bench_key_serialization(c: &mut Criterion) {
    let keypair = Ed25519KeyPair::generate();

    c.bench_function("ed25519_public_key_to_bytes", |b| {
        b.iter(|| {
            black_box(keypair.public_key().to_bytes())
        })
    });
}

criterion_group!(
    benches,
    bench_ed25519_keygen,
    bench_ed25519_sign,
    bench_ed25519_verify,
    bench_ed25519_sign_sizes,
    bench_x25519_key_agreement,
    bench_chacha20poly1305_encrypt,
    bench_chacha20poly1305_decrypt,
    bench_key_serialization,
);

criterion_main!(benches);
