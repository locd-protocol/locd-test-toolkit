use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use locd_core::IdentityDomain;
use locd_crypto::Ed25519KeyPair;
use locd_dns::{IdentityRecord, RevocationRecord};

/// Benchmark TXT record formatting for identity records
/// Target: <0.1ms
fn bench_txt_record_format_identity(c: &mut Criterion) {
    let keypair = Ed25519KeyPair::generate();
    let domain = IdentityDomain::new("alice.example.com").unwrap();

    let record = IdentityRecord::builder()
        .domain(domain.clone())
        .master_key(keypair.public_key().to_bytes())
        .version(1)
        .build()
        .unwrap();

    c.bench_function("txt_record_format_identity", |b| {
        b.iter(|| black_box(record.to_txt_record()))
    });
}

/// Benchmark TXT record parsing for identity records
/// Target: <0.2ms
fn bench_txt_record_parse_identity(c: &mut Criterion) {
    let keypair = Ed25519KeyPair::generate();
    let domain = IdentityDomain::new("alice.example.com").unwrap();

    let record = IdentityRecord::builder()
        .domain(domain.clone())
        .master_key(keypair.public_key().to_bytes())
        .version(1)
        .build()
        .unwrap();

    let txt = record.to_txt_record().unwrap();

    c.bench_function("txt_record_parse_identity", |b| {
        b.iter(|| black_box(IdentityRecord::from_txt_record(&txt)))
    });
}

/// Benchmark TXT record formatting for revocation records
/// Target: <0.1ms
fn bench_txt_record_format_revocation(c: &mut Criterion) {
    let mut revoked = Vec::new();
    for _ in 0..10 {
        revoked.push(uuid::Uuid::new_v4());
    }

    let record = RevocationRecord::builder()
        .revoked_tokens(revoked)
        .version(1)
        .build()
        .unwrap();

    c.bench_function("txt_record_format_revocation", |b| {
        b.iter(|| black_box(record.to_txt_record()))
    });
}

/// Benchmark TXT record parsing for revocation records
/// Target: <0.2ms
fn bench_txt_record_parse_revocation(c: &mut Criterion) {
    let mut revoked = Vec::new();
    for _ in 0..10 {
        revoked.push(uuid::Uuid::new_v4());
    }

    let record = RevocationRecord::builder()
        .revoked_tokens(revoked)
        .version(1)
        .build()
        .unwrap();

    let txt = record.to_txt_record().unwrap();

    c.bench_function("txt_record_parse_revocation", |b| {
        b.iter(|| black_box(RevocationRecord::from_txt_record(&txt)))
    });
}

/// Benchmark revocation list with varying sizes
fn bench_revocation_list_sizes(c: &mut Criterion) {
    let mut group = c.benchmark_group("revocation_list_sizes");

    for size in [1, 10, 50, 100, 500].iter() {
        let mut revoked = Vec::new();
        for _ in 0..*size {
            revoked.push(uuid::Uuid::new_v4());
        }

        let record = RevocationRecord::builder()
            .revoked_tokens(revoked.clone())
            .version(1)
            .build()
            .unwrap();

        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            b.iter(|| black_box(record.to_txt_record()));
        });
    }
    group.finish();
}

/// Benchmark checking if a token is revoked
fn bench_revocation_check(c: &mut Criterion) {
    let mut group = c.benchmark_group("revocation_check");

    for size in [10, 100, 500, 1000].iter() {
        let mut revoked = Vec::new();
        for _ in 0..*size {
            revoked.push(uuid::Uuid::new_v4());
        }

        let record = RevocationRecord::builder()
            .revoked_tokens(revoked.clone())
            .version(1)
            .build()
            .unwrap();

        let check_uuid = uuid::Uuid::new_v4(); // Not in list

        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            b.iter(|| black_box(record.is_revoked(&check_uuid)));
        });
    }
    group.finish();
}

/// Benchmark domain validation
fn bench_domain_validation(c: &mut Criterion) {
    c.bench_function("domain_validation_valid", |b| {
        b.iter(|| black_box(IdentityDomain::new("alice.example.com")))
    });

    c.bench_function("domain_validation_invalid", |b| {
        b.iter(|| black_box(IdentityDomain::new("invalid..domain")))
    });
}

/// Benchmark TXT record roundtrip (format + parse)
fn bench_txt_record_roundtrip(c: &mut Criterion) {
    let keypair = Ed25519KeyPair::generate();
    let domain = IdentityDomain::new("alice.example.com").unwrap();

    let record = IdentityRecord::builder()
        .domain(domain.clone())
        .master_key(keypair.public_key().to_bytes())
        .version(1)
        .build()
        .unwrap();

    c.bench_function("txt_record_roundtrip", |b| {
        b.iter(|| {
            let txt = record.to_txt_record().unwrap();
            black_box(IdentityRecord::from_txt_record(&txt))
        })
    });
}

criterion_group!(
    benches,
    bench_txt_record_format_identity,
    bench_txt_record_parse_identity,
    bench_txt_record_format_revocation,
    bench_txt_record_parse_revocation,
    bench_revocation_list_sizes,
    bench_revocation_check,
    bench_domain_validation,
    bench_txt_record_roundtrip,
);

criterion_main!(benches);
