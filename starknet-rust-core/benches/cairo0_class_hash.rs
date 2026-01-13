use criterion::{Criterion, criterion_group, criterion_main};
use starknet_rust_core::types::contract::legacy::LegacyContractClass;
use std::hint::black_box;

pub fn criterion_benchmark(c: &mut Criterion) {
    // Using the latest OZ account contract for the benchmark
    let contract_artifact: LegacyContractClass = serde_json::from_str(include_str!(
        "../test-data/contracts/cairo0/artifacts/oz_account.txt"
    ))
    .unwrap();

    c.bench_function("cairo0_class_hash", |b| {
        b.iter(|| {
            black_box(&contract_artifact).class_hash().unwrap();
        });
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
