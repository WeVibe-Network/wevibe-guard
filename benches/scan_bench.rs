use criterion::{black_box, criterion_group, criterion_main, Criterion};
use wevibe_guard::scan_memory;

fn bench_scan_10kb(c: &mut Criterion) {
    let text = "a".repeat(10_000);
    c.bench_function("scan_10kb_clean", |b| {
        b.iter(|| scan_memory(black_box(&text)))
    });
}

criterion_group!(benches, bench_scan_10kb);
criterion_main!(benches);
