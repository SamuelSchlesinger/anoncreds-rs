use anoncreds_rs::{PrivateKey, PreIssuance};
use criterion::{
    criterion_group,
    criterion_main,
    Criterion,
};
use curve25519_dalek::Scalar;
use rand_core::OsRng;

fn bench_issuance(c: &mut Criterion) {
    let mut group = c.benchmark_group("issuance");

    let private_key = PrivateKey::random(OsRng);
    let public_key = private_key.public();
    let pre_issuance = PreIssuance::random(OsRng);

    let n = Scalar::random(&mut OsRng);

    group.bench_function("request", |b| {
        b.iter(|| {
            let _req = pre_issuance.request(OsRng);
        })
    });

    let req = pre_issuance.request(OsRng);

    group.bench_function("response", |b| {
        b.iter(|| {
            let _resp = private_key.respond(&req, n, OsRng).unwrap();
        })
    });

    let resp = private_key.respond(&req, n, OsRng).unwrap();

    group.bench_function("creds", |b| {
        b.iter(|| {
            let _cred = pre_issuance.credential(&public_key, &req, &resp).unwrap();
        })
    });

    group.bench_function("all", |b| {
        b.iter(|| {
            let pre_issuance_local = PreIssuance::random(OsRng); 
            let req_local = pre_issuance_local.request(OsRng);
            let resp_local = private_key.respond(&req_local, n, OsRng).unwrap();
            let _cred_local = pre_issuance_local.credential(&public_key, &req_local, &resp_local).unwrap();
        })
    });

    group.finish();
}

criterion_group!(benches, bench_issuance);
criterion_main!(benches); 