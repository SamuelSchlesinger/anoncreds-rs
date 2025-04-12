use anoncreds_rs::{PrivateKey, PreIssuance};
use curve25519_dalek::Scalar;
use rand_core::OsRng;

fn main() {
    println!("keygen...");
    let private_key = PrivateKey::random(OsRng);
    let public_key = private_key.public();

    let pre_issuance = PreIssuance::random(OsRng);

    // nonce?
    let n = Scalar::random(&mut OsRng);

    println!("generating issuance request...");
    let req = pre_issuance.request(OsRng);
    println!("issuance request: {:?}", req);

    println!("generating issuance response...");
    match private_key.respond(&req, n, OsRng) {
        Some(resp) => {
            println!("issuance response: {:?}", resp);

            println!("verifying response and creating creds...");
            match pre_issuance.credential(&public_key, &req, &resp) {
                Some(cred) => println!("credential created successfully: {:?}", cred),
                None => println!("failed to create creds."),
            }
        }
        None => {
            println!("failed to generate issuance response.");
        }
    }
} 