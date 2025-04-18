use curve25519_dalek::{RistrettoPoint, Scalar};
use group::Group;
use rand_chacha::ChaCha20Rng;
use rand_core::{CryptoRngCore, SeedableRng};
use serde::{Deserialize, Serialize};

use std::ops::Neg;

struct Transcript {
    hasher: blake3::Hasher,
}

impl Transcript {
    fn new(label: &[u8]) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(label);
        Transcript { hasher }
    }

    fn with(label: &[u8], f: impl FnOnce(&mut Transcript)) -> Scalar {
        let mut transcript = Transcript::new(label);
        f(&mut transcript);
        transcript.challenge()
    }

    fn add_element(&mut self, element: &RistrettoPoint) {
        self.hasher
            .update(&bincode::serde::encode_to_vec(element, bincode::config::standard()).unwrap());
    }

    fn add_elements<'a>(&mut self, elements: impl Iterator<Item = &'a RistrettoPoint>) {
        for element in elements {
            self.add_element(element);
        }
    }

    fn add_scalar(&mut self, scalar: &Scalar) {
        self.hasher
            .update(&bincode::serde::encode_to_vec(scalar, bincode::config::standard()).unwrap());
    }

    fn rng(self) -> ChaCha20Rng {
        ChaCha20Rng::from_seed(*self.hasher.finalize().as_bytes())
    }

    fn challenge(self) -> Scalar {
        Scalar::random(&mut self.rng())
    }
}

#[derive(Serialize, Deserialize)]
pub struct PrivateKey {
    x: Scalar,
    public: PublicKey,
}

impl PrivateKey {
    pub fn random(mut rng: impl CryptoRngCore) -> Self {
        let x = Scalar::random(&mut rng);
        let public = PublicKey {
            w: RistrettoPoint::generator() * x,
        };
        PrivateKey { x, public }
    }

    pub fn public(&self) -> &PublicKey {
        &self.public
    }
}

#[derive(Serialize, Deserialize)]
pub struct PublicKey {
    w: RistrettoPoint,
}

#[derive(Serialize, Deserialize)]
pub struct Params {
    h0: RistrettoPoint,
    h1: RistrettoPoint,
    h2: RistrettoPoint,
}

impl Default for Params {
    fn default() -> Self {
        let rng = ChaCha20Rng::from_seed(*blake3::hash(b"INNOCENCE").as_bytes());
        Self::random(rng)
    }
}

impl Params {
    fn random(mut rng: impl CryptoRngCore) -> Self {
        Params {
            h0: RistrettoPoint::random(&mut rng),
            h1: RistrettoPoint::random(&mut rng),
            h2: RistrettoPoint::random(&mut rng),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct PreIssuance {
    r: Scalar,
    k: Scalar,
}

#[derive(Serialize, Deserialize)]
pub struct IssuanceRequest {
    kr: RistrettoPoint,
    c: Scalar,
    r_z: Scalar,
    k_z: Scalar,
}

#[derive(Serialize, Deserialize)]
pub struct CreditToken {
    a: RistrettoPoint,
    e: Scalar,
    k: Scalar,
    r: Scalar,
    n: Scalar,
}

impl PreIssuance {
    pub fn random(mut rng: impl CryptoRngCore) -> Self {
        PreIssuance {
            r: Scalar::random(&mut rng),
            k: Scalar::random(&mut rng),
        }
    }

    pub fn request(&self, mut rng: impl CryptoRngCore) -> IssuanceRequest {
        let params = Params::default();

        let kr = params.h0 * self.r + params.h1 * self.k;
        let r_t = Scalar::random(&mut rng);
        let k_t = Scalar::random(&mut rng);
        let kr_t = params.h0 * r_t + params.h1 * k_t;

        let c = Transcript::with(b"request", |transcript| {
            transcript.add_elements([&kr, &kr_t].into_iter());
        });

        let r_z = r_t + self.r * c;
        let k_z = k_t + self.k * c;

        IssuanceRequest { kr, c, r_z, k_z }
    }

    pub fn to_credit_token(
        &self,
        public: &PublicKey,
        request: &IssuanceRequest,
        response: &IssuanceResponse,
    ) -> Option<CreditToken> {
        let params = Params::default();

        let x_a = RistrettoPoint::generator() + request.kr + params.h2 * response.n;
        let x_g = RistrettoPoint::generator() * response.e + public.w;
        let y_a = response.a * response.z + x_a * response.c.neg();
        let y_g = RistrettoPoint::generator() * response.z + x_g * response.c.neg();

        let c = Transcript::with(b"respond", |transcript| {
            transcript.add_scalar(&response.e);
            transcript.add_elements([&response.a, &x_a, &x_g, &y_a, &y_g].into_iter());
        });

        if c != response.c {
            return None;
        }

        Some(CreditToken {
            a: response.a,
            e: response.e,
            r: self.r,
            k: self.k,
            n: response.n,
        })
    }
}

#[derive(Serialize, Deserialize)]
pub struct IssuanceResponse {
    a: RistrettoPoint,
    e: Scalar,
    c: Scalar,
    z: Scalar,
    n: Scalar,
}

impl PrivateKey {
    pub fn issue(
        &self,
        request: &IssuanceRequest,
        n: Scalar,
        mut rng: impl CryptoRngCore,
    ) -> Option<IssuanceResponse> {
        let params = Params::default();
        let kr_t = (params.h0 * request.r_z + params.h1 * request.k_z) - request.kr * request.c;

        let c = Transcript::with(b"request", |transcript| {
            transcript.add_elements([&request.kr, &kr_t].into_iter());
        });

        if c != request.c {
            return None;
        }

        let e = Scalar::random(&mut rng);
        let a = (RistrettoPoint::generator() + request.kr + params.h2 * n) * (e + self.x).invert();
        let x_a = RistrettoPoint::generator() + request.kr + params.h2 * n;
        let x_g = RistrettoPoint::generator() * e + self.public.w;
        let alpha = Scalar::random(&mut rng);
        let y_a = a * alpha;
        let y_g = RistrettoPoint::generator() * alpha;

        let c = Transcript::with(b"respond", |transcript| {
            transcript.add_scalar(&e);
            transcript.add_elements([&a, &x_a, &x_g, &y_a, &y_g].into_iter());
        });

        let z = c * (self.x + e) + alpha;

        Some(IssuanceResponse { a, e, c, z, n })
    }
}

#[derive(Serialize, Deserialize)]
pub struct SpendProof {
    nonce: Scalar,
    charge: Scalar,
}

impl SpendProof {
    pub fn nonce(&self) -> Scalar {
        todo!()
    }

    pub fn charge(&self) -> Scalar {
        todo!()
    }
}

impl PrivateKey {
    pub fn refund(&self, _spend_proof: &SpendProof, mut _rng: impl CryptoRngCore) -> Option<Refund> {
        todo!()
    }
}

#[derive(Serialize, Deserialize)]
pub struct PreRefund {
    r: Scalar,
    k: Scalar,
    m: Scalar,
}

impl CreditToken {
    pub fn prove_spend(&self, _charge: Scalar, _public_key: &PublicKey, mut _rng: impl CryptoRngCore) -> (SpendProof, PreRefund) {
        todo!()
    }
}

#[derive(Serialize, Deserialize)]
pub struct Refund {
}

impl PreRefund {
    pub fn to_credit_token(&self, _spend_proof: &SpendProof, _refund: &Refund, _public_key: &PublicKey) -> Option<CreditToken> {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issuance() {
        use rand_core::OsRng;
        for _i in 0..100 {
            let private_key = PrivateKey::random(OsRng);
            let preissuance = PreIssuance::random(OsRng);
            let issuance_request = preissuance.request(OsRng);
            let issuance_response = private_key
                .issue(&issuance_request, Scalar::from(20u64), OsRng)
                .unwrap();
            let _credit_token1 = preissuance
                .to_credit_token(private_key.public(), &issuance_request, &issuance_response)
                .unwrap();
            }
    }

    /*
    #[test]
    fn full_cycle() {
        use rand_core::OsRng;
        for _i in 0..100 {
            let private_key = PrivateKey::random(OsRng);
            let preissuance = PreIssuance::random(OsRng);
            let issuance_request = preissuance.request(OsRng);
            let issuance_response = private_key
                .issue(&issuance_request, Scalar::from(20u64), OsRng)
                .unwrap();
            let credit_token1 = preissuance
                .to_credit_token(private_key.public(), &issuance_request, &issuance_response)
                .unwrap();
            let charge = Scalar::from(20u64);
            let (spend_proof, prerefund) = credit_token1.prove_spend(charge, private_key.public(), OsRng);
            let refund = private_key.refund(&spend_proof, OsRng).unwrap();
            let credit_token2 = prerefund
                .to_credit_token(&spend_proof, &refund, private_key.public())
                .unwrap();
            let charge = Scalar::from(20u64);
            let (spend_proof, prerefund) = credit_token2.prove_spend(charge, private_key.public(), OsRng);
            let refund = private_key.refund(&spend_proof, OsRng).unwrap();
            let _credit_token3 = prerefund
                .to_credit_token(&spend_proof, &refund, private_key.public())
                .unwrap();
        }
    }
    */
}
