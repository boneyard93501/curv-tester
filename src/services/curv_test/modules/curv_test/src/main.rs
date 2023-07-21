#![allow(non_snake_case)]
use marine_rs_sdk::marine;

use curv::elliptic::curves::*;

pub fn main() {}

use curv::elliptic::curves::*;
use sha2::Sha256;

/// Sigma protocol for proof of knowledge of discrete log
/// TO RUN:
/// cargo run --example proof_of_knowledge_of_dlog -- CURVE_NAME
/// CURVE_NAME is any of the supported curves: i.e.:
/// cargo run --example proof_of_knowledge_of_dlog -- jubjub
///
/// notice: this library includes other more complex sigma protocol.
/// see proofs folder for more details

pub fn dlog_proof<E: Curve>() {
    use curv::cryptographic_primitives::proofs::sigma_dlog::*;

    let witness = Scalar::random();
    let dlog_proof = DLogProof::<E, Sha256>::prove(&witness);
    assert!(DLogProof::verify(&dlog_proof).is_ok());
}


pub fn secret_sharing_3_out_of_5<E: Curve>() {
    use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;

    let secret = Scalar::random();

    let (vss_scheme, secret_shares) = VerifiableSS::<E, Sha256>::share(3, 5, &secret);

    let shares_vec = vec![
        secret_shares[0].clone(),
        secret_shares[1].clone(),
        secret_shares[2].clone(),
        secret_shares[4].clone(),
    ];
    //test reconstruction

    let secret_reconstructed = vss_scheme.reconstruct(&[0, 1, 2, 4], &shares_vec);

    assert_eq!(secret, secret_reconstructed);
    // test secret shares are verifiable
    let valid3 = vss_scheme.validate_share(&secret_shares[2], 3);
    let valid1 = vss_scheme.validate_share(&secret_shares[0], 1);
    assert!(valid3.is_ok());
    assert!(valid1.is_ok());

    let g = Point::generator();
    let share1_public = g * &secret_shares[0];
    let valid1_public = vss_scheme.validate_share_public(&share1_public, 1);
    assert!(valid1_public.is_ok());

    // test map (t,n) - (t',t')
    let s = &vec![0, 1, 2, 3, 4];
    let l0 = VerifiableSS::<E, Sha256>::map_share_to_new_params(&vss_scheme.parameters, 0, s);
    let l1 = VerifiableSS::<E, Sha256>::map_share_to_new_params(&vss_scheme.parameters, 1, s);
    let l2 = VerifiableSS::<E, Sha256>::map_share_to_new_params(&vss_scheme.parameters, 2, s);
    let l3 = VerifiableSS::<E, Sha256>::map_share_to_new_params(&vss_scheme.parameters, 3, s);
    let l4 = VerifiableSS::<E, Sha256>::map_share_to_new_params(&vss_scheme.parameters, 4, s);

    let w = l0 * secret_shares[0].clone()
        + l1 * secret_shares[1].clone()
        + l2 * secret_shares[2].clone()
        + l3 * secret_shares[3].clone()
        + l4 * secret_shares[4].clone();
    assert_eq!(w, secret_reconstructed);
}


#[marine]
fn pok_dlog(curv_name: String) {
    // let curve_name = std::env::args().nth(1);
    let curve_name = Some(curv_name);
    match curve_name.as_deref() {
        Some("secp256k1") => dlog_proof::<Secp256k1>(),
        Some("ristretto") => dlog_proof::<Ristretto>(),
        Some("ed25519") => dlog_proof::<Ed25519>(),
        Some("bls12_381_1") => dlog_proof::<Bls12_381_1>(),
        Some("bls12_381_2") => dlog_proof::<Bls12_381_2>(),
        Some("p256") => dlog_proof::<Secp256r1>(),
        Some(unknown_curve) => eprintln!("Unknown curve: {}", unknown_curve),
        None => eprintln!("Missing curve name"),
    }
}

#[marine]
fn vs_share(curv_name: String) {
    let curve_name = Some(curv_name);
    match curve_name.as_deref() {
        Some("secp256k1") => secret_sharing_3_out_of_5::<Secp256k1>(),
        Some("ristretto") => secret_sharing_3_out_of_5::<Ristretto>(),
        Some("ed25519") => secret_sharing_3_out_of_5::<Ed25519>(),
        Some("bls12_381_1") => secret_sharing_3_out_of_5::<Bls12_381_1>(),
        Some("bls12_381_2") => secret_sharing_3_out_of_5::<Bls12_381_2>(),
        Some("p256") => secret_sharing_3_out_of_5::<Secp256r1>(),
        Some(unknown_curve) => eprintln!("Unknown curve: {}", unknown_curve),
        None => eprintln!("Missing curve name"),
    }
}