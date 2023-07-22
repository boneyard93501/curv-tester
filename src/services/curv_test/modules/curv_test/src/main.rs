#![allow(non_snake_case)]
use marine_rs_sdk::marine;

use curv::elliptic::curves::*;
use sha2::Sha256;
// use secp256k1::rand::rngs::OsRng;
// use secp256k1::{Secp256k1 as NSecp256k1, Message as NMessage};
use bitcoin_hashes::sha256;


pub fn main() {}


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
    println!("got curv");
    let witness = Scalar::random();
    println!("got witness: {:?}", witness);
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
fn pok_dlog() {
    // let curve_name = std::env::args().nth(1);
    let curve_names = vec![
        // "secp256k1",
        "ristretto",
        "ed25519",
        "bls12_381_1",
        "bls12_381_2",
        "secp256k1",
        "p256"];
    for cn in curve_names {
        let curve_name = Some(cn);
        // if curve_name.unwrap() != "p256" {
        //      return;
        // }
        println!("pok_dlog curve requested: {}", curve_name.clone().unwrap());
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
        println!("pok_dlog curve used: {}", curve_name.clone().unwrap());
    }
}

#[marine]
fn pok_dlog_secp() {
    let res = dlog_proof::<Secp256k1>();
    println!("pok_dlog secp256K1: {:?}", res);
}



#[marine]
fn vs_share() {
    let curve_names: Vec<&str> = vec![
        "secp256k1",
        "ristretto",
        "ed25519",
        "bls12_381_1",
        "bls12_381_2",
        "p256"];
    for cn in curve_names {
        let curve_name = Some(cn);
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

}
/*
#[marine]
fn secp_test() {
    let secp = NSecp256k1::new();
    let mut rng = OsRng::new().expect("OsRng");
    let (secret_key, public_key) = secp.generate_keypair(&mut rng);
    // let (secret_key, public_key) = secp.generate_keypair(&mut OsRng);   
    // let message = NMessage::from_hashed_data::<sha256::Hash>("Hello World!".as_bytes());

    // let sig = secp.sign(&message, &secret_key);
}
*/
/*
use bitcoin_hashes::{sha256, Hash};
use secp256k1::{ecdsa, Error, Message, PublicKey, Secp256k1, SecretKey, Signing, Verification};

fn recover<C: Verification>(
    secp: &Secp256k1<C>,
    msg: &[u8],
    sig: [u8; 64],
    recovery_id: u8,
) -> Result<PublicKey, Error> {
    let msg = sha256::Hash::hash(msg);
    let msg = Message::from_slice(msg.as_ref())?;
    let id = ecdsa::RecoveryId::from_i32(recovery_id as i32)?;
    let sig = ecdsa::RecoverableSignature::from_compact(&sig, id)?;

    secp.recover_ecdsa(&msg, &sig)
}

fn sign_recovery<C: Signing>(
    secp: &Secp256k1<C>,
    msg: &[u8],
    seckey: [u8; 32],
) -> Result<ecdsa::RecoverableSignature, Error> {
    let msg = sha256::Hash::hash(msg);
    let msg = Message::from_slice(msg.as_ref())?;
    let seckey = SecretKey::from_slice(&seckey)?;
    Ok(secp.sign_ecdsa_recoverable(&msg, &seckey))
}
*/