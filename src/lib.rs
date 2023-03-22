use wasm_bindgen::prelude::*;
use vsss_rs::{
    curve25519::{WrappedRistretto, WrappedScalar},
    Feldman, FeldmanVerifier,Share,
};
use curve25519_dalek::scalar::Scalar;
use rand::rngs::OsRng;
use hex;

const SHARES_NUMBER:usize = 5;
const THRESHOLD:usize = 3;
const SECRET_SIZE:usize = 33;
const ENCODED_SIZE:usize = 34;

/* GENERATE SECRET */
#[wasm_bindgen]
pub fn generate_secret() -> Result<Vec<u8>, JsValue> {
    let mut osrng7 = rand_7::rngs::OsRng::default();
    let sc = Scalar::random(&mut osrng7);
    
    Ok(sc.as_bytes().to_vec())
}

/* SPLIT */
#[wasm_bindgen]
pub fn split_secret(secret: &[u8]) -> Result<Vec<u8>, JsValue> {
    
    //alert(&format!("input, {}!", hex::encode(secret.clone())));

    let mut osrng = OsRng::default();
    
    //alert(&format!("working-1!"));
    //alert(&format!("secret size = {}", secret.len()));
    
    let mut secret_bound: [u8; 32] = Default::default();
    //alert(&format!("working-2-1!"));

    secret_bound.copy_from_slice(&secret);
    //alert(&format!("working-2-2!"));

    let sk = Scalar::from_bits(secret_bound);
    //alert(&format!("working-2-3!"));

    let res = Feldman::<THRESHOLD, SHARES_NUMBER>::split_secret::<WrappedScalar, WrappedRistretto, OsRng, SECRET_SIZE>(
        sk.into(),
        None,
        &mut osrng,
    );
    //alert(&format!("working-3!"));

    let (shares, verifier) = res.unwrap();
    
    let res = serde_bare::to_vec(&verifier);
    let mut v_bytes: Vec<u8> = res.unwrap();

    let mut s_bytes: Vec<u8> = Vec::<u8>::new();

    for i in 0..shares.len() {
        let mut res = serde_bare::to_vec(&shares[i]).unwrap();
        s_bytes.append(&mut res);
    }
    
    s_bytes.append(&mut v_bytes);
    
    Ok(s_bytes)
}

/* VERIFY */
#[wasm_bindgen]
pub fn verify_secret(share_bytes: &[u8], verifier_bytes: &[u8]) -> Result<bool, JsValue> {
    let res =
        serde_bare::from_slice::<FeldmanVerifier<WrappedScalar, WrappedRistretto, THRESHOLD>>(&verifier_bytes);
    
    let verifier = res.unwrap();
    
    let share:Share<SECRET_SIZE> = serde_bare::from_slice(share_bytes).unwrap();
    let res = verifier.verify(&share);

    Ok(res)
}

/* COMBINE */
#[wasm_bindgen]
pub fn combine_secret(share_bytes: &[u8]) -> Result<Vec<u8>, JsValue> {
    let mut share_bound: Vec<Share<SECRET_SIZE>> = Default::default();

    for i in 0..share_bytes.len()/ENCODED_SIZE {
        let sliced_share:[u8;ENCODED_SIZE] = share_bytes[i*ENCODED_SIZE..(i+1)*ENCODED_SIZE].try_into().unwrap();
        let share:Share<SECRET_SIZE> = serde_bare::from_slice(&sliced_share).unwrap();
        share_bound.append(&mut [share].to_vec());
    }
    
    let res = Feldman::<THRESHOLD, SHARES_NUMBER>::combine_shares::<WrappedScalar, SECRET_SIZE>(&share_bound);
    let scalar = res.unwrap().0;

    Ok(scalar.to_bytes().to_vec())
}

/* TEST */
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let secret = generate_secret().unwrap();

        let result = split_secret(&secret);
        let res = result.unwrap();

        let shareslen = SHARES_NUMBER * ENCODED_SIZE;

        //let mut shares = res[0..shareslen].chunks(33);
        let verifier = &res[shareslen..res.len()];
        
        for i in 0..SHARES_NUMBER {
            let share = &res[i*ENCODED_SIZE..(i+1)*ENCODED_SIZE];
            let valid = verify_secret(&share, verifier).unwrap();
            assert!(valid);
        }

        let reconstructed_secret = combine_secret(&res[0..shareslen]).unwrap();
        
        assert_eq!(reconstructed_secret,secret);
    }
}
