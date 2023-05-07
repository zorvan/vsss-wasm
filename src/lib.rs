//use console_error_panic_hook;

use wasm_bindgen::prelude::*;
use vsss_rs::{
    curve25519::{WrappedRistretto, WrappedScalar},
    feldman, FeldmanVerifier,Share, combine_shares,
};
use curve25519_dalek::scalar::Scalar;
use rand::{rngs::OsRng, SeedableRng, RngCore};
use rand_chacha::ChaCha20Rng;

pub const SHARES_NUMBER:usize = 5;
pub const THRESHOLD:usize = 3;
pub const SECRET_SIZE:usize = 33;
pub const ENCODED_SIZE:usize = 34;

/* GENERATE SECRET */
#[wasm_bindgen]
pub fn generate_secret() -> Result<Vec<u8>, JsValue> {
    //console_error_panic_hook::set_once();

    let mut rng = ChaCha20Rng::from_entropy();
    let mut scalar_bytes = [0u8; 64];
    rng.fill_bytes(&mut scalar_bytes);
    let sc = Scalar::from_bytes_mod_order_wide(&scalar_bytes);
       
    Ok(sc.as_bytes().to_vec())
}

/* SPLIT */
#[wasm_bindgen]
pub fn split_secret(secret: &[u8]) -> Result<Vec<u8>, JsValue> {
    
    let mut osrng = OsRng::default();
    
    let mut secret_bound: [u8; 32] = Default::default();

    secret_bound.copy_from_slice(&secret);

    let sk = Scalar::from_bits(secret_bound);

    
    let res = feldman::split_secret::<WrappedScalar, WrappedRistretto, OsRng>(THRESHOLD, SHARES_NUMBER,
        sk.into(),
        None,
        &mut osrng,
    );

    let (shares, verifier) = match res {
        Ok(tuple) => tuple,
        Err(e) => return Err(e.to_string().into()),
    };
    
    let res = serde_bare::to_vec(&verifier);
    let mut v_bytes: Vec<u8> = match res {
        Ok(vbytes) => vbytes,
        Err(e) => return Err(e.to_string().into()),
    };

    let mut s_bytes: Vec<u8> = Vec::<u8>::new();

    for i in 0..shares.len() {
        let mut res = match serde_bare::to_vec(&shares[i]) {
            Ok(encoded) => encoded,
            Err(e) => return Err(e.to_string().into()),
        };

        s_bytes.append(&mut res);
    }
    
    s_bytes.append(&mut v_bytes);
    
    Ok(s_bytes)
}

/* VERIFY */
#[wasm_bindgen]
pub fn verify_secret(share_bytes: &[u8], verifier_bytes: &[u8]) -> Result<bool, JsValue> {
    
    let res =
        serde_bare::from_slice::<FeldmanVerifier<WrappedScalar, WrappedRistretto>>(&verifier_bytes);

    let verifier = match res {
        Ok(fv) => fv,
        Err(e) => return Err(e.to_string().into()),
    };

    let share:Share = match serde_bare::from_slice(share_bytes) {
        Ok(share) => share,
        Err(e) => return Err(e.to_string().into()),
    };

    let res = match verifier.verify(&share) {
        Ok(_) => true,
        Err(e) => return Err(e.to_string().into()), 
    };

    Ok(res)
}

/* COMBINE */
#[wasm_bindgen]
pub fn combine_secret(share_bytes: &[u8]) -> Result<Vec<u8>, JsValue> {
    let mut share_bound: Vec<Share> = Default::default();

    for i in 0..share_bytes.len()/ENCODED_SIZE {
        let sliced_share:[u8;ENCODED_SIZE] = match share_bytes[i*ENCODED_SIZE..(i+1)*ENCODED_SIZE].try_into() {
            Ok(sliced) => sliced,
            Err(e) => return Err(e.to_string().into()),
        };

        let share:Share = match serde_bare::from_slice(&sliced_share) {
            Ok(decoded) => decoded,
            Err(e) => return Err(e.to_string().into()),
        };

        share_bound.append(&mut [share].to_vec());
    }
    
    let res = combine_shares::<WrappedScalar>(&share_bound);
    let scalar = match res {
        Ok(wrap) => wrap,
        Err(e) =>  return Err(e.to_string().into()),
    };

    Ok(scalar.0.to_bytes().to_vec())
}

#[wasm_bindgen]
extern {
    fn alert(s: &str);
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

        let reconstructed_secret = combine_secret(&res[2*ENCODED_SIZE..shareslen]).unwrap();
        
        assert_eq!(reconstructed_secret,secret);
    }
}

