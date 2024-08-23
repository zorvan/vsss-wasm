//use console_error_panic_hook;

mod bindings;

use bindings::Guest;

//use wasm_bindgen::prelude::*;
use curve25519::WrappedRistretto;
use vsss_rs::{curve25519::WrappedScalar,curve25519_dalek::scalar::Scalar, *};
use rand::{rngs::OsRng, SeedableRng, RngCore};
use rand_chacha::ChaCha20Rng;

pub const SHARES_NUMBER:usize = 5;
pub const THRESHOLD:usize = 3;
pub const SECRET_SIZE:usize = 33;
pub const ENCODED_SIZE:usize = 34;

struct Component;

impl Guest for Component {
 /* GENERATE SECRET */
fn generatesecret() -> Result<Vec<u8>, String> {
    //console_error_panic_hook::set_once();

    let mut rng = ChaCha20Rng::from_entropy();
    let mut scalar_bytes = [0u8; 64];
    rng.fill_bytes(&mut scalar_bytes);
    let sc = Scalar::from_bytes_mod_order_wide(&scalar_bytes);
    
    Ok(sc.as_bytes().to_vec())
}

/* SPLIT */
 fn splitsecret(secret: Vec<u8>) -> Result<Vec<u8>, String> {
    
    let mut osrng = OsRng::default();
    
    let mut secret_bound: [u8; 32] = Default::default();

    secret_bound.copy_from_slice(&secret);

    let sk = Scalar::from_bytes_mod_order(secret_bound);

    let res = feldman::split_secret::<WrappedRistretto, u8, Vec<u8>>(THRESHOLD, SHARES_NUMBER, sk.into(), None, &mut osrng);
    //let res = shamir::split_secret::<WrappedScalar, u8, Vec<u8>>(THRESHOLD, SHARES_NUMBER, sk.into(), &mut osrng);
    //let res = pedersen::split_secret::<WrappedRistretto, u8, Vec<u8>>(THRESHOLD, SHARES_NUMBER, sk.into(), None, None, None, &mut osrng);

    let (shares, verifier) = match res {
        Ok(tuple) => tuple,
        Err(e) => return Err(e.to_string()),
    };

    let res = serde_bare::to_vec(&verifier);
    let mut v_bytes: Vec<u8> = match res {
        Ok(vbytes) => vbytes,
        Err(e) => return Err(e.to_string()),
    };

    let mut s_bytes: Vec<u8> = Vec::<u8>::new();

    for i in 0..shares.len() {
        let mut res = match serde_bare::to_vec(&shares[i]) {
            Ok(encoded) => encoded,
            Err(e) => return Err(e.to_string()),
        };

        s_bytes.append(&mut res);
    }
    
    s_bytes.append(&mut v_bytes);
    
    Ok(s_bytes)
}

/* VERIFY */
 fn verifysecret(share_bytes: Vec<u8>, verifier_bytes: Vec<u8>) -> Result<bool, String> {
    
    let res =
        serde_bare::from_slice::<Vec<WrappedRistretto>>(&verifier_bytes);

    let verifier = match res {
        Ok(fv) => fv,
        Err(e) => return Err(e.to_string().into()),
    };

    let share = match serde_bare::from_slice::<Vec<u8>>(&share_bytes) {
        Ok(share) => share,
        Err(e) => return Err(e.to_string().into()),
    };

    let res = match verifier.verify_share(&share) {
        Ok(_) => true,
        Err(e) => return Err(e.to_string().into()), 
    };

    Ok(res)
}

/* COMBINE */
 fn combinesecret(share_bytes: Vec<u8>) -> Result<Vec<u8>, String> {
    type Shares = Vec<Vec<u8>>;
    let mut share_bound: Shares = Default::default();

    for i in 0..share_bytes.len()/ENCODED_SIZE {
        let sliced_share:[u8;ENCODED_SIZE] = match share_bytes[i*ENCODED_SIZE..(i+1)*ENCODED_SIZE].try_into() {
            Ok(sliced) => sliced,
            Err(e) => return Err(e.to_string().into()),
        };

        let share:Vec<u8> = match serde_bare::from_slice(&sliced_share) {
            Ok(decoded) => decoded,
            Err(e) => return Err(e.to_string().into()),
        };

        share_bound.append(&mut [share].to_vec());
    }
    
    let res = combine_shares(&share_bound);

    let scalar: WrappedScalar = match res {
        Ok(wrap) => wrap,
        Err(e) =>  return Err(e.to_string().into()),
    };

    Ok(scalar.0.to_bytes().to_vec())
}

}

bindings::export!(Component with_types_in bindings);


/* TEST */
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        
        let secret = Component::generatesecret().unwrap();

        let result = Component::splitsecret(secret.clone());
        let res = result.unwrap();

        let shareslen = SHARES_NUMBER * ENCODED_SIZE;

        //let mut shares = res[0..shareslen].chunks(33);
        let verifier = &res[shareslen..res.len()];
        
        for i in 0..SHARES_NUMBER {
            let share = &res[i*ENCODED_SIZE..(i+1)*ENCODED_SIZE];
            let valid = Component::verifysecret(share.to_vec(), verifier.to_vec()).unwrap();
            assert!(valid);
        }

        let reconstructed_secret = Component::combinesecret(res[2*ENCODED_SIZE..shareslen].to_vec()).unwrap();
        
        assert_eq!(reconstructed_secret,secret);
    }
}

