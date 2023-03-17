use wasm_bindgen::prelude::*;
use vsss_rs::{
    curve25519::{WrappedEdwards, WrappedRistretto, WrappedScalar},
    Feldman, FeldmanVerifier, Pedersen, PedersenResult, PedersenVerifier, Shamir,
};
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::SecretKey;
use rand::rngs::OsRng;
use x25519_dalek::StaticSecret;
use hex;

#[wasm_bindgen]
pub fn split(secret: &[u8]) -> Result<Vec<u8>, JsValue> {
    
    //alert(&format!("input, {}!", hex::encode(secret.clone())));

    let mut osrng = OsRng::default();
    
    //alert(&format!("working-1!"));
    //alert(&format!("secret size = {}", secret.len()));
    
    let mut secret_bound: [u8; 32] = Default::default();
    //alert(&format!("working-2-1!"));

    secret_bound.copy_from_slice(&secret);
    //alert(&format!("working-2-2!"));

    let sk = Scalar::from_bytes_mod_order(secret_bound);
    //alert(&format!("working-2-3!"));

    let res = Feldman::<2, 3>::split_secret::<WrappedScalar, WrappedRistretto, OsRng, 33>(
        sk.into(),
        None,
        &mut osrng,
    );
    //alert(&format!("working-3!"));
    
    let (shares, verifier) = res.unwrap();

    for s in &shares {
        //alert(&format!("verify share, {}!", &verifier.verify(s).to_string()));
        verifier.verify(s);
    }
    
    let res = serde_cbor::to_vec(&verifier);
    let _v_bytes = res.unwrap();

    let res = serde_cbor::to_vec(&shares);
    let s_bytes = res.unwrap();

    Ok(s_bytes)
}

#[wasm_bindgen]
pub fn greet(name: &str) {
    alert(&format!("Hello, {}!", name));
}

#[wasm_bindgen]
extern {
    pub fn alert(s: &str);
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = split(&[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,240,241,242,243,244,245,246,247,248,249,250,251,252,253,254,255]);
        let binding = result.unwrap();
        let mut res = binding.chunks(32);
        
        for i in 0..4 {
            println!("share [{i}] = 0x{}",hex::encode(res.next().unwrap()));
        }
    }
}

