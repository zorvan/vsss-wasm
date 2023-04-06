use wasm_bindgen_test::*;
use vsss_wasm::*;

#[wasm_bindgen_test]
fn full_test() {
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


