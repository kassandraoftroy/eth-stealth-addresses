use rand;
use k256;
use stealth_addresses::{
    get_pubkey_from_priv,
    encode_priv,
    encode_pubkey,
    encode_stealth_meta_address,
    decode_priv,
    decode_pubkey,
    decode_stealth_meta_address,
    hexlify,
    check_stealth_address,
    check_stealth_address_fast,
    compute_stealth_key,
    generate_stealth_address
};

#[test]
fn test_functions() {
    // setup
    let mut rng = rand::thread_rng();
    let spending_key_scalar = k256::Scalar::generate_biased(&mut rng);
    let viewing_key_scalar = k256::Scalar::generate_biased(&mut rng);
    let spending_pubkey_point = get_pubkey_from_priv(spending_key_scalar);
    let viewing_pubkey_point = get_pubkey_from_priv(viewing_key_scalar);

    // test encode
    let stealth_meta_address =
        encode_stealth_meta_address(spending_pubkey_point, viewing_pubkey_point);
    let spending_key = encode_priv(spending_key_scalar);
    let viewing_key = encode_priv(viewing_key_scalar);
    let spending_pubkey = encode_pubkey(spending_pubkey_point);
    let viewing_pubkey = encode_pubkey(viewing_pubkey_point);

    // test decode
    let (spending_pk_point_check, viewng_pk_point_check) =
        decode_stealth_meta_address(&stealth_meta_address);
    let spending_sk_scalar_check = decode_priv(&spending_key);
    let spending_pk_point_check_2 = decode_pubkey(&spending_pubkey);
    let viewing_sk_scalar_check = decode_priv(&viewing_key);
    let viewng_pk_point_check_2 = decode_pubkey(&viewing_pubkey);
    assert_eq!(spending_pk_point_check, spending_pubkey_point);
    assert_eq!(viewng_pk_point_check, viewing_pubkey_point);
    assert_eq!(spending_sk_scalar_check, spending_key_scalar);
    assert_eq!(viewing_sk_scalar_check, viewing_key_scalar);
    assert_eq!(spending_pk_point_check_2, spending_pubkey_point);
    assert_eq!(viewng_pk_point_check_2, viewing_pubkey_point);

    // test
    let (stealth_address, ephemeral_pubkey, view_tag) =
        generate_stealth_address(&stealth_meta_address);

    // print
    println!("--- EXAMPLE ---");
    println!("steath address: 0x{}", hexlify(&stealth_address));
    println!("ephemeral pubkey: 0x{}", hexlify(&ephemeral_pubkey));
    println!("view tag: {}", view_tag);

    // check
    let check1 = check_stealth_address(
        &stealth_address,
        &ephemeral_pubkey,
        &viewing_key,
        &spending_pubkey,
    );
    let check2 = check_stealth_address_fast(
        &stealth_address,
        &ephemeral_pubkey,
        &viewing_key,
        &spending_pubkey,
        view_tag,
    );
    let check3 = check_stealth_address_fast(
        &stealth_address,
        &ephemeral_pubkey,
        &viewing_key,
        &spending_pubkey,
        view_tag + 1, // wrong
    );
    let check4 = check_stealth_address(
        &stealth_address,
        &ephemeral_pubkey,
        &spending_key, // wrong
        &spending_pubkey,
    );
    let stealth_key = compute_stealth_key(
        &stealth_address,
        &ephemeral_pubkey,
        &viewing_key,
        &spending_key,
    );
    assert_eq!(check1, true);
    assert_eq!(check2, true);
    assert_eq!(check3, false);
    assert_eq!(check4, false);

    println!("stealth key: {}", hexlify(&stealth_key));
}
