use eth_stealth_addresses::{
    check_stealth_address,
    check_stealth_address_fast,
    compute_stealth_key,
    generate_stealth_address,
    generate_stealth_meta_address,
    get_pubkey_from_priv,
    get_address_from_pubkey,
    split_stealth_meta_address,
    encode_priv,
    encode_pubkey,
    encode_stealth_meta_address,
    decode_priv,
    decode_pubkey,
    decode_stealth_meta_address,
};

#[test]
fn test_encode_decode() {
    // setup
    let (stealth_meta_address, spending_key, viewing_key) = generate_stealth_meta_address();

    // test
    let spending_key_scalar = decode_priv(&spending_key);
    let viewing_key_scalar = decode_priv(&viewing_key);
    let spending_pubkey_point = get_pubkey_from_priv(spending_key_scalar);
    let viewing_pubkey_point = get_pubkey_from_priv(viewing_key_scalar);
    let spending_key_check = encode_priv(spending_key_scalar);
    let viewing_key_check = encode_priv(viewing_key_scalar);
    let stealth_meta_address_check =
        encode_stealth_meta_address(spending_pubkey_point, viewing_pubkey_point);
    let (spending_pk_point_check, viewing_pk_point_check) =
        decode_stealth_meta_address(&stealth_meta_address);
    assert_eq!(spending_key_check, spending_key);
    assert_eq!(viewing_key_check, viewing_key);
    assert_eq!(stealth_meta_address_check, stealth_meta_address);
    assert_eq!(spending_pk_point_check, spending_pubkey_point);
    assert_eq!(viewing_pk_point_check, viewing_pubkey_point);

    let spending_pubkey = encode_pubkey(spending_pubkey_point);
    let viewing_pubkey = encode_pubkey(viewing_pubkey_point);
    let spending_pk_point_check_2 = decode_pubkey(&spending_pubkey);
    let viewing_pk_point_check_2 = decode_pubkey(&viewing_pubkey);
    assert_eq!(spending_pk_point_check_2, spending_pubkey_point);
    assert_eq!(viewing_pk_point_check_2, viewing_pubkey_point);

    let (spending_pubkey_check, viewing_pubkey_check) = split_stealth_meta_address(&stealth_meta_address);
    assert_eq!(spending_pubkey_check, spending_pubkey);
    assert_eq!(viewing_pubkey_check, viewing_pubkey);
}

#[test]
fn test_check_stealth_address() {
    // setup
    let (stealth_meta_address, spending_key, viewing_key) = generate_stealth_meta_address();

    let (stealth_address, ephemeral_pubkey, view_tag) =
        generate_stealth_address(&stealth_meta_address);

    let (spending_pubkey, viewing_pubkey) = split_stealth_meta_address(&stealth_meta_address);

    // test
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
    assert_eq!(check1, true);
    assert_eq!(check2, true);

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
    let check5 = check_stealth_address(
        &stealth_address,
        &ephemeral_pubkey,
        &viewing_key,
        &viewing_pubkey, // wrong
    );
    assert_eq!(check3, false);
    assert_eq!(check4, false);
    assert_eq!(check5, false);
}

#[test]
fn test_compute_stealth_key() {
    // setup
    let (stealth_meta_address, spending_key, viewing_key) = generate_stealth_meta_address();

    let (stealth_address, ephemeral_pubkey, _) =
        generate_stealth_address(&stealth_meta_address);

    // test
    let stealth_key = compute_stealth_key(
        &stealth_address,
        &ephemeral_pubkey,
        &viewing_key,
        &spending_key,
    );

    let stealth_address_check = get_address_from_pubkey(get_pubkey_from_priv(decode_priv(&stealth_key)));
    assert_eq!(stealth_address_check, stealth_address);
}

#[test]
#[should_panic(expected = "keys do not generate stealth address")]
fn test_stealth_key_panic() {
    // setup
    let (stealth_meta_address, _, viewing_key) = generate_stealth_meta_address();

    let (stealth_address, ephemeral_pubkey, _) =
        generate_stealth_address(&stealth_meta_address);

    // test
    let _ = compute_stealth_key(
        &stealth_address,
        &ephemeral_pubkey,
        &viewing_key,
        &viewing_key, //wrong
    );
}