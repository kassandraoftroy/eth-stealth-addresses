use k256;
use rand;
use sha3::{Digest, Keccak256};
use k256::elliptic_curve::group::GroupEncoding;
use hex;
use secp256k1::PublicKey;
use generic_array::GenericArray;


fn main() {
    // setup
    let mut rng = rand::thread_rng();
    let spending_key_scalar = k256::Scalar::generate_biased(&mut rng);
    let viewing_key_scalar = k256::Scalar::generate_biased(&mut rng);
    let spending_pubkey_point = get_pubkey_from_priv(spending_key_scalar);
    let viewing_pubkey_point = get_pubkey_from_priv(viewing_key_scalar);

    // test encode
    let stealth_meta_address = encode_stealth_meta_address(spending_pubkey_point, viewing_pubkey_point);
    let spending_key = encode_scalar(spending_key_scalar);
    let viewing_key = encode_scalar(viewing_key_scalar);
    let spending_pubkey = encode_pubkey(spending_pubkey_point);
    let viewing_pubkey = encode_pubkey(viewing_pubkey_point);
    
    // test decode
    let (spending_pk_point_check, viewng_pk_point_check) = decode_stealth_meta_address(&stealth_meta_address);
    let spending_sk_scalar_check = decode_scalar(&spending_key);
    let spending_pk_point_check_2 = decode_pubkey(&spending_pubkey);
    let viewing_sk_scalar_check = decode_scalar(&viewing_key);
    let viewng_pk_point_check_2 = decode_pubkey(&viewing_pubkey);
    assert_eq!(spending_pk_point_check, spending_pubkey_point);
    assert_eq!(viewng_pk_point_check, viewing_pubkey_point);
    assert_eq!(spending_sk_scalar_check, spending_key_scalar);
    assert_eq!(viewing_sk_scalar_check, viewing_key_scalar);
    assert_eq!(spending_pk_point_check_2, spending_pubkey_point);
    assert_eq!(viewng_pk_point_check_2, viewing_pubkey_point);

    // test
    let (stealth_address, ephemeral_pubkey, view_tag) = generate_stealth_address(&stealth_meta_address);

    // print
    println!("--- EXAMPLE ---");
    println!("steath address: 0x{}", hexlify(&stealth_address));
    println!("ephemeral pubkey: 0x{}", hexlify(&ephemeral_pubkey));
    println!("view tag: {}", view_tag);

    // check
    let check1 = check_stealth_address(&stealth_address, &ephemeral_pubkey, &viewing_key, &spending_pubkey);
    let check2 = check_stealth_address_fast(&stealth_address, &ephemeral_pubkey, &viewing_key, &spending_pubkey, view_tag);
    let check3 = check_stealth_address_fast(&stealth_address, &ephemeral_pubkey, &viewing_key, &spending_pubkey, view_tag+1);
    let check4 = check_stealth_address(&stealth_address, &ephemeral_pubkey, &spending_key, &spending_pubkey);
    let stealth_key = compute_stealth_key(&stealth_address, &ephemeral_pubkey, &viewing_key, &spending_key);
    assert_eq!(check1, true);
    assert_eq!(check2, true);
    assert_eq!(check3, false);
    assert_eq!(check4, false);

    println!("stealth key: {}", hexlify(&stealth_key));
}

fn generate_stealth_address(    
    stealth_meta_address: &[u8; 66],
) -> ([u8; 20], [u8; 33], u8) {
    let r = k256::Scalar::generate_biased(&mut rand::thread_rng());
    let (spend_pk_point, view_pk_point) = decode_stealth_meta_address(stealth_meta_address);
    let (stealth_pk_point, view_tag) = get_stealth_pubkey(spend_pk_point, view_pk_point, r);
    let stealth_address = get_address_from_pubkey(stealth_pk_point);
    let ephemeral_pubkey = encode_pubkey(get_pubkey_from_priv(r));

    (stealth_address, ephemeral_pubkey, view_tag)
}

fn check_stealth_address(
    stealth_address: &[u8; 20],
    ephemeral_pubkey: &[u8; 33],
    viewing_key: &[u8; 32],
    spending_pubkey: &[u8; 33]
) -> bool {
    let (shared_secret, _) = get_shared_secret(decode_pubkey(&ephemeral_pubkey), decode_scalar(&viewing_key));
    let check = get_address_from_pubkey(decode_pubkey(&spending_pubkey)+get_pubkey_from_priv(shared_secret));

    return check==*stealth_address;
}

fn check_stealth_address_fast(
    stealth_address: &[u8; 20],
    ephemeral_pubkey: &[u8; 33],
    viewing_key: &[u8; 32],
    spending_pubkey: &[u8; 33],
    view_tag: u8
) -> bool {
    let (shared_secret, view_tag_check) = get_shared_secret(decode_pubkey(&ephemeral_pubkey), decode_scalar(&viewing_key));
    if view_tag_check == view_tag {
        let check = get_address_from_pubkey(decode_pubkey(&spending_pubkey)+get_pubkey_from_priv(shared_secret));

        return check==*stealth_address;
    } else {
        return false;
    }
}

fn compute_stealth_key(
    stealth_address: &[u8; 20],
    ephemeral_pubkey: &[u8; 33],
    viewing_key: &[u8; 32],
    spending_key: &[u8; 32],
) -> [u8; 32] {
    let (shared_secret, _) = get_shared_secret(decode_pubkey(&ephemeral_pubkey), decode_scalar(&viewing_key));
    let stealth_key_scalar = shared_secret+decode_scalar(&spending_key);
    let stealth_address_check = get_address_from_pubkey(get_pubkey_from_priv(stealth_key_scalar));
    if stealth_address_check != *stealth_address {
        panic!("stealth key does not match stealth address (spend/view keys are not recipient)");
    }
    return encode_scalar(stealth_key_scalar);
}

fn get_stealth_pubkey(
    pks: k256::ProjectivePoint,
    pkv: k256::ProjectivePoint,
    r: k256::Scalar
) -> (k256::ProjectivePoint, u8) {
    let (shared_secret, view_tag) = get_shared_secret(pkv, r);
    let stealth_pub = pks+get_pubkey_from_priv(shared_secret);

    (stealth_pub, view_tag)
}

fn get_shared_secret(
    pubkey: k256::ProjectivePoint,
    k: k256::Scalar
) -> (k256::Scalar, u8) {
    let shared_secret_raw = pubkey*k;
    let mut hasher = Keccak256::new();
    hasher.update(shared_secret_raw.to_bytes());
    let hashed_s = hasher.finalize();
    let result = k256::elliptic_curve::scalar::ScalarPrimitive::from_slice(&hashed_s);
    let primitive = match result {
        Ok(val) => val,
        Err(error) => panic!("problem generating scalar: {:?}", error),
    };
    
    return (k256::Scalar::from(primitive), hashed_s[0]);
}

fn encode_stealth_meta_address(pks: k256::ProjectivePoint, pkv: k256::ProjectivePoint) -> [u8; 66] {
    let b = [pks.to_bytes(), pkv.to_bytes()].concat();
    let arr: [u8; 66] = b.as_slice().try_into().unwrap();

    arr
}

fn decode_stealth_meta_address(encoded: &[u8; 66]) -> (k256::ProjectivePoint, k256::ProjectivePoint) {
    let mut front = encoded.to_vec();
    let back = front.split_off(33);
    let front_arr: [u8; 33] = front.as_slice().try_into().unwrap();
    let back_arr: [u8; 33] = back.as_slice().try_into().unwrap();

    return (decode_pubkey(&front_arr), decode_pubkey(&back_arr));
}

fn encode_pubkey(x: k256::ProjectivePoint) -> [u8; 33] {
    let b = x.to_bytes();
    let arr: [u8; 33] = b.as_slice().try_into().unwrap();

    arr
}

fn decode_pubkey(encoded: &[u8; 33]) -> k256::ProjectivePoint {
    return k256::ProjectivePoint::from_bytes(GenericArray::from_slice(encoded)).unwrap();
}

fn encode_scalar(x: k256::Scalar) -> [u8; 32] {
    let b = x.to_bytes();
    let arr: [u8; 32] = b.as_slice().try_into().unwrap();

    arr
}

fn decode_scalar(encoded: &[u8; 32]) -> k256::Scalar {
    let result = k256::elliptic_curve::scalar::ScalarPrimitive::from_slice(encoded);
    let primitive = match result {
        Ok(val) => val,
        Err(error) => panic!("problem generating scalar: {:?}", error),
    };
    return k256::Scalar::from(primitive);
}

fn get_pubkey_from_priv(x: k256::Scalar) -> k256::ProjectivePoint {
    return k256::ProjectivePoint::GENERATOR*x;
}

fn get_address_from_pubkey(pubkey: k256::ProjectivePoint) -> [u8; 20] {
    let result = PublicKey::from_slice(&pubkey.to_bytes());
    let pub_reformat = match result {
        Ok(val) => val,
        Err(error) => panic!("problem generating PublicKey: {:?}", error),
    };
    let pub_uncompressed = pub_reformat.serialize_uncompressed();
    let pub_hashable = strip_uncompressed_pubkey(&pub_uncompressed);
    let mut hasher = Keccak256::new();
    hasher.update(pub_hashable);
    let address_raw = hasher.finalize();
    let mut address_vec_long = address_raw.to_vec();
    let address_vec = address_vec_long.split_off(12);
    let address: [u8; 20] = address_vec.as_slice().try_into().unwrap();

    address
}

fn strip_uncompressed_pubkey(a: &[u8; 65]) -> [u8; 64] {
    let mut front = a.to_vec();
    let back = front.split_off(1);
    let arr: [u8; 64] = back.as_slice().try_into().unwrap();

    arr
}

fn hexlify(a: &[u8]) -> String {
    return hex::encode(a);
}
