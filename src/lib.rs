use rand;
use generic_array::GenericArray;
use k256;
use k256::elliptic_curve::group::GroupEncoding;
use secp256k1::PublicKey;
use sha3::{Digest, Keccak256};

type Address = [u8; 20];
type StealthMetaAddress = [u8; 66];
type PublicKeyUncompressed = [u8; 65];
type PublicKeyCompressed = [u8; 33];
type PrivateKey = [u8; 32];

pub fn generate_stealth_address(
    stealth_meta_address: &StealthMetaAddress,
) -> (Address, PublicKeyCompressed, u8) {
    let r = k256::Scalar::generate_biased(&mut rand::thread_rng());
    let (spend_pk_point, view_pk_point) = decode_stealth_meta_address(stealth_meta_address);
    let (stealth_pk_point, view_tag) = get_stealth_pubkey(spend_pk_point, view_pk_point, r);
    let stealth_address: Address = get_address_from_pubkey(stealth_pk_point);
    let ephemeral_pubkey: PublicKeyCompressed = encode_pubkey(get_pubkey_from_priv(r));

    (stealth_address, ephemeral_pubkey, view_tag)
}

pub fn check_stealth_address(
    stealth_address: &Address,
    ephemeral_pubkey: &PublicKeyCompressed,
    viewing_key: &PrivateKey,
    spending_pubkey: &PublicKeyCompressed,
) -> bool {
    let (shared_secret, _) = get_shared_secret(
        decode_pubkey(&ephemeral_pubkey),
        decode_priv(&viewing_key),
    );
    let check: Address = get_address_from_pubkey(
        decode_pubkey(&spending_pubkey) + get_pubkey_from_priv(shared_secret),
    );

    return check == *stealth_address;
}

pub fn check_stealth_address_fast(
    stealth_address: &Address,
    ephemeral_pubkey: &PublicKeyCompressed,
    viewing_key: &PrivateKey,
    spending_pubkey: &PublicKeyCompressed,
    view_tag: u8,
) -> bool {
    let (shared_secret, view_tag_check) = get_shared_secret(
        decode_pubkey(&ephemeral_pubkey),
        decode_priv(&viewing_key),
    );
    if view_tag_check == view_tag {
        let check = get_address_from_pubkey(
            decode_pubkey(&spending_pubkey) + get_pubkey_from_priv(shared_secret),
        );

        return check == *stealth_address;
    } else {
        return false;
    }
}

pub fn compute_stealth_key(
    stealth_address: &Address,
    ephemeral_pubkey: &PublicKeyCompressed,
    viewing_key: &PrivateKey,
    spending_key: &PrivateKey,
) -> PrivateKey {
    let (shared_secret, _) = get_shared_secret(
        decode_pubkey(&ephemeral_pubkey),
        decode_priv(&viewing_key),
    );
    let stealth_key_scalar = shared_secret + decode_priv(&spending_key);
    let stealth_address_check = get_address_from_pubkey(get_pubkey_from_priv(stealth_key_scalar));
    if stealth_address_check != *stealth_address {
        panic!("keys do not generate stealth address");
    }
    return encode_priv(stealth_key_scalar);
}

pub fn generate_stealth_meta_address() -> (StealthMetaAddress, PrivateKey, PrivateKey) {
    let rng = &mut rand::thread_rng();
    let s = k256::Scalar::generate_biased(rng);
    let v = k256::Scalar::generate_biased(rng);
    let pks = get_pubkey_from_priv(s);
    let pkv = get_pubkey_from_priv(v);

    return (encode_stealth_meta_address(pks, pkv), encode_priv(s), encode_priv(v));
}

pub fn split_stealth_meta_address(
    encoded: &StealthMetaAddress,
) -> (PublicKeyCompressed, PublicKeyCompressed) {
    let mut front = encoded.to_vec();
    let back = front.split_off(33);
    let front_arr = front.as_slice().try_into().unwrap();
    let back_arr = back.as_slice().try_into().unwrap();

    (front_arr, back_arr)
}

pub fn encode_stealth_meta_address(
    pks: k256::ProjectivePoint,
    pkv: k256::ProjectivePoint,
) -> StealthMetaAddress {
    let b = [pks.to_bytes(), pkv.to_bytes()].concat();
    let arr = b.as_slice().try_into().unwrap();

    arr
}

pub fn decode_stealth_meta_address(
    encoded: &StealthMetaAddress,
) -> (k256::ProjectivePoint, k256::ProjectivePoint) {
    let (front_arr, back_arr) = split_stealth_meta_address(encoded);

    return (decode_pubkey(&front_arr), decode_pubkey(&back_arr));
}

pub fn encode_pubkey(x: k256::ProjectivePoint) -> PublicKeyCompressed {
    let b = x.to_bytes();
    let arr = b.as_slice().try_into().unwrap();

    arr
}

pub fn decode_pubkey(encoded: &PublicKeyCompressed) -> k256::ProjectivePoint {
    return k256::ProjectivePoint::from_bytes(GenericArray::from_slice(encoded)).unwrap();
}

pub fn encode_priv(x: k256::Scalar) -> PrivateKey {
    let b = x.to_bytes();
    let arr: PrivateKey = b.as_slice().try_into().unwrap();

    arr
}

pub fn decode_priv(encoded: &PrivateKey) -> k256::Scalar {
    let result = k256::elliptic_curve::scalar::ScalarPrimitive::from_slice(encoded);
    let primitive = match result {
        Ok(val) => val,
        Err(error) => panic!("problem generating scalar: {:?}", error),
    };
    return k256::Scalar::from(primitive);
}

pub fn get_pubkey_from_priv(x: k256::Scalar) -> k256::ProjectivePoint {
    return k256::ProjectivePoint::GENERATOR * x;
}

pub fn get_address_from_pubkey(pubkey: k256::ProjectivePoint) -> Address {
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
    let address: Address = address_raw[12..].try_into().unwrap();

    address
}

fn strip_uncompressed_pubkey(a: &PublicKeyUncompressed) -> [u8; 64] {
    let arr: [u8; 64] = a[1..].try_into().unwrap();

    arr
}

fn get_stealth_pubkey(
    pks: k256::ProjectivePoint,
    pkv: k256::ProjectivePoint,
    r: k256::Scalar,
) -> (k256::ProjectivePoint, u8) {
    let (shared_secret, view_tag) = get_shared_secret(pkv, r);
    let stealth_pub = pks + get_pubkey_from_priv(shared_secret);

    (stealth_pub, view_tag)
}

fn get_shared_secret(pubkey: k256::ProjectivePoint, k: k256::Scalar) -> (k256::Scalar, u8) {
    let shared_secret_raw = pubkey * k;
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
