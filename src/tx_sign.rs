use k256::{
    ecdsa::{SigningKey, Signature,signature::RandomizedSigner,VerifyingKey},
};
use hex::FromHex;
use rand_core::OsRng;
// sign data with private_key sha256 & ecdsa
pub fn sign_ecdsa_data(private_key:&str,data:&str) -> String{
    let a: Vec<u8> = Vec::from_hex(private_key).expect("Invalid Hex String");
    let sign_key = SigningKey::from_bytes(&a).unwrap();

    let signature: Signature = sign_key.sign_with_rng(&mut OsRng,data.as_bytes());
    base64::encode(signature)
}

//TODO: verifying key from public key
pub fn validate_signature(pub_key:&str, _signature:&str, _data:&str){
    let pubkey = base64::decode(pub_key).unwrap();
    match VerifyingKey::from_sec1_bytes(&pubkey){
        Ok(res)=>println!("~~~~~~~~~~~~~~~~~~~{:?}",res),
        Err(error)=>println!("{:?}",error)
    };
}