use crate::elgamal_utils;
use crate::mt_utils;
use num::bigint::BigInt;
use encoding::{Encoding, EncoderTrap};
use encoding::all::UTF_16LE;
use num::BigUint;


#[derive(Debug)]
pub struct PublicKey {
    pub p: BigInt,
    pub g: BigInt,
    pub h: BigInt,
    pub bit_length: u32,
    /*Init public key structure for elgamal encryption.

        Args:
            p: a large prime number
            g: a generator
            h:
            bit_length: bit length of the prime number
        */
}

#[derive(Debug)]
pub struct PrivateKey {
    pub p: BigInt,
    pub g: BigInt,
    pub x: BigInt,
    /*Init private key structure for elgamal encryption.

        Args:
            p: a large prime number
            g: a generator
            x: a randomly chosen key
            bit_length: bit length of the prime number
        */
}

impl PublicKey {
    //print public_key's p、g、h
    pub fn print_parameter(&self) {
        println!("_____________");
        println!("p:{}", self.p);
        println!("g:{}", self.g);
        println!("h:{}", self.h);
    }
    //Generate a public key from string.
    pub fn from_hex_str(key_str:&str)->PublicKey{
        let keys:Vec<_> = key_str.split(", ").collect();
        println!("keys~~~~~~~~~~~~~~~~{:?}",keys);
        if keys.len() < 3{
            println!("The input string is not valid")
        }
        let p = BigInt::from(BigUint::parse_bytes(keys[0].replace("0x", "").as_bytes(), 16).unwrap());
        let g = BigInt::from(BigUint::parse_bytes(keys[1].replace("0x", "").as_bytes(), 16).unwrap());
        let h = BigInt::from(BigUint::parse_bytes(keys[2].replace("0x", "").as_bytes(), 16).unwrap());
        let bit_length = keys[3].parse::<u32>().unwrap();
        PublicKey{
            p,
            g,
            h,
            bit_length
        }
    }
}

//generate public_key with seed、bit_length、i_confidence
pub fn generate_pub_key(seed: &BigInt, bit_length: u32, i_confidence: u32) -> (PublicKey,mt_utils::MT19937) {
    /*
    Generates public key K1 (p, g, h) and private key K2 (p, g, x).

    Args:
        seed:
        bit_length:
        i_confidence:

    Returns:

     p is the prime
     g is the primitive root
     x is random in (0, p-1) inclusive
     h = g ^ x mod p
     */
    let key = seed.to_u32_digits();
    let mut rng: mt_utils::MT19937 = mt_utils::MT19937::new_with_slice_seed(&key.1);
    let val = elgamal_utils::random_prime_bigint(bit_length, i_confidence, &mut rng);
    let mut rng: mt_utils::MT19937 = mt_utils::MT19937::new_with_slice_seed(&key.1);
    let val1 = elgamal_utils::find_primitive_root_bigint(&val,&mut rng);
    let mut rng: mt_utils::MT19937 = mt_utils::MT19937::new_with_slice_seed(&key.1);
    let val2 = elgamal_utils::find_h_bigint(&val,&mut rng);
    let pubkey: PublicKey = PublicKey {
        p: val,
        g: val1,
        h: val2,
        bit_length: bit_length,
    };
    println!("p:{}~~~~~~~~g:{}~~~~~~~~~~~h:{}",pubkey.p,pubkey.g,pubkey.h);
    (pubkey,rng)
}

pub fn encrypt<R: rand_core::RngCore>(key:&PublicKey,s_plaintext:&str,rng:&mut R) -> String{
    /*Encrypts a string using the public key k.

    Args:
        key: public key for encryption
        s_plaintext: input message string

    Returns:
        Encrypted text string.
    */
    let z = encode_utf16(s_plaintext, key.bit_length);
    // cipher_pairs list will hold pairs (c, d) corresponding to each integer in z
    let mut cipher_pairs = vec!();
    // i is an integer in z
    for i_code in z{
        // pick random y from (0, p-1) inclusive
        let y = mt_utils::gen_bigint_range(rng, &elgamal_utils::to_bigint_from_int(0), &(&key.p));
        // c = g^y mod p
        let c = key.g.modpow(&y, &key.p);
        // d = ih^y mod p
        let d = (&i_code * key.h.modpow(&y, &key.p)) % &key.p;
        // add the pair to the cipher pairs list
        let mut arr:Vec<BigInt> = Vec::new();
        arr.push(c);
        arr.push(d);
        cipher_pairs.push(arr);
    }
    let mut encrypted_str = "".to_string();
    for pair in cipher_pairs{
        let pair_one = pair[0].to_str_radix(10).to_string();
        let pair_two = pair[1].to_str_radix(10).to_string();
        let space = " ".to_string();

        encrypted_str += &pair_one;
        encrypted_str += &space;
        encrypted_str += &pair_two;
        encrypted_str += &space;
    }
    encrypted_str
}

pub fn encode_utf16(s_plaintext:&str,bit_length:u32) -> Vec<BigInt>{
    /*Encodes bytes to integers mod p.
    Example
    if n = 24, k = n / 8 = 3
    z[0] = (summation from i = 0 to i = k)m[i]*(2^(8*i))
    where m[i] is the ith message byte

    Args:
        s_plaintext: String text to be encoded
        bit_length: bit length of the prime number

    Returns:
        A list of encoded integers
    */
    let mut byte_array:Vec<u8> = UTF_16LE.encode(s_plaintext, EncoderTrap::Strict).unwrap();
    byte_array.insert(0, 254);
    byte_array.insert(0, 255);

    // z is the array of integers mod p
    let mut z:Vec<BigInt> = vec![];
    // each encoded integer will be a linear combination of k message bytes
    // k must be the number of bits in the prime divided by 8 because each
    // message byte is 8 bits long
    let k:isize = (bit_length / 8) as isize;
    // j marks the jth encoded integer
    // j will start at 0 but make it -k because j will be incremented during first iteration
    let mut j:isize = -1  * k;
    // num is the summation of the message bytes
    // num = 0
    // i iterates through byte array
    for idx in 0..byte_array.len(){
        // if i is divisible by k, start a new encoded integer
        if idx as isize % k == 0{
            j += k;
            // num = 0
            z.push(elgamal_utils::to_bigint_from_int(0));
        }
        let index:usize = (j / k) as usize;
        let base:BigInt = elgamal_utils::to_bigint_from_int(2);
        let mi:u32 = (8*(idx as isize % k)) as u32;
        // add the byte multiplied by 2 raised to a multiple of 8
        z[index] += elgamal_utils::to_bigint_from_int(byte_array[idx] as i64) * base.pow(mi);
    }
    z
}