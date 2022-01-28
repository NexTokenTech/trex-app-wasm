use serde_json::json;
use crate::{alert, tx_sign};
use serde_json::{Value};
use std::str;
use num::{ToPrimitive};
use elgamal_capsule::elgamal::*;

const BLOCK_TIME:u32 = 30;

pub fn send_transaction(addr_from:&str, private_key:&str, addr_to:&str, amount:&str, msg:&str, lock_time:&str, last_block_slice:&str) -> String {
    return if private_key.len() == 64 {
        alert("private_key is right,wait a moment to encrypt message for transaction.");

        // Json for encrypt
        let data = json!({
            "addr_from": addr_from,
            "addr_to": addr_to,
            "amount": amount
        });

        // Json for mutation
        let mut data_map = json!({
            "addr_from": addr_from,
            "addr_to": addr_to,
            "amount": amount
        });

        let json_str = data.to_string();

        // when sign and verify is completed,will unlock this function
        let sig = tx_sign::sign_ecdsa_data(&private_key, &json_str);
        data_map["signature"] = Value::String(sig);

        //parse lock_time string to u32
        if msg.len() > 0{
            let lock_time_num: u32 = lock_time.parse().unwrap();
            // Parsing JSON string
            let s = match str::from_utf8(&last_block_slice.as_bytes()) {
                Ok(v) => v,
                Err(e) => panic!("Invalid UTF-8 sequence: {}", e),
            };
            let last_block: Value = serde_json::from_str(s).unwrap();

            // Fetch last block's public_key and generate seed for next public_key
            let pubkey_str = &last_block["public_key"].to_string().replace("\"", "");
            let pubkey = PublicKey::from_hex_str(&pubkey_str);
            let seed = pubkey.p + pubkey.g + pubkey.h;

            // Generate new public_key with seed
            let pubkey_turple = generate_pub_key(&seed, 32, 32);
            let pubkey = pubkey_turple.0;

            // Printer for new public_key
            pubkey.print_parameter();

            let block_interval = lock_time_num / BLOCK_TIME;
            let mut fpubkey = pubkey;
            // if block_interval == 1 then you should only use public_key generate before
            if block_interval == 1 {
                let mut rng: mt19937::MT19937 = pubkey_turple.1;
                let result = encrypt(&fpubkey, &msg, &mut rng);

                let release_block_idx = (&last_block["height"].as_u64().unwrap() + block_interval.to_u64().unwrap()).to_string();
                data_map["release_block_idx"] = Value::String(release_block_idx);
                data_map["cipher"] = Value::String(result);
                return data_map.to_string();
            } else {
                if block_interval <= 0 {
                    alert("Time release period is too short, please choose another time");
                    return "{}".to_string();
                }
                // because a public_key is generated already, so the range is >0 and <= block_interval-1
                for idx in 0..block_interval - 1 {
                    let new_seed = fpubkey.p + fpubkey.g + fpubkey.h;
                    let pub_tuple = generate_pub_key(&new_seed, fpubkey.bit_length, 32);
                    fpubkey = pub_tuple.0;
                    let mut rng: mt19937::MT19937 = pub_tuple.1;
                    // if generate the dest block's public_key,then you should encrypt message
                    if idx == block_interval - 2 {
                        let result = encrypt(&fpubkey, &msg, &mut rng);
                        println!("signed msg is:{}", result);
                        let release_block_idx = (&last_block["height"].as_u64().unwrap() + block_interval.to_u64().unwrap()).to_string();
                        data_map["release_block_idx"] = Value::String(release_block_idx);
                        data_map["cipher"] = Value::String(result);
                        return data_map.to_string();
                    }
                }
            }
        }else{
            return data_map.to_string();
        }
        return "{}".to_string();
    } else {
        alert("private key is error");
        println!("Wrong address or key length! Verify and try again");
        "{}".to_string()
    }
}