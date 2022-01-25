mod utils;
pub mod elgamal;
pub mod elgamal_utils;
pub mod tx_sign;
pub mod wallet;

use wasm_bindgen::prelude::*;

// When the `wee_alloc` feature is enabled, use `wee_alloc` as the global
// allocator.
#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

#[wasm_bindgen]
extern {
    fn alert(s: &str);
}

#[wasm_bindgen]
pub fn greet() {
    alert("Hello, time_capsule_wallet!");
}

//send transaction export function for js
#[wasm_bindgen]
pub fn send_transaction(last_block:&str,public_key:&str,private_key:&str,lock_time:&str,msg:&str)->String{
    let res = wallet::send_transaction(public_key, private_key, public_key, &"1", &msg, lock_time,last_block);
    return res;
}