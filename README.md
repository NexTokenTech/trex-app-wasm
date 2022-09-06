#TREX-Demo-Wallet-Rust-WebAssembly
This repo provides WASM codes for decentralized timed-release encryption algorithms. This WASM code would be built into a package and run in browsers to support web applications.


### 🛠️ Build with `wasm-pack build`

```
wasm-pack build
```

### 🔬 Test in Headless Browsers with `wasm-pack test`

```
wasm-pack test --headless --firefox
```

### 🎁 Publish to NPM with `wasm-pack publish`

```
wasm-pack publish
```

## 🔋 Batteries Included

* [`wasm-bindgen`](https://github.com/rustwasm/wasm-bindgen) for communicating
  between WebAssembly and JavaScript.
* [`console_error_panic_hook`](https://github.com/rustwasm/console_error_panic_hook)
  for logging panic messages to the developer console.
* [`wee_alloc`](https://github.com/rustwasm/wee_alloc), an allocator optimized
  for small code size.

## 🎆 Folder Description

* [`lib`] wasm interface
* [`elgamal`] public_key & private_key，encrypt with pubkey
* [`elgamal_utils`] some algorithms for generating public_key
* [`mt_utils`] mt19937 random Variant algorithm utils
* [`tx_sign`] sign tx with Sha256 & ecdsa
* [`utils`] system generate utils for panic!
* [`wallet`] Wallet core class, contain send_transaction function
