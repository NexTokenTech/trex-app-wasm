#![allow(clippy::unreadable_literal, clippy::upper_case_acronyms)]

use mt19937::MT19937;
use mt19937;
use num::bigint::{BigInt, BigUint, ToBigInt, Sign};
use num::traits::{Zero,One};
use num::Integer;

/** These real versions are due to Kaisuki, 2021/01/07 added */
pub fn gen_bigint_range<R: rand_core::RngCore>(
    rng: &mut R,
    start: &BigInt,
    stop: &BigInt,
) -> BigInt {
    let width: BigInt = stop + 1 - start;
    let k: u64 = width.bits(); // don't use (n-1) here because n can be 1
    let mut r: BigInt = getrandbits(rng, k as usize); // 0 <= r < 2**k
    while r >= width {
        r = getrandbits(rng, k as usize);
    }
    return start + r;
}

/// Return an integer with k random bits.
fn getrandbits<R: rand_core::RngCore>(rng: &mut R, k: usize) -> BigInt {
    if k == 0 {
        return BigInt::from_slice(Sign::NoSign, &[0]);
        // return Err(
        //     vm.new_value_error("number of bits must be greater than zero".to_owned())
        // );
    }

    // let mut rng = self.rng.lock();
    let mut k = k;
    let mut gen_u32 = |k| {
        let r = rng.next_u32();
        if k < 32 {
            r >> (32 - k)
        } else {
            r
        }
    };

    if k <= 32 {
        return gen_u32(k).into();
    }

    let words = (k - 1) / 32 + 1;
    let wordarray = (0..words)
        .map(|_| {
            let word = gen_u32(k);
            k = k.wrapping_sub(32);
            word
        })
        .collect::<Vec<_>>();

    let uint = BigUint::new(wordarray);
    // very unlikely but might as well check
    let sign = if uint.is_zero() {
        Sign::NoSign
    } else {
        Sign::Plus
    };
    BigInt::from_biguint(sign, uint)
}

#[allow(unused)]
pub fn random_prime_bigint(
    bit_length: u32,
    i_confidence: u32,
    r: &mut mt19937::MT19937,
) -> BigInt {
    /*Find a prime number p for elgamal public key.

        Args:
        bit_length: number of binary bits for the prime number.
        i_confidence:
        seed: random generator seed

    Returns:
        A prime number with requested length of bits in binary.*/
    let zero: BigInt = Zero::zero();
    //keep testing until one is found
    loop {
        let one: BigInt = One::one();
        let two: BigInt = &one + &one;
        // generate potential prime randomly
        let mut p = gen_prime(&bit_length, r);
        // make sure it is odd
        while p.mod_floor(&two) == zero {
            p = gen_prime(&bit_length, r);
        }
        // keep doing this if the solovay-strassen test fails
        while solovay_strassen(&p, i_confidence, r) != true {
            p = gen_prime(&bit_length, r);
            while p.mod_floor(&two) == zero {
                p = gen_prime(&bit_length, r);
            }
        }
        // if p is prime compute p = 2*p + 1
        // this step is critical to protect the encryption from Pohlig–Hellman algorithm
        // if p is prime, we have succeeded; else, start over
        p = p * two + one;
        if solovay_strassen(&p, i_confidence, r) == true {
            return p;
        }
    }
}

fn gen_prime(bit_length: &u32, r: &mut mt19937::MT19937) -> BigInt {
    let base: BigInt = to_bigint_from_int(2);
    let pow_num_low: BigInt = (bit_length - 2).to_bigint().unwrap();
    let pow_num_high: BigInt = (bit_length - 1).to_bigint().unwrap();
    let low = pow_bigint(&base, &pow_num_low);
    let high = pow_bigint(&base, &pow_num_high);
    let p: BigInt = gen_bigint_range(r, &low, &high);
    p
}

pub fn find_primitive_root_bigint(p: &BigInt,r: &mut mt19937::MT19937) -> BigInt {
    /*Finds a primitive root for prime p.
    This function was implemented from the algorithm described here:
    http://modular.math.washington.edu/edu/2007/spring/ent/ent-html/node31.html

    Args:
        p:
        seed:

    Returns:
        A primitive root for prime p.
    */
    // the prime divisors of p-1 are 2 and (p-1)/2 because
    // p = 2x + 1 where x is a prime
    let one: BigInt = One::one();
    let two: BigInt = &one + &one;
    if *p == two {
        return One::one();
    }
    let p1: BigInt = two;
    
    let p2: BigInt = (p - &one) / p1;
    let p3: BigInt = (p - &one) / &p2;
    let mut g;
    //test random g's until one is found that is a primitive root mod p
    loop {
        let range_num_low: BigInt = &one + &one;
        let range_num_high: BigInt = p - &one;
        g = gen_bigint_range(r, &range_num_low, &range_num_high);
        // g is a primitive root if for all prime factors of p-1, p[i]
        // g^((p-1)/p[i]) (mod p) is not congruent to 1
        if g.modpow(&p2, &p) != one {
            if g.modpow(&p3, &p) != one {
                return g;
            }
        }
    }
}

pub fn find_h_bigint(p: &BigInt,r: &mut mt19937::MT19937) -> BigInt {
    let one: BigInt = One::one();
    let range_num_low: BigInt = One::one();
    let range_num_high: BigInt = p - &one;
    let h = gen_bigint_range(r, &range_num_low, &range_num_high);
    h
}

pub fn solovay_strassen(num: &BigInt, i_confidence: u32, r: &mut MT19937) -> bool {
    // Solovay-strassen primality test.
    //     This function tests if num is prime.
    //     http://www-math.ucdenver.edu/~wcherowi/courses/m5410/ctcprime.html
    //
    //     Args:
    //     num: input integer
    // i_confidence:
    //
    //     Returns:
    // if pass the test
    // ensure confidence of t
    for _idx in 0..i_confidence {
        let one: BigInt = One::one();
        let high: BigInt = num - &one;
        // choose random a between 1 and n-2
        let a: BigInt = gen_bigint_range(r, &one, &high);

        let two: BigInt = &one +&one;
        // if a is not relatively prime to n, n is composite
        if a.gcd(num) > one {
            return false;
        }
        // declares n prime if jacobi(a, n) is congruent to a^((n-1)/2) mod n
        let jacobi_result: BigInt = jacobi(&a, num).mod_floor(num);
        let mi: BigInt = (num - &one) / &two;
        let pow_reulst: BigInt = a.modpow(&mi, num);
        if jacobi_result != pow_reulst {
            return false;
        }
    }
    // if there have been t iterations without failure, num is believed to be prime
    return true;
}

pub fn jacobi(a: &BigInt, n: &BigInt) -> BigInt {
    // Computes the jacobi symbol of a, n.
    //
    //     Args:
    //     a:
    //     n:
    //
    //     Returns:
    let bigint_0 = Zero::zero();
    let bigint_1 = One::one();//to_bigint_from_int(1);
    let bigint_2 = to_bigint_from_int(2);
    let bigint_r1 = to_bigint_from_int(-1);
    let bigint_3 = to_bigint_from_int(3);
    let bigint_4 = to_bigint_from_int(4);
    let bigint_5 = to_bigint_from_int(5);
    let bigint_7 = to_bigint_from_int(7);
    let bigint_8 = to_bigint_from_int(8);
    if a == &bigint_0 {
        if n == &bigint_1 {
            return bigint_1;
        } else {
            return bigint_0;
        }
    } else if a == &bigint_r1 { //property 1 of the jacobi symbol
        if n.mod_floor(&bigint_2) == bigint_0 {
            return bigint_1;
        } else {
            return bigint_r1;
        }
    } else if a == &bigint_1 {// if a == 1, jacobi symbol is equal to 1
        return bigint_1;
    } else if a == &bigint_2 {// property 4 of the jacobi symbol
        if (n.mod_floor(&bigint_8) == bigint_1) || (n.mod_floor(&bigint_8) == bigint_7) {
            return bigint_1;
        } else if (n.mod_floor(&bigint_8) == bigint_3) || (n.mod_floor(&bigint_8) == bigint_5) {
            return bigint_r1;
        } else {
            return bigint_0;
        }
    } else if a >= n { // property of the jacobi symbol ,if a = b mod n, jacobi(a, n) = jacobi( b, n )
        let tmp_a = a.mod_floor(n);
        return jacobi(&tmp_a, n);
    } else if a.mod_floor(&bigint_2) == bigint_0 {
        let tmp_a2 = a / &bigint_2;
        return jacobi(&bigint_2, n) * jacobi(&tmp_a2, n);
    } else {// law of quadratic reciprocity, if a is odd and a is co-prime to n
        if (a.mod_floor(&bigint_4) == bigint_3) && (n.mod_floor(&bigint_4) == bigint_3) {
            return bigint_r1 * jacobi(n, a);
        } else {
            return jacobi(n, a);
        }
    }
}

pub fn pow_mod_bigint(base: &BigInt, exponent: &BigInt, modulus: &BigInt) -> BigInt {
    let zero: BigInt = to_bigint_from_int(0);
    let one: BigInt = to_bigint_from_int(1);

    let mut result: BigInt = One::one();
    let mut e: BigInt = exponent.clone();
    let mut b: BigInt = base.clone();

    while e > zero {
        if &e & &one == one {
            result = (result * &b) % (*&modulus);
        }
        e = e >> 1;
        b = (&b * &b) % (*&modulus);
    }
    result
}

pub fn pow_bigint(base: &BigInt, exponent: &BigInt) -> BigInt {
    let zero: BigInt = Zero::zero();
    let one: BigInt = One::one();

    let mut result: BigInt = One::one();
    let mut e: BigInt = exponent.clone();
    let mut b: BigInt = base.clone();

    while e > zero {
        if &e & &one == one {
            result = result * &b;
        }
        e = e >> 1;
        b = &b * &b;
    }
    result
}

pub fn to_bigint_from_int(a: i64) -> BigInt {
    let output: BigInt = a.to_bigint().unwrap();
    output
}
pub fn to_bigint_from_uint(a: u64) -> BigInt {
    let output: BigInt = a.to_bigint().unwrap();
    output
}
