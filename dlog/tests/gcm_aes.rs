mod gcm;

use self::gcm::{aes::*, gcm::*};
use rand::{thread_rng, Rng};
use std::time::Instant;
use colored::Colorize;

#[test]
fn aes()
{
    let rng = &mut thread_rng();
    for x in 0..256
    {
        for y in 0..256
        {
            unsafe {XOR[y | (x << 8)] = (x as u8) ^ (y as u8)}
        }
    }

    let key: u128 = rng.gen();
    let cipher = AesCipher::create(key.to_le_bytes());

    let start = Instant::now();
    for _ in 0..1000
    {
        let mut pt1 = (0..10000).map(|_| {let x: u8 = rng.gen(); x}).collect::<Vec<u8>>();

        let ct1 = cipher.encrypt(&pt1);
        let pt2 = cipher.decrypt(&ct1);

        let ct2 = cipher.encrypt(&pt2);
        pt1 = cipher.decrypt(&ct2);

        assert_eq!(pt1, pt2);
        assert_eq!(ct1, ct2);
    }
    println!("{}{:?}", "Execution time: ".yellow(), start.elapsed());
}

#[test]
fn gcm()
{
    // init GF(2^8) XOR and GF(2^128) multiplication tables
    for x in 0..256
    {
        for y in 0..256
        {
            unsafe {XOR[y | (x << 8)] = (x as u8) ^ (y as u8)}
            unsafe {MUL[y | (x << 8)] =
            {
                let mut xx: [u8; 16] = [0; 16]; xx[0] = x as u8;
                let mut yy: [u8; 16] = [0; 16]; yy[0] = y as u8;
                u128::from_le_bytes(mul_helper(xx, yy))
            }}
        }
    }

    let rng = &mut thread_rng();
    let iv: u128 = rng.gen();
    let key: u128 = rng.gen();
    let mut cipher = Gcm::create(key.to_le_bytes(), iv.to_le_bytes());

    let start = Instant::now();
    for _ in 0..1000
    {
        let aad1 = (0..3000).map(|_| {let x: u8 = rng.gen(); x}).collect::<Vec<u8>>();
        let aad2 = (0..3070).map(|_| {let x: u8 = rng.gen(); x}).collect::<Vec<u8>>();
        let mut pt1 = (0..10000).map(|_| {let x: u8 = rng.gen(); x}).collect::<Vec<u8>>();

        cipher.reset();
        let (ct1, at1) = cipher.encrypt(&aad1, &pt1);
        cipher.reset();
        let pt2 = cipher.decrypt(&aad1, &ct1, at1).unwrap();

        cipher.reset();
        let (ct2, at2) = cipher.encrypt(&aad2, &pt2);
        cipher.reset();
        pt1 = cipher.decrypt(&aad2, &ct2, at2).unwrap();

        assert_eq!(pt1, pt2);
        assert_eq!(ct1, ct2);
    }
    println!("{}{:?}", "Execution time: ".yellow(), start.elapsed());
}

/* This uses aes-gcm Rust crate implementing GCM primitives */

use aes_gcm::Aes256Gcm;
use aes_gcm::aead::{Aead, NewAead, generic_array::GenericArray};

#[test]
fn cipher()
{
    let key = GenericArray::from_slice(b"an example very very secret key.");
    let cipher = Aes256Gcm::new(key);

    let nonce = GenericArray::from_slice(b"unique nonce"); // 96-bits; unique per message

    let ciphertext = cipher.encrypt(nonce, b"plaintext message".as_ref())
        .expect("encryption failure!"); // NOTE: handle this error to avoid panics!
    
    let plaintext = cipher.decrypt(nonce, ciphertext.as_ref())
        .expect("decryption failure!"); // NOTE: handle this error to avoid panics!

    if plaintext.len() < 3 {panic!("visla")}
    
    assert_eq!(&plaintext, b"plaintext message");
}
