/*

This implements GCM primitives for TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 TLS-1.2 cipher suite

Wikipedia quote (https://en.wikipedia.org/wiki/Galois/Counter_Mode):

In cryptography, 0xGalois/Counter Mode (GCM) is a mode of operation for symmetric-key cryptographic [u8; 16] ciphers
widely adopted for its performance. GCM throughput rates for state-of-the-art, 0xhigh-speed communication channels
can be achieved with inexpensive hardware resources.[1] The operation is an authenticated encryption algorithm
designed to provide both data authenticity (integrity) and confidentiality. GCM is defined for [u8; 16] ciphers
with a [u8; 16] size of 128 bits. Galois Message Authentication Code (GMAC) is an authentication-only variant of
the GCM which can form an incremental message authentication code. Both GCM and GMAC can accept initialization
vectors of arbitrary length.

*/

use std::convert::TryInto;
pub use super::aes::AesCipher;
use rand::{thread_rng, Rng};
use array_init::array_init;
use std::time::Instant;
use colored::Colorize;

pub struct Gcm
{
    pub iv: [u8; 16],       // initialization vector
    pub key: [u8; 16],      // encryption key
    pub h: [u8; 16],        // hash key
    pub counter: [u8; 16],  // [u8; 16] counter
    pub cipher: AesCipher,  // symmetric cipher
}

impl Gcm
{
    pub fn create(key: [u8; 16], iv: [u8; 16]) -> Gcm
    {
        let cipher = AesCipher::create(key);
        Gcm
        {
            iv,
            key,
            h: cipher.encryptBlock([0; 16]),
            counter: [0; 16],
            cipher
        }
    }

    pub fn encrypt (&mut self, aad: &Vec<u8>, pt: &Vec<u8>) -> (Vec<u8>, [u8; 16])
    {
        let mut ct = Vec::<u8>::with_capacity(pt.len());
        let mut ht: [u8; 16] = [0; 16];

        for i in (0..aad.len()).step_by(16)
        {
            let b = if i+16 > aad.len()
            {
                let mut b = aad[i..aad.len()].to_vec();
                b.resize(16, 0);
                b
            } else {aad[i..i+16].to_vec()};

            let x = ht.iter().zip(b.iter()).map(|(h, b)| super::aes::xor2(*h, *b)).collect::<Vec<_>>();
            ht = mul(self.h, x[0..16].try_into().unwrap());
        }

        let ec = self.cipher.encryptBlock(self.counter);

        for i in (0..pt.len()).step_by(16)
        {
            self.incr();
            let ec = self.cipher.encryptBlock(self.counter);

            let mut et = pt[i .. if i+16 > pt.len() {pt.len()} else {i+16}].
                iter().zip(ec.iter()).map(|(p, c)| super::aes::xor2(*p, *c)).collect::<Vec<_>>();
            let mut etc = et.clone();
            ct.append(&mut et);

            etc.resize(16, 0);
            let x = ht.iter().zip(etc.iter()).map(|(h, e)| super::aes::xor2(*h, *e)).collect::<Vec<_>>();
            ht = mul(self.h, x[0..16].try_into().unwrap());
        }

        let sz: u128 = ((aad.len() as u128) << 64) | (pt.len() as u128);
        let x = ht.iter().zip(sz.to_le_bytes().iter()).map(|(h, e)| super::aes::xor2(*h, *e)).collect::<Vec<_>>();
        ht = mul(self.h, x[0..16].try_into().unwrap());
        ht = ht.iter().zip(ec.iter()).map(|(h, e)| super::aes::xor2(*h, *e)).collect::<Vec<_>>()[0..16].try_into().unwrap();

        (ct, ht)
    }

    pub fn decrypt (&mut self, aad: &Vec<u8>, ct: &Vec<u8>, at: [u8; 16]) -> Option<Vec<u8>>
    {
        let mut pt = Vec::<u8>::with_capacity(ct.len());
        let mut ht: [u8; 16] = [0; 16];

        for i in (0..aad.len()).step_by(16)
        {
            let b = if i+16 > aad.len()
            {
                let mut b = aad[i..aad.len()].to_vec();
                b.resize(16, 0);
                b
            } else {aad[i..i+16].to_vec()};

            let x = ht.iter().zip(b.iter()).map(|(h, b)| super::aes::xor2(*h, *b)).collect::<Vec<_>>();
            ht = mul(self.h, x[0..16].try_into().unwrap());
        }

        let ec = self.cipher.encryptBlock(self.counter);

        for i in (0..ct.len()).step_by(16)
        {
            self.incr();
            let ec = self.cipher.encryptBlock(self.counter);

            let mut ctc = ct[i .. if i+16 > pt.len() {ct.len()} else {i+16}].to_vec();
            let mut dt = ctc.iter().zip(ec.iter()).map(|(c, e)| super::aes::xor2(*c, *e)).collect::<Vec<_>>();
            pt.append(&mut dt);

            ctc.resize(16, 0);
            let x = ht.iter().zip(ctc.iter()).map(|(h, c)| super::aes::xor2(*h, *c)).collect::<Vec<_>>();
            ht = mul(self.h, x[0..16].try_into().unwrap());
        }

        let sz: u128 = ((aad.len() as u128) << 64) | (pt.len() as u128);
        let x = ht.iter().zip(sz.to_le_bytes().iter()).map(|(h, e)| super::aes::xor2(*h, *e)).collect::<Vec<_>>();
        ht = mul(self.h, x[0..16].try_into().unwrap());
        ht = ht.iter().zip(ec.iter()).map(|(h, e)| super::aes::xor2(*h, *e)).collect::<Vec<_>>()[0..16].try_into().unwrap();

        if ht == at {Some(pt)} else {None}
    }

    fn incr(&mut self)
    {
        let lower32: u32 = u32::from_le_bytes(self.counter[12..16].try_into().unwrap());
        self.counter[12..16].clone_from_slice(&(if lower32 == u32::MAX {0} else {lower32+1}).to_le_bytes());
    }

    pub fn reset(&mut self)
    {
        self.counter[12..16].clone_from_slice(&(0 as u32).to_le_bytes());
    }
}

pub fn mul_helper(x: [u8; 16], y: [u8; 16]) -> [u8; 16]
{
    let x: u128 = u128::from_le_bytes(x);
    let y: u128 = u128::from_le_bytes(y);
    let r: u128 = 0xE1000000000000000000000000000000;
    let mut z: u128 = 0;
    let mut v = x;

    for i in 0..128
    {
        if y & (1<<(127-i)) != 0 {z ^= v}
        v = (v >> 1) ^ if v & 1 == 0 {0} else {r}
    }
    z.to_le_bytes()
}

pub fn mul(x: [u8; 16], y: [u8; 16]) -> [u8; 16]
{
    mul_helper(x, y)
}

pub static mut MUL: [u128; 0x10000] = [0; 0x10000];
