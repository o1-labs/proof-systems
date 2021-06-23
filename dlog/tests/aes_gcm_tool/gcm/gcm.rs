/*

This implements GCM primitives for TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 TLS-1.2 cipher suite

Wikipedia quote (https://en.wikipedia.org/wiki/Galois/Counter_Mode):

In cryptography, Galois/Counter Mode (GCM) is a mode of operation for symmetric-key cryptographic block ciphers
widely adopted for its performance. GCM throughput rates for state-of-the-art, high-speed communication channels
can be achieved with inexpensive hardware resources. The operation is an authenticated encryption algorithm
designed to provide both data authenticity (integrity) and confidentiality. GCM is defined for block ciphers
with a block size of 128 bits. Galois Message Authentication Code (GMAC) is an authentication-only variant of
the GCM which can form an incremental message authentication code. Both GCM and GMAC can accept initialization
vectors of arbitrary length.

*/

use std::convert::TryInto;
use array_init::array_init;
use super::aes::*;

pub static mut MUL: [u16; 0x100] =
[
    0x0000, 0x01c2, 0x0384, 0x0246, 0x0708, 0x06ca, 0x048c, 0x054e,
    0x0e10, 0x0fd2, 0x0d94, 0x0c56, 0x0918, 0x08da, 0x0a9c, 0x0b5e,
    0x1c20, 0x1de2, 0x1fa4, 0x1e66, 0x1b28, 0x1aea, 0x18ac, 0x196e,
    0x1230, 0x13f2, 0x11b4, 0x1076, 0x1538, 0x14fa, 0x16bc, 0x177e,
    0x3840, 0x3982, 0x3bc4, 0x3a06, 0x3f48, 0x3e8a, 0x3ccc, 0x3d0e,
    0x3650, 0x3792, 0x35d4, 0x3416, 0x3158, 0x309a, 0x32dc, 0x331e,
    0x2460, 0x25a2, 0x27e4, 0x2626, 0x2368, 0x22aa, 0x20ec, 0x212e,
    0x2a70, 0x2bb2, 0x29f4, 0x2836, 0x2d78, 0x2cba, 0x2efc, 0x2f3e,
    0x7080, 0x7142, 0x7304, 0x72c6, 0x7788, 0x764a, 0x740c, 0x75ce,
    0x7e90, 0x7f52, 0x7d14, 0x7cd6, 0x7998, 0x785a, 0x7a1c, 0x7bde,
    0x6ca0, 0x6d62, 0x6f24, 0x6ee6, 0x6ba8, 0x6a6a, 0x682c, 0x69ee,
    0x62b0, 0x6372, 0x6134, 0x60f6, 0x65b8, 0x647a, 0x663c, 0x67fe,
    0x48c0, 0x4902, 0x4b44, 0x4a86, 0x4fc8, 0x4e0a, 0x4c4c, 0x4d8e,
    0x46d0, 0x4712, 0x4554, 0x4496, 0x41d8, 0x401a, 0x425c, 0x439e,
    0x54e0, 0x5522, 0x5764, 0x56a6, 0x53e8, 0x522a, 0x506c, 0x51ae,
    0x5af0, 0x5b32, 0x5974, 0x58b6, 0x5df8, 0x5c3a, 0x5e7c, 0x5fbe,
    0xe100, 0xe0c2, 0xe284, 0xe346, 0xe608, 0xe7ca, 0xe58c, 0xe44e,
    0xef10, 0xeed2, 0xec94, 0xed56, 0xe818, 0xe9da, 0xeb9c, 0xea5e,
    0xfd20, 0xfce2, 0xfea4, 0xff66, 0xfa28, 0xfbea, 0xf9ac, 0xf86e,
    0xf330, 0xf2f2, 0xf0b4, 0xf176, 0xf438, 0xf5fa, 0xf7bc, 0xf67e,
    0xd940, 0xd882, 0xdac4, 0xdb06, 0xde48, 0xdf8a, 0xddcc, 0xdc0e,
    0xd750, 0xd692, 0xd4d4, 0xd516, 0xd058, 0xd19a, 0xd3dc, 0xd21e,
    0xc560, 0xc4a2, 0xc6e4, 0xc726, 0xc268, 0xc3aa, 0xc1ec, 0xc02e,
    0xcb70, 0xcab2, 0xc8f4, 0xc936, 0xcc78, 0xcdba, 0xcffc, 0xce3e,
    0x9180, 0x9042, 0x9204, 0x93c6, 0x9688, 0x974a, 0x950c, 0x94ce,
    0x9f90, 0x9e52, 0x9c14, 0x9dd6, 0x9898, 0x995a, 0x9b1c, 0x9ade,
    0x8da0, 0x8c62, 0x8e24, 0x8fe6, 0x8aa8, 0x8b6a, 0x892c, 0x88ee,
    0x83b0, 0x8272, 0x8034, 0x81f6, 0x84b8, 0x857a, 0x873c, 0x86fe,
    0xa9c0, 0xa802, 0xaa44, 0xab86, 0xaec8, 0xaf0a, 0xad4c, 0xac8e,
    0xa7d0, 0xa612, 0xa454, 0xa596, 0xa0d8, 0xa11a, 0xa35c, 0xa29e,
    0xb5e0, 0xb422, 0xb664, 0xb7a6, 0xb2e8, 0xb32a, 0xb16c, 0xb0ae,
    0xbbf0, 0xba32, 0xb874, 0xb9b6, 0xbcf8, 0xbd3a, 0xbf7c, 0xbebe,
];

pub static mut R: [Block; 0x100] = [[0; 16]; 0x100];
pub static mut MULT: [[u8; 2]; 0x10000] = [[0; 2]; 0x10000];

pub struct Gcm
{
    pub h: Block,           // hash key
    pub iv: Block,          // initialization vector
    pub key: Block,         // encryption key
    pub cipher: AesCipher,  // symmetric cipher
    pub counter: Block,     // counter
    pub r: [Block; 256],    // static multiplication table
    pub mul: [Block; 256],  // session multiplication table
}

impl Gcm
{
    pub fn create(key: Block, iv: Block) -> Gcm
    {
        let cipher = AesCipher::create(key);
        let h = cipher.encryptBlock([0; 16]);
        println!("h");
        h.iter().for_each(|h| print!("{:#04x?}; ", h));
        println!();
        Gcm
        {
            h,
            iv,
            key,
            cipher,
            counter: iv,
            mul: array_init(|i| mul_init(&h, &[i as u8, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0])),
            r: unsafe {array_init(|i| ((MUL[i] as u128) << 112).to_be_bytes())}
        }
    }

    pub fn encrypt (&mut self, aad: &Vec<u8>, pt: &Vec<u8>) -> (Vec<u8>, Block)
    {
        self.counter[12..16].clone_from_slice(&(1 as u32).to_be_bytes());

        let mut ct = Vec::<u8>::with_capacity(pt.len());
        let mut ht = [0u8; 16];

        for i in (0..aad.len()).step_by(16)
        {
            let b = aad[i..if i+16 > aad.len() {aad.len()} else {i+16}].to_vec();
            let x = xor16v(&ht, &b);
            ht = self.mulh(&x);
        }

        let ec = self.cipher.encryptBlock(self.counter);
        println!("ec0");
        ec.iter().for_each(|h| print!("{:#04x?}; ", h));
        println!();

        for i in (0..pt.len()).step_by(16)
        {
            self.incr();
            let eic = self.cipher.encryptBlock(self.counter);
            println!("ec");
            eic.iter().for_each(|h| print!("{:#04x?}; ", h));
            println!();

            let mut et = pt[i .. if i+16 > pt.len() {pt.len()} else {i+16}].
                iter().zip(eic.iter()).map(|(p, c)| xor(*p, *c, true)).collect();
            ht = self.mulh(&xor16v(&ht, &et));
            ct.append(&mut et);
        }

        let sz: u128 = (((aad.len() as u128) << 64) | (pt.len() as u128)) << 3;
        ht = xor16a(&self.mulh(&xor16a(&ht, &sz.to_be_bytes(), true)), &ec, true);

        (ct, ht)
    }

    pub fn decrypt (&mut self, aad: &Vec<u8>, ct: &Vec<u8>, at: Block) -> Option<Vec<u8>>
    {
        self.counter[12..16].clone_from_slice(&(1 as u32).to_be_bytes());

        let mut pt = Vec::<u8>::with_capacity(ct.len());
        let mut ht: Block = [0; 16];

        for i in (0..aad.len()).step_by(16)
        {
            let b = aad[i..if i+16 > aad.len() {aad.len()} else {i+16}].to_vec();
            let x = xor16v(&ht, &b);
            ht = self.mulh(&x);
        }

        let ec = self.cipher.encryptBlock(self.counter);

        for i in (0..ct.len()).step_by(16)
        {
            self.incr();
            let ec = self.cipher.encryptBlock(self.counter);

            let ctc = ct[i .. if i+16 > pt.len() {ct.len()} else {i+16}].to_vec();
            let mut dt = ctc.iter().zip(ec.iter()).map(|(c, e)| xor(*c, *e, true)).collect();
            pt.append(&mut dt);
            ht = self.mulh(&xor16v(&ht, &ctc));
        }

        let sz: u128 = (((aad.len() as u128) << 64) | (pt.len() as u128)) << 3;
        ht = xor16a(&self.mulh(&xor16a(&ht, &sz.to_be_bytes(), true)), &ec, true);

        if ht == at {Some(pt)} else {None}
    }

    fn incr(&mut self)
    {
        let counter = u32::from_be_bytes(self.counter[12..16].try_into().unwrap());
        self.counter[12..16].clone_from_slice(&(if counter == u32::MAX {0} else {counter+1}).to_be_bytes());
    }

    pub fn mulh(&self, x: &Block) -> Block
    {
        unsafe {mult(x, &self.h)}
    }

    #[allow(dead_code)]
    pub fn mulh_table(&self, x: &Block) -> Block
    {
        let mut z = self.mul[x[15] as usize];
        for i in (0..15).rev()
        {
            z.rotate_right(1);
            let r = self.r[z[0] as usize];
            z[0] = r[0];
            z[1] = xor(z[1], r[1], false);
            z = xor16a(&z, &self.mul[x[i] as usize], false)
        }
        z
    }
}

pub unsafe fn mult(x: &Block, y: &Block) -> Block
{
    let mut z = [0u8; 16];
    for i in 0..16
    {
        for j in 0..16
        {
            let k = i + j;
            let m = MULT[(x[i] as usize) | ((y[j] as usize) << 8)];

            if k < 15
            {
                z[k] = xor(z[k], m[0], false);
                z[k+1] = xor(z[k+1], m[1], false);
            }
            else if k == 15
            {
                let r = R[m[1] as usize];
                z[0] = xor(z[0], r[0], false);
                z[1] = xor(z[1], r[1], false);
                z[15] = xor(z[15], m[0], false);
            }
            else if k < 30
            {
                let r0 = R[m[0] as usize];
                let r1 = R[m[1] as usize];
                z[k-16] = xor(z[k-16], r0[0], false);
                z[k-15] = xor(z[k-15], xor(r0[1], r1[0], false), false);
                z[k-14] = xor(z[k-14], r1[1], false);
            }
            else
            {
                let r0 = R[m[0] as usize];
                let r1 = R[m[1] as usize];
                let r2 = R[r1[1] as usize];
                z[0] = xor(z[0], r2[0], false);
                z[1] = xor(z[1], r2[1], false);
                z[14] = xor(z[14], r0[0], false);
                z[15] = xor(z[15], xor(r0[1], r1[0], false), false);
            }
        }
    }
    z
}

pub fn mul_init(x: &Block, y: &Block) -> Block
{
    let x: u128 = u128::from_be_bytes(*x);
    let y: u128 = u128::from_be_bytes(*y);
    let r: u128 = 0xE1000000000000000000000000000000;
    let mut z: u128 = 0;
    let mut v = x;

    for i in 0..128
    {
        if y & (1<<(127-i)) != 0 {z ^= v}
        v = (v >> 1) ^ if v & 1 == 0 {0} else {r}
    }
    z.to_be_bytes()
}
