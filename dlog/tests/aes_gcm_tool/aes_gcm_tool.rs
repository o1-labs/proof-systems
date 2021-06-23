mod gcm;

use aes_gcm::Aes128Gcm;
use aes_gcm::aead::{Aead, NewAead, generic_array::GenericArray, Payload};
use self::gcm::{aes::*, gcm::*};
use rand::{thread_rng, Rng, SeedableRng, rngs::StdRng};
use array_init::array_init;
use std::{io, io::Write};
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
    let cipher = AesCipher::create(key.to_be_bytes());

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
    unsafe {for x in 0..256 {for y in 0..256
    {
        XOR[y | (x << 8)] = (x as u8) ^ (y as u8);
        MULT[y | (x << 8)] =
            {
                let mut xx: Block = [0; 16]; xx[0] = x as u8;
                let mut yy: Block = [0; 16]; yy[0] = y as u8;
                let z = mul_init(&xx, &yy);
                [z[0], z[1]]
            }
        };
        R = array_init(|i| ((MUL[i] as u128) << 112).to_be_bytes())
    }}

    let rng = &mut thread_rng();

    let iv: Block = {let iv: u128 = rng.gen(); iv}.to_be_bytes();
    let key: Block = {let key: u128 = rng.gen(); key}.to_be_bytes();
    let mut cipher = Gcm::create(key, iv);

    let iv_rust = GenericArray::clone_from_slice(&iv[0..12]);
    let key_rust = GenericArray::clone_from_slice(&key[0..16]);
    let cipher_rust = Aes128Gcm::new(&key_rust);

    let start = Instant::now();
    for test in 0..1000
    {
        let aad1 = (0..rng.gen_range(1357, 3579)).map(|_| {let x: u8 = rng.gen(); x}).collect::<Vec<u8>>();
        let aad2 = (0..rng.gen_range(135, 357)).map(|_| {let x: u8 = rng.gen(); x}).collect::<Vec<u8>>();
        let mut pt1 = (0..rng.gen_range(13579, 35791)).map(|_| {let x: u8 = rng.gen(); x}).collect::<Vec<u8>>();

        let (ct1, at1) = cipher.encrypt(&aad1, &pt1);
        let pt2 = cipher.decrypt(&aad1, &ct1, at1).expect("authentication failure!");

        let ct1_rust = cipher_rust.encrypt(&iv_rust, Payload{aad: &aad1, msg: &pt1}).expect("encryption failure!");
        let pt2_rust = cipher_rust.decrypt(&iv_rust, Payload{aad: &aad1, msg: &ct1_rust}).expect("decryption failure!");

        assert_eq!(ct1, ct1_rust[0..ct1.len()].to_vec());
        assert_eq!(at1.to_vec(), ct1_rust[ct1.len()..ct1_rust.len()].to_vec());
        assert_eq!(pt2, pt2_rust);

        let (ct2, at2) = cipher.encrypt(&aad2, &pt2);
        pt1 = cipher.decrypt(&aad2, &ct2, at2).expect("authentication failure!");

        let ct2_rust = cipher_rust.encrypt(&iv_rust, Payload{aad: &aad2, msg: &pt2}).expect("encryption failure!");
        let pt1_rust = cipher_rust.decrypt(&iv_rust, Payload{aad: &aad2, msg: &ct2_rust}).expect("decryption failure!");

        assert_eq!(ct2, ct2_rust[0..ct2.len()].to_vec());
        assert_eq!(at2.to_vec(), ct2_rust[ct2.len()..ct2_rust.len()].to_vec());
        assert_eq!(pt1, pt1_rust);

        assert_eq!(pt1, pt2);
        assert_eq!(ct1, ct2);

        print!("{:?}\r", test);
        io::stdout().flush().unwrap();
    }
    println!("{}{:?}", "Execution time: ".yellow(), start.elapsed());
}

fn main()
{
    // init GF(2^8) XOR and GF(2^128) multiplication tables
    unsafe {for x in 0..256 {for y in 0..256
    {
        XOR[y | (x << 8)] = (x as u8) ^ (y as u8);
        MULT[y | (x << 8)] =
            {
                let mut xx: Block = [0; 16]; xx[0] = x as u8;
                let mut yy: Block = [0; 16]; yy[0] = y as u8;
                let z = mul_init(&xx, &yy);
                [z[0], z[1]]
            }
        };
        R = array_init(|i| ((MUL[i] as u128) << 112).to_be_bytes());
    }}

    let mut rng: StdRng = SeedableRng::from_seed([1,3,5,7,1,3,5,7,1,3,5,7,1,3,5,7,1,3,5,7,1,3,5,7,1,3,5,7,1,3,5,7]);

    let iv: Block = {let iv: u128 = rng.gen(); iv}.to_be_bytes();
    let key: Block = {let key: u128 = rng.gen(); key}.to_be_bytes();
    let mut cipher = Gcm::create(key, iv);
/*
    let iv_rust = GenericArray::clone_from_slice(&iv[0..12]);
    let key_rust = GenericArray::clone_from_slice(&key[0..16]);
    let cipher_rust = Aes128Gcm::new(&key_rust);
*/
    let start = Instant::now();
    for _ in 0..1
    {
        let aad1 = (0..0/*rng.gen_range(1357, 3579)*/).map(|_| {let x: u8 = rng.gen(); x}).collect::<Vec<u8>>();
        //let aad2 = (0..0/*rng.gen_range(135, 357)*/).map(|_| {let x: u8 = rng.gen(); x}).collect::<Vec<u8>>();
        //let pt1 = (0..1500/*rng.gen_range(13579, 35791)*/).map(|_| {let x: u8 = rng.gen(); x}).collect::<Vec<u8>>();

        let pt1 =
"HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8
Content-Length: 56
Vary: origin
Access-Control-Allow-Credentials: true
Access-Control-Expose-Headers: WWW-Authenticate,Server-Authorization
Server: CK-FG-server
Strict-Transport-Security: max-age=31536000; includeSubdomains; preload
X-Frame-Options: SAMEORIGIN
X-XSS-Protection: 1; mode=block
ORIGIN-ENV: production
ORIGIN-DC: us-central1
Expires: Mon, 08 Mar 2021 22:56:10 GMT
Cache-Control: max-age=0, no-cache, no-store
Pragma: no-cache
Date: Mon, 08 Mar 2021 22:56:10 GMT
Connection: keep-alive
Set-Cookie: bm_sz=B1AE08DD298335B7182B0BAD1E94A4C6~YAAQn4hlXybT58p3AQAAQBMOFAu+elquuJr6dVUmUkixH8ngfyBkihQ+KMWF5/x3NFlrMxN1W9g3NDD2yNTxKwNwbtchPX6FMevu5xwEmC6pOBg8SOPpyNMlkUUKyAdDUnzvNPvU/dNXLl+76O/fywVhMDj/2T/0r7Uwp4zY8Qol9Bg2ZPLwa+5lhs7e38KAtBHDf+Y=; Domain=.creditkarma.com; Path=/; Expires=Tue, 09 Mar 2021 02:56:09 GMT; Max-Age=14399; HttpOnly
Set-Cookie: _abck=40552327C7CCD349D4A0CC1CCBF85A41~-1~YAAQn4hlXyfT58p3AQAAQBMOFAXOBuPbRx0T6wILoZGvX0R+IC7OF4/VN0I7XDZAWzNjZuFdj4ijZz4eAI/DAPK8jxv1lWeRrZRlYRD2hmaTfJG7HrGOLHymnNNR4ndxQFR5bxF2r5navFubmfwEwdBGfw4B78ISllldsL/QkwiA1O+TuuvfEFTzjQKp77FKWfyW9jiWUGniqs4NezXGIe9iOC9ou3PUzYpyFGdxi3aBI2X/ecdkUENtCDb5apw2iWG+hUqmDG/QbEGGBBQM+E2f9sVUHV2b06kkax7k5iHZjBKpztXUZAYDiV0APt44HNYop6RUDijwhmlfmNp2iFwkWZtsawx8WVN2Ktr/d1bIEKLl4PLshlWK5rXmelJR~-1~-1~-1; Domain=.creditkarma.com; Path=/; Expires=Tue, 08 Mar 2022 22:56:10 GMT; Max-Age=31536000; Secure
[{\"data\":{\"creditScores\":{\"equifax\":[{\"value\":706}]}}}]".as_bytes().to_vec();

        println!("key");
        key.iter().for_each(|h| print!("{:#04x?}; ", h));
        println!();

        println!("iv");
        iv.iter().for_each(|h| print!("{:#04x?}; ", h));
        println!();

        println!("pt");
        pt1.iter().enumerate().for_each(|(i, h)| {print!("{:#04x?}; ", h); if (i+1)%16==0 {println!()}});
        println!();

        let (ct1, at1) = cipher.encrypt(&aad1, &pt1);

        println!("ct");
        ct1.iter().enumerate().for_each(|(i, h)| {print!("{:#04x?}; ", h); if (i+1)%16==0 {println!()}});
        println!();

        println!("at");
        at1.iter().for_each(|h| print!("{:#04x?}; ", h));
        println!();

        /*
        let pt2 = cipher.decrypt(&aad1, &ct1, at1).expect("authentication failure!");
        let ct1_rust = cipher_rust.encrypt(&iv_rust, Payload{aad: &aad1, msg: &pt1}).expect("encryption failure!");
        let pt2_rust = cipher_rust.decrypt(&iv_rust, Payload{aad: &aad1, msg: &ct1_rust}).expect("decryption failure!");

        assert_eq!(ct1, ct1_rust[0..ct1.len()].to_vec());
        assert_eq!(at1.to_vec(), ct1_rust[ct1.len()..ct1_rust.len()].to_vec());
        assert_eq!(pt2, pt2_rust);

        let (ct2, at2) = cipher.encrypt(&aad2, &pt2);
        pt1 = cipher.decrypt(&aad2, &ct2, at2).expect("authentication failure!");

        let ct2_rust = cipher_rust.encrypt(&iv_rust, Payload{aad: &aad2, msg: &pt2}).expect("encryption failure!");
        let pt1_rust = cipher_rust.decrypt(&iv_rust, Payload{aad: &aad2, msg: &ct2_rust}).expect("decryption failure!");

        assert_eq!(ct2, ct2_rust[0..ct2.len()].to_vec());
        assert_eq!(at2.to_vec(), ct2_rust[ct2.len()..ct2_rust.len()].to_vec());
        assert_eq!(pt1, pt1_rust);

        assert_eq!(pt1, pt2);
        assert_eq!(ct1, ct2);

        print!("{:?}\r", test);
        io::stdout().flush().unwrap();
        */
    }

    println!("{}{:?}", "Execution time: ".yellow(), start.elapsed());
}
