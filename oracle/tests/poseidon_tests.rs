#[cfg(test)]
mod tests {
    use algebra::{pasta::Fp, field_new, BigInteger256, UniformRand};
    use oracle::poseidon::{Sponge, ArithmeticSponge, PlonkSpongeConstants};

    fn _rand_fields(n: u8) {
        let rng = &mut rand::thread_rng();
        for _i in 0..n {
            let fe = Fp::rand(rng);
            println!("{:?}", fe);
        }
    }

    fn field_to_c_str(fe: Fp) -> String {
        let s = fe.to_string().to_lowercase();
        let s = &s[8..s.len()-2];
        return format!("{{0x{}, 0x{}, 0x{}, 0x{}}}", &s[48..64], &s[32..48], &s[16..32], &s[0..16]);
    }

    fn print_c_test(input: &[Fp], target: Fp) {
        println!("// Input {{");
        for x in input {
            println!("//   {}", field_to_c_str(*x));
        }
        println!("// }}\n//");
        println!("// Target\n//   {}\n", field_to_c_str(target));
    }

    fn test_poseidon(input: &[Fp], target: Fp) -> bool {
        let mut s = ArithmeticSponge::<Fp, PlonkSpongeConstants>::new();
        s.absorb(&oracle::pasta::fp::params(), &input);
        let output: Fp = s.squeeze(&oracle::pasta::fp::params());

        print_c_test(input, target);
        if output != target {
            println!("FAIL: got      {:?}", output);
            println!("FAIL: expected {:?}", target);
            return false;
        }
        else {
            return true;
        }
    }

    #[test]
    fn poseidon_test() {
        // _rand_fields(1);
        // Input {
        //   {0x47187fecbf726861, 0xb2a5a57187baf1d1, 0x049e0f1315247d81, 0x1276cef18d3f2a88}
        // }
        //
        // Target
        //   {0xf3eb3d1417523abf, 0xeee57792bb273d07, 0x776c0b1ce4bad9e5, 0x1450c2da2a737fc3}
        assert!(test_poseidon(
            &[
                field_new!(Fp, BigInteger256([11416295947058400506, 3360729831846485862, 12146560982654972456, 2987985415332862884]))
            ],
            field_new!(Fp, BigInteger256([9339310613046265565, 11457895583497182008, 4032588709016551538, 2534517186416423078]))
        ));

        // _rand_fields(2);
        // Input {
        //   {0x09409b2c065207ae, 0xe446c4f2d72552be, 0xcf92397ffb628078, 0x0590e7a4b7de334a}
        //   {0x2ac6b89957fd3114, 0x6a14b01f3987e59e, 0x7d28b6469319f32e, 0x0ae79043108233d3}
        // }
        //
        // Target
        //   {0xe64eccc70da91d4c, 0x5d047b3533963a38, 0x14bb20b81f4f89dc, 0x014c99bbb112dcbc}
        assert!(test_poseidon(
            &[
                field_new!(Fp, BigInteger256([16049149342757733248, 17845879034270049224, 6274988087599189421, 3891307270444217155])),
                field_new!(Fp, BigInteger256([9941995706707671113, 236362462947459140, 17033003259035381397, 4098833191871625741]))
            ],
            field_new!(Fp, BigInteger256([9143025204397860770, 1235381248942540265, 4081231076261420062, 3576918845002739766]))
        ));

        // _rand_fields(6);
        // Input {
        //   {0x4618b840ee8b6a75, 0x9cef04d622f15b3b, 0x4549401a1f8d44c9, 0x3d1bd914030b5929}
        //   {0x33056bdcd587e7e8, 0x13f52e1be37ddb92, 0xa664a94e7c098886, 0x34faaf6e5fd9828e}
        //   {0x1ec31f9269b2a109, 0x4b9942ba132332d5, 0xe5a9693f8a44ff0b, 0x2e4975307038208b}
        //   {0xedbeeea6513acf5f, 0x0ee3b2c7c5fb2f17, 0x36dd5c17cf593510, 0x357d2281aeea7c21}
        //   {0x7a8d15e587110ae4, 0x5091df19c4cfc86d, 0xb18915e7380f91aa, 0x271a893ea31d9a2c}
        //   {0x6037a01e3873690c, 0x5115d763d47dcce1, 0xcfe78d3916508fc1, 0x1279f6ec0d1fad11}
        // }
        //
        // Target
        //   {0x4e0a065baa662e2b, 0x1f18e68970cbf81c, 0x20e4cab4a9da56ff, 0x2bf12f80a8df096a}
        assert!(test_poseidon(
            &[
                field_new!(Fp, BigInteger256([9704301770581080981, 2499732416380034080, 1552460651457635878, 2182092766742516766])),
                field_new!(Fp, BigInteger256([10241172525723548917, 3250849480340098134, 5608178086178266886, 1366213406343751254])),
                field_new!(Fp, BigInteger256([10380623415383037784, 13389668539492290994, 10482142744861128937, 3077159350427358629])),
                field_new!(Fp, BigInteger256([6584749540286661553, 15562759185129930720, 5515971328990950811, 4437184837018641102])),
                field_new!(Fp, BigInteger256([1641465937504143586, 7033936464935017438, 13243587829712915388, 2871847862647531309])),
                field_new!(Fp, BigInteger256([12626981959362826674, 18184519472077450570, 9623752967626843601, 2849047078275902603]))
            ],
            field_new!(Fp, BigInteger256([13702685026207732732, 15541592410354713311, 11881342638040842876, 4114242432626008720]))
        ));
    }
}
