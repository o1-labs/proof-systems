#[cfg(test)]
mod tests {
    use algebra::{pasta::Fp, fields::PrimeField, BigInteger256, UniformRand};
    use oracle::poseidon::Sponge; // needed for ::new() sponge

    use oracle::poseidon::ArithmeticSponge as Poseidon;
    use oracle::poseidon::PlonkSpongeConstants as Constants;
    use oracle::pasta::fp as Parameters;

    use oracle::poseidon_5_wires::ArithmeticSponge as Poseidon5Wires;
    use oracle::poseidon_5_wires::PlonkSpongeConstants as Constants5Wires;
    use oracle::pasta::fp5 as Parameters5Wires;

    use oracle::poseidon_3::ArithmeticSponge as Poseidon3;
    use oracle::poseidon_3::PlonkSpongeConstants as Constants3;
    use oracle::pasta::fp5 as Parameters3;

    fn _rand_fields(n: u8) {
        let rng = &mut rand::thread_rng();
        for _i in 0..n {
            let fe = Fp::rand(rng);
            println!("{:?}", fe.into_repr());
        }
    }

    #[test]
    fn poseidon() {
        macro_rules! assert_poseidon_eq {
            ($input:expr, $target:expr) => {
                let mut s = Poseidon::<Fp, Constants>::new();
                s.absorb(&Parameters::params(), $input);
                let output = s.squeeze(&Parameters::params());
                assert_eq!(output, $target, "\n output: {:?}\n target: {:?}", output.into_repr(), $target.into_repr());
            };
        }

        // _rand_fields(0);
        assert_poseidon_eq!(
            &[
            ],
            Fp::from_repr(BigInteger256([17114291637813588507, 14335107542818720711, 1320934316380316157, 1722173086297925183]))
        );

        // _rand_fields(1);
        assert_poseidon_eq!(
            &[
                Fp::from_repr(BigInteger256([11416295947058400506, 3360729831846485862, 12146560982654972456, 2987985415332862884]))
            ],
            Fp::from_repr(BigInteger256([871590621865441384, 15942464099191336363, 2836661416333151733, 11819778491522761]))
        );

        // _rand_fields(2);
        assert_poseidon_eq!(
            &[
                Fp::from_repr(BigInteger256([16049149342757733248, 17845879034270049224, 6274988087599189421, 3891307270444217155])),
                Fp::from_repr(BigInteger256([9941995706707671113, 236362462947459140, 17033003259035381397, 4098833191871625741]))
            ],
            Fp::from_repr(BigInteger256([17256859529285183666, 10562454737368249340, 16653501986100235558, 1613229473904780795]))
        );

        // _rand_fields(3);
        assert_poseidon_eq!(
            &[
                Fp::from_repr(BigInteger256([16802949773563312590, 13786671686687654025, 6327949131269833714, 2206832697832183571])),
                Fp::from_repr(BigInteger256([18422989176992908572, 7121908340714489421, 15983151711675082713, 2047309793776126211])),
                Fp::from_repr(BigInteger256([10656504003679202293, 5033073342697291414, 15641563258223497348, 2549024716872047224]))
            ],
            Fp::from_repr(BigInteger256([4610990272905062813, 1786831480172390544, 12827185513759772316, 1463055697820942106]))
        );

        // _rand_fields(6);
        assert_poseidon_eq!(
            &[
                Fp::from_repr(BigInteger256([13568896335663078044, 12780551435489493364, 7939944734757335782, 2716817606766379733])),
                Fp::from_repr(BigInteger256([8340509593943796912, 14326728421072412984, 1939214290157533341, 248823904156563876])),
                Fp::from_repr(BigInteger256([18138459445226614284, 7569000930215382240, 12226032416704596818, 754852930030810284])),
                Fp::from_repr(BigInteger256([11813108562003481058, 3775716673546104688, 7004407702567408918, 2198318152235466722])),
                Fp::from_repr(BigInteger256([9752122577441799495, 2743141496725547769, 8526535807986851558, 1154473298561249145])),
                Fp::from_repr(BigInteger256([12335717698867852470, 17616685850532508842, 8342889821739786893, 2726231867163795098]))
            ],
            Fp::from_repr(BigInteger256([2534358780431475408, 3747832072933808141, 2500060454948506474, 2342403740596596240]))
        );
    }

    #[test]
    fn poseidon_5_wires() {
        macro_rules! assert_poseidon_5_wires_eq {
            ($input:expr, $target:expr) => {
                let mut s = Poseidon5Wires::<Fp, Constants5Wires>::new();
                s.absorb(&Parameters5Wires::params(), $input);
                let output = s.squeeze(&Parameters5Wires::params());
                assert_eq!(output, $target, "\n output: {:?}\n target: {:?}", output.into_repr(), $target.into_repr());
            };
        }

        // _rand_fields(0);
        assert_poseidon_5_wires_eq!(
            &[
            ],
            Fp::from_repr(BigInteger256([11864518339837020673, 11154701827270369066, 18250329647482904211, 2973895537517503096]))
        );

        // _rand_fields(1);
        assert_poseidon_5_wires_eq!(
            &[
                Fp::from_repr(BigInteger256([925605326051629702, 9450022185177868805, 3430781963795317176, 2120098912251973017]))
            ],
            Fp::from_repr(BigInteger256([2462689009389580473, 17870513234387686250, 11236274956264243810, 3641294289935218438]))
        );

        // _rand_fields(2);
        assert_poseidon_5_wires_eq!(
            &[
                Fp::from_repr(BigInteger256([4872213112846934187, 15221974649365942201, 4177652558587823268, 1324361518338458527])),
                Fp::from_repr(BigInteger256([10368205141323064185, 9471328583611422132, 12997197966961952901, 3290733940621514661]))
            ],
            Fp::from_repr(BigInteger256([6903622620367681812, 11040552022054417145, 756305575883948511, 2025491032262703105]))
        );

        // _rand_fields(4);
        assert_poseidon_5_wires_eq!(
            &[
                Fp::from_repr(BigInteger256([7832849012654337787, 4963068119957452774, 10773086124514989319, 1683727612549340848])),
                Fp::from_repr(BigInteger256([3569008656860171438, 10394421784622027030, 196192141273432503, 1248957759478765405])),
                Fp::from_repr(BigInteger256([9522737303355578738, 572132462899615385, 13566429773365192181, 121306779591653499])),
                Fp::from_repr(BigInteger256([13250259935835462717, 4425586510556471497, 14507184955230611679, 2566418502016358110]))
            ],
            Fp::from_repr(BigInteger256([15890326985419680819, 13328868938658098350, 14092994142147217030, 1596359391679724262]))
        );

        // _rand_fields(5);
        assert_poseidon_5_wires_eq!(
            &[
                Fp::from_repr(BigInteger256([17910451947845015148, 5322223719857525348, 10480894361828395044, 34781755494926625])),
                Fp::from_repr(BigInteger256([6570939701805895370, 4169423915667089544, 2366634926126932666, 1804659639444390640])),
                Fp::from_repr(BigInteger256([13670464873640336259, 14938327700162099274, 9664883370546456952, 2153565343801502671])),
                Fp::from_repr(BigInteger256([6187547161975656466, 12648383547735143102, 15485540615689340699, 417108511095786061])),
                Fp::from_repr(BigInteger256([3554897497035940734, 1047125997069612643, 8351564331993121170, 2878650169515721164]))
            ],
            Fp::from_repr(BigInteger256([4479424786655393812, 790574497228972985, 13640155489552216446, 711750288597225015]))
        );

        // _rand_fields(6);
        assert_poseidon_5_wires_eq!(
            &[
                Fp::from_repr(BigInteger256([13179872908007675812, 15426428840987667748, 15925112389472812618, 1172338616269137102])),
                Fp::from_repr(BigInteger256([9811926356385353149, 16140323422473131507, 1062272508702625050, 1217048734747816216])),
                Fp::from_repr(BigInteger256([9487959623437049412, 8184175053892911879, 12241988285373791715, 528401480102984021])),
                Fp::from_repr(BigInteger256([2797989853748670076, 10357979140364496699, 12883675067488813586, 2675529708005952482])),
                Fp::from_repr(BigInteger256([8051500605615959931, 13944994468851713843, 9308072337342366951, 3594361030023669619])),
                Fp::from_repr(BigInteger256([6680331634300327182, 6761417420987938685, 10683832798558320757, 2470756527121432589]))
            ],
            Fp::from_repr(BigInteger256([3614205655220390000, 4108372806675450262, 3652960650983359474, 2116997592584139383]))
        );
    }

    #[test]
    fn poseidon_3() {
        macro_rules! assert_poseidon_3_eq {
            ($input:expr, $target:expr) => {
                let mut s = Poseidon3::<Fp, Constants3>::new();
                s.absorb(&Parameters3::params(), $input);
                let output = s.squeeze(&Parameters3::params());
                assert_eq!(output, $target, "\n output: {:?}\n target: {:?}", output.into_repr(), $target.into_repr());
            };
        }

        // _rand_fields(0);
        assert_poseidon_3_eq!(
            &[
            ],
            Fp::from_repr(BigInteger256([15449015445789340742, 8188265220607939614, 14255528068821191610, 3263398758375185362]))
        );

        // _rand_fields(1);
        assert_poseidon_3_eq!(
            &[
                Fp::from_repr(BigInteger256([7268460211608788188, 10132480989041334579, 2339874299280274918, 194293202993774285]))
            ],
            Fp::from_repr(BigInteger256([2558090059455896147, 7307347974437946425, 4536174362957322879, 2630632011732286938]))
        );

        // _rand_fields(2);
        assert_poseidon_3_eq!(
            &[
                Fp::from_repr(BigInteger256([9917828826452988051, 15189182483242825728, 17783867389905310625, 3096233339466922731])),
                Fp::from_repr(BigInteger256([11112469648615694507, 1349483555912170531, 5132274865255624365, 291635065414725798]))
            ],
            Fp::from_repr(BigInteger256([8379552536522502903, 12394062870321263370, 1732109214237199200, 1189670113580531968]))
        );

        // _rand_fields(3);
        assert_poseidon_3_eq!(
            &[
                Fp::from_repr(BigInteger256([14267996300018486948, 670373130142722849, 4216114176990048262, 3881970950122376215])),
                Fp::from_repr(BigInteger256([2734205406253254786, 17095706724646389267, 5933659775356387652, 3721674824441362406])),
                Fp::from_repr(BigInteger256([4947525329177827161, 2645489287737017668, 9857560748408218200, 1227757243736002830]))
            ],
            Fp::from_repr(BigInteger256([1325431644610243984, 7526369527749934923, 12039861643291311194, 368685106794101856]))
        );

        // _rand_fields(6);
        assert_poseidon_3_eq!(
            &[
                Fp::from_repr(BigInteger256([7267853995951905224, 90403176695802388, 4774599761789790556, 3347377905747449096])),
                Fp::from_repr(BigInteger256([11838594320814769562, 278541806768709143, 4632615733560524785, 2328922649099910504])),
                Fp::from_repr(BigInteger256([17911298769116557437, 6834069749734115640, 9177656000002681079, 2795336499778575742])),
                Fp::from_repr(BigInteger256([7151979636429903658, 14400997240730962670, 4625828803120157807, 1840002810696946942])),
                Fp::from_repr(BigInteger256([10973288036385879140, 15163372292438207457, 8171725748546728133, 4039739380933749593])),
                Fp::from_repr(BigInteger256([14659358909991100974, 4969649262916868094, 16870234378475169070, 2694211618115933100]))
            ],
            Fp::from_repr(BigInteger256([4866823284634240780, 13596820755913603173, 1589815242261644762, 1228434131579452506]))
        );
    }
}
