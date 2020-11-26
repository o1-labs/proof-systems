/*********************************************************************************************************

This source file tests constraints for the following computatios:

1. Weierstrass curve group addition of non-special pairs of points
   via generic Plonk constraints

    (x2 - x1) * s = y2 - y1
    s * s = x1 + x2 + x3
    (x1 - x3) * s = y3 + y1

1. Weierstrass curve y^2 = x^3 + 7 group addition of non-special pairs of points
    via custom Plonk constraints

3. Poseidon hash function permutation via custom Plonk constraints

4. short Weierstrass curve variable base scalar multiplication via custom Plonk constraints

5. short Weierstrass curve group endomorphism optimised variable base
   scalar multiplication via custom Plonk constraints

**********************************************************************************************************/

use oracle::{poseidon::*, sponge::{DefaultFqSponge, DefaultFrSponge}};
use plonk_circuits::{wires::Wire, gate::CircuitGate, constraints::ConstraintSystem};
use commitment_dlog::{srs::SRS, commitment::{CommitmentCurve, ceil_log2, product, b_poly_coefficients}};
use algebra::{Field, tweedle::{dee::{Affine, TweedledeeParameters}, fp::Fp}, One, Zero, UniformRand};
use plonk_protocol_dlog::{prover::{ProverProof}, index::{Index, SRSSpec}};
use ff_fft::DensePolynomial;
use std::{io, io::Write};
use groupmap::GroupMap;
use std::time::Instant;
use colored::Colorize;
use rand_core::OsRng;

const MAX_SIZE: usize = 128; // max size of poly chunks
const N: usize = 64; // Plonk domain size

#[test]
fn turbo_plonk()
{
    let z = Fp::zero();
    let p = Fp::one();
    let n = -Fp::one();

    // circuit gates

    let mut gates = vec!
    [
        // public input constraints

        /*
            | x1 | .. | .. | .. | .. |
            --------------------------
            | x2 | .. | .. | .. | .. |
            --------------------------
            | x3 | .. | .. | .. | .. |
            --------------------------
            | y1 | .. | .. | .. | .. |
            --------------------------
            | y2 | .. | .. | .. | .. |
            --------------------------
            | y3 | .. | .. | .. | .. |
        */

        CircuitGate::<Fp>::create_generic(0, [Wire{col:0, row: 6}, Wire{col:1, row:0}, Wire{col:2, row:0}, Wire{col:3, row:0}, Wire{col:4, row:0}], [p, z, z, z, z], z, z),
        CircuitGate::<Fp>::create_generic(1, [Wire{col:1, row: 6}, Wire{col:1, row:1}, Wire{col:2, row:1}, Wire{col:3, row:1}, Wire{col:4, row:1}], [p, z, z, z, z], z, z),
        CircuitGate::<Fp>::create_generic(2, [Wire{col:4, row: 8}, Wire{col:1, row:2}, Wire{col:2, row:2}, Wire{col:3, row:2}, Wire{col:4, row:2}], [p, z, z, z, z], z, z),
        CircuitGate::<Fp>::create_generic(3, [Wire{col:2, row: 7}, Wire{col:1, row:3}, Wire{col:2, row:3}, Wire{col:3, row:3}, Wire{col:4, row:3}], [p, z, z, z, z], z, z),
        CircuitGate::<Fp>::create_generic(4, [Wire{col:3, row: 7}, Wire{col:1, row:4}, Wire{col:2, row:4}, Wire{col:3, row:4}, Wire{col:4, row:4}], [p, z, z, z, z], z, z),
        CircuitGate::<Fp>::create_generic(5, [Wire{col:3, row:10}, Wire{col:1, row:5}, Wire{col:2, row:5}, Wire{col:3, row:5}, Wire{col:4, row:5}], [p, z, z, z, z], z, z),

        /* generic constraint gates for Weierstrass curve group addition

            (x2 - x1) * s = y2 - y1
            s * s = x1 + x2 + x3
            (x1 - x3) * s = y3 + y1

            x1 - x2 + a1
            a1 * s + y1 - y2
            s * s - x1 - x2 - x3
            x1 - x3 - a2
            a2 * s - y1 - y3

            | x1 | x2 | a1 | .. | .. |
            --------------------------
            | a1 | s  | y1 | y2 | .. |
            --------------------------
            | s  | s  | x1 | x2 | x3 |
            --------------------------
            | x1 | x3 | a2 | .. | .. |
            --------------------------
            | a2 | s  | y1 | y3 | .. |
        */

        CircuitGate::<Fp>::create_generic( 6, [Wire{col:2, row: 8}, Wire{col:3, row: 8}, Wire{col:0, row: 7}, Wire{col:3, row: 6}, Wire{col:4, row: 6}], [p, n, p, z, z], z, z),
        CircuitGate::<Fp>::create_generic( 7, [Wire{col:2, row: 6}, Wire{col:0, row: 8}, Wire{col:2, row:10}, Wire{col:3, row:11}, Wire{col:4, row: 7}], [z, z, p, n, z], p, z),
        CircuitGate::<Fp>::create_generic( 8, [Wire{col:1, row: 8}, Wire{col:1, row:10}, Wire{col:0, row: 9}, Wire{col:2, row:11}, Wire{col:1, row: 9}], [z, z, p, p, p], n, z),
        CircuitGate::<Fp>::create_generic( 9, [Wire{col:0, row:11}, Wire{col:0, row:12}, Wire{col:0, row:10}, Wire{col:3, row: 9}, Wire{col:4, row: 9}], [p, n, n, z, z], z, z),
        CircuitGate::<Fp>::create_generic(10, [Wire{col:2, row: 9}, Wire{col:1, row: 7}, Wire{col:1, row:11}, Wire{col:1, row:12}, Wire{col:4, row:10}], [z, z, p, p, z], n, z),
    ];

    /* custom constraint gates for Weierstrass curve group addition
        | x1 | y1 | x2 | y2 | r  |
        --------------------------
        | x3 | y3 | .. | .. | .. |
    */

    let mut add = CircuitGate::<Fp>::create_add
    (
        11,
        &[
            [Wire{col:0, row:13}, Wire{col:0, row:14}, Wire{col:0, row: 1}, Wire{col:0, row: 4}, Wire{col:4, row:11}],
            [Wire{col:0, row: 2}, Wire{col:0, row: 5}, Wire{col:2, row:12}, Wire{col:3, row:12}, Wire{col:4, row:12}],
        ]
    );
    gates.append(&mut add);

    /* generic constraint gates for Weierstrass curve group doubling

            2 * s * y1 = 3 * x1^2
            x2 = s^2 – 2*x1
            y2 = -y1 - s * (x2 – x1)

            x1 * x1 - x12
            2 * y1 * s - 3 * x12
            s * s - 2*x1 – x2
            s * x21 + y1 + y2
            x2 – x1 - x21

            | x1 | x1 |x12 | .. | .. |
            --------------------------
            | y1 | s  |x12 | .. | .. |
            --------------------------
            | s  | s  | x1 | x2 | .. |
            --------------------------
            | s  |x21 | y1 | y2 | .. |
            --------------------------
            | x2 | x1 |x21 | .. | .. |
    */

    let mut double = vec!
    [
        CircuitGate::<Fp>::create_generic(13, [Wire{col:1, row:13}, Wire{col:2, row:15}, Wire{col:2, row:14}, Wire{col:3, row:13}, Wire{col:4, row:13}], [z, z, n, z, z], p, z),
        CircuitGate::<Fp>::create_generic(14, [Wire{col:2, row:16}, Wire{col:0, row:15}, Wire{col:2, row:13}, Wire{col:3, row:14}, Wire{col:4, row:14}], [z, z, (n.double() + &n), z, z], p.double(), z),
        CircuitGate::<Fp>::create_generic(15, [Wire{col:1, row:15}, Wire{col:0, row:16}, Wire{col:1, row:17}, Wire{col:0, row:17}, Wire{col:4, row:15}], [z, z, n.double(), n, z], p, z),
        CircuitGate::<Fp>::create_generic(16, [Wire{col:1, row:14}, Wire{col:2, row:17}, Wire{col:1, row:18}, Wire{col:3, row:18}, Wire{col:4, row:16}], [z, z, p, p, z], p, z),
        CircuitGate::<Fp>::create_generic(17, [Wire{col:2, row:18}, Wire{col:0, row:18}, Wire{col:1, row:16}, Wire{col:3, row:17}, Wire{col:4, row:17}], [p, n, n, z, z], z, z),
    ];
    gates.append(&mut double);

    /* custom constraint gates for Weierstrass curve group doubling
        | x1 | y1 | x2 | y2 | r  |
    */

    let double = CircuitGate::<Fp>::create_double
    (
        18,
        [Wire{col:0, row:0}, Wire{col:0, row: 3}, Wire{col:3, row:15}, Wire{col:3, row:16}, Wire{col:4, row:18}]
    );
    gates.push(double);

    // custom constraints for Poseidon hash function permutation
    
    let c = &oracle::tweedle::fp5::params().round_constants;
    for i in 0..PlonkSpongeConstants::ROUNDS_FULL
    {
        gates.push(CircuitGate::<Fp>::create_poseidon
        (
            i+19,
            [
                Wire{col:0, row:i+19},
                Wire{col:1, row:i+19},
                Wire{col:2, row:i+19},
                Wire{col:3, row:i+19},
                Wire{col:4, row:i+19},
            ],
            c[i].clone()
        ));
    }
    let i = PlonkSpongeConstants::ROUNDS_FULL+19;
    gates.push(CircuitGate::<Fp>::zero
        (i, [Wire{col:0, row:i}, Wire{col:1, row:i}, Wire{col:2, row:i}, Wire{col:3, row:i}, Wire{col:4, row:i}]));

    // custom constraint gates for short Weierstrass curve variable base scalar multiplication
    // test with 2-bit scalar


    // custom constraint gates for short Weierstrass curve variable base
    // scalar multiplication with group endomorphism optimization
    // test with 8-bit scalar


    let (endo_q, _endo_r) = commitment_dlog::srs::endos::<algebra::tweedle::dum::Affine>();
    let srs = SRS::create(MAX_SIZE, 6, N);

    let index = Index::<Affine>::create
    (
        ConstraintSystem::<Fp>::create(gates, oracle::tweedle::fp5::params() as ArithmeticSpongeParams<Fp>, 6).unwrap(),
        MAX_SIZE,
        oracle::tweedle::fq5::params(),
        endo_q,
        SRSSpec::Use(&srs)
    );

    positive(&index);
    negative(&index);
}

fn positive(index: &Index<Affine>)
where <Fp as std::str::FromStr>::Err : std::fmt::Debug
{
    let rng = &mut OsRng;

    let mut batch = Vec::new();
    let points = sample_points();
    let group_map = <Affine as CommitmentCurve>::Map::setup();
    let params = oracle::tweedle::fp5::params();

    println!("{}", "Prover 100 zk-proofs computation".green());
    let mut start = Instant::now();

    for test in 0..100
    {
        let (x1, y1, x2, y2, _, _) = points[test % 10];
        let (x3, y3) = add_points((x1, y1), (x2, y2));
        let a1 = x2 - &x1;
        let a2 = x1 - &x3;
        let s1 = (y2 - &y1) / &(x2 - &x1);
        let r1 = (x2-&x1).inverse().unwrap();

        let (x4, y4) = add_points((x1, y1), (x1, y1));
        let x41 = x4 - &x1;
        let x12 = x1.square();
        let s2 = (x12.double() + x12) / &y1.double();
        let r2 = y1.inverse().unwrap();

        let mut w = || -> Fp {Fp::rand(rng)};

        /* public input and EC addition witness for generic constraints

            | x1 | .. | .. | .. | .. |
            --------------------------
            | x2 | .. | .. | .. | .. |
            --------------------------
            | x3 | .. | .. | .. | .. |
            --------------------------
            | y1 | .. | .. | .. | .. |
            --------------------------
            | y2 | .. | .. | .. | .. |
            --------------------------
            | y3 | .. | .. | .. | .. |
            --------------------------
            | x1 | x2 | a1 | .. | .. |
            --------------------------
            | a1 | s1 | y1 | y2 | .. |
            --------------------------
            | s1 | s1 | x1 | x2 | x3 |
            --------------------------
            | x1 | x3 | a2 | .. | .. |
            --------------------------
            | a2 | s1 | y1 | y3 | .. |
        
        witness for custom gates for Weierstrass curve group addition

            | x1 | y1 | x2 | y2 | r1 |
            --------------------------
            | x3 | y3 | .. | .. | .. |

        witness for generic constraint gates for Weierstrass curve group doubling

            | x1 | x1 |x12 | .. | .. |
            --------------------------
            | y1 | s2 |x12 | .. | .. |
            --------------------------
            | s2 | s2 | x1 | x4 | .. |
            --------------------------
            | s2 |x41 | y1 | y4 | .. |
            --------------------------
            | x4 | x1 |x41 | .. | .. |

        witness for custom constraint gate for Weierstrass curve group doubling

            | x1 | y1 | x4 | y4 | r2 |
    */

        let mut witness =
        [
            vec![ x1, x2, x3, y1, y2, y3, x1, a1, s1, x1, a2,x1, x3, x1, y1, s2, s2, x4, x1],
            vec![w(),w(),w(),w(),w(),w(), x2, s1, s1, x3, s1,y1, y3, x1, s2, s2,x41, x1, y1],
            vec![w(),w(),w(),w(),w(),w(), a1, y1, x1, a2, y1,x2,w(),x12,x12, x1, y1,x41, x4],
            vec![w(),w(),w(),w(),w(),w(),w(), y2, x2,w(), y3,y2,w(),w(),w(), x4, y4,w(), y4],
            vec![w(),w(),w(),w(),w(),w(),w(),w(), x3,w(),w(),r1,w(),w(),w(),w(),w(),w(), r2],
        ];

        //  witness for Poseidon permutation custom constraints

        let mut sponge = ArithmeticSponge::<Fp, PlonkSpongeConstants>::new();
        sponge.state = vec![w(), w(), w(), w(), w()];
        witness.iter_mut().zip(sponge.state.iter()).for_each(|(w, s)| w.push(*s));

        // ROUNDS_FULL full rounds

        for j in 0..PlonkSpongeConstants::ROUNDS_FULL
        {
            sponge.full_round(j, &params);
            witness.iter_mut().zip(sponge.state.iter()).for_each(|(w, s)| w.push(*s));
        }

        // variable base scalar multiplication witness for custom constraints
        // test with 2-bit scalar

        // group endomorphism optimised variable base scalar multiplication witness for custom constraints
        // test with 8-bit scalar 11001001

        witness.iter_mut().for_each(|w| w.resize(N, Fp::zero()));

        // verify the circuit satisfiability by the computed witness
        assert_eq!(index.cs.verify(&witness), true);

        let prev = {
            let k = ceil_log2(index.srs.get_ref().g.len());
            let chals : Vec<_> = (0..k).map(|_| w()).collect();
            let comm = {
                let chal_squareds = chals.iter().map(|x| x.square()).collect::<Vec<_>>();
                let s0 = product(chals.iter().map(|x| *x) ).inverse().unwrap();
                let b = DensePolynomial::from_coefficients_vec(b_poly_coefficients(s0, &chal_squareds));
                index.srs.get_ref().commit(&b, None)
            };
            ( chals, comm )
        };

        // add the proof to the batch
        batch.push(ProverProof::create::<DefaultFqSponge<TweedledeeParameters, PlonkSpongeConstants>, DefaultFrSponge<Fp, PlonkSpongeConstants>>(
            &group_map, &witness, &index, vec![prev]).unwrap());

        print!("{:?}\r", test);
        io::stdout().flush().unwrap();
    }
    println!("{}{:?}", "Execution time: ".yellow(), start.elapsed());

    let verifier_index = index.verifier_index();
    // verify one proof serially
    match ProverProof::verify::<DefaultFqSponge<TweedledeeParameters, PlonkSpongeConstants>, DefaultFrSponge<Fp, PlonkSpongeConstants>>(&group_map, &vec![batch[0].clone()], &verifier_index)
    {
        Err(error) => {panic!("Failure verifying the prover's proof: {}", error)},
        Ok(_) => {}
    }

    // verify the proofs in batch
    println!("{}", "Verifier zk-proofs verification".green());
    start = Instant::now();
    match ProverProof::verify::<DefaultFqSponge<TweedledeeParameters, PlonkSpongeConstants>, DefaultFrSponge<Fp, PlonkSpongeConstants>>(&group_map, &batch, &verifier_index)
    {
        Err(error) => {panic!("Failure verifying the prover's proofs in batch: {}", error)},
        Ok(_) => {println!("{}{:?}", "Execution time: ".yellow(), start.elapsed());}
    }
}

fn negative(index: &Index<Affine>)
where <Fp as std::str::FromStr>::Err : std::fmt::Debug
{
    // non-satisfying witness
    let x1 = <Fp as std::str::FromStr>::from_str("7502226838017077786426654731704772400845471875650491266565363420906771040750427824367287841412217114884691397809929").unwrap();
    let y1 = <Fp as std::str::FromStr>::from_str("3558210182254086348603204259628694223851158529696790509955564950434596266578621349330875065217679787287369448875015").unwrap();
    let x2 = <Fp as std::str::FromStr>::from_str("1321172652000590462919749014481227416957437277585347677751917393570871798430478578222556789479124360282597488862528").unwrap();
    let y2 = <Fp as std::str::FromStr>::from_str("1817964682602513729710432198132831699408829439216417056703680523866007606577303266376792163132424248003554474817101").unwrap();
    let x3 = <Fp as std::str::FromStr>::from_str("3116498715141724683149051461624569979663973751357290170267796754661152457577855966867446609811524433931603777277670").unwrap();
    let y3 = <Fp as std::str::FromStr>::from_str("2773782014032351532784325670003998192667953688555790212612755975320369406749808761658203420299756946851710956379722").unwrap();

    let a1 = x2 - &x1;
    let a2 = x1 - &x3;
    let s = (y2 - &y1) / &(x2 - &x1);

    let rng = &mut OsRng;
    let mut w = || -> Fp {Fp::rand(rng)};

    let mut l = vec![ x1, x2, x3, y1, y2, y3, x1, a1,  s, x1, a2];
    let mut r = vec![w(),w(),w(),w(),w(),w(), x2,  s,  s, x3,  s];
    let mut o = vec![w(),w(),w(),w(),w(),w(), a1, y1, x1, a2, y1];
    let mut a = vec![w(),w(),w(),w(),w(),w(),w(), y2, x2,w(), y3];
    let mut b = vec![w(),w(),w(),w(),w(),w(),w(),w(), x3,w(),w()];

    l.resize(N, Fp::zero());
    r.resize(N, Fp::zero());
    o.resize(N, Fp::zero());
    a.resize(N, Fp::zero());
    b.resize(N, Fp::zero());

    // verify the circuit negative satisfiability by the computed witness
    assert_eq!(index.cs.verify(&[l,r,o,a,b]), false);
}

fn add_points(a: (Fp, Fp), b: (Fp, Fp)) -> (Fp, Fp)
{
    if a == (Fp::zero(), Fp::zero()) {b}
    else if b == (Fp::zero(), Fp::zero()) {a}
    else if a.0 == b.0 && (a.1 != b.1 || b.1 == Fp::zero()) {(Fp::zero(), Fp::zero())}
    else if a.0 == b.0 && a.1 == b.1
    {
        let sq = a.0.square();
        let s = (sq.double() + &sq) / &a.1.double();
        let x = s.square() - &a.0.double();
        let y = -a.1 - &(s * &(x - &a.0));
        (x, y)
    }
    else
    {
        let s = (a.1 - &b.1) / &(a.0 - &b.0);
        let x = s.square() - &a.0 - &b.0;
        let y = -a.1 - &(s * &(x - &a.0));
        (x, y)
    }
}

fn sample_points() -> [(Fp, Fp, Fp, Fp, Fp, Fp); 10]
{
    [((
        <Fp as std::str::FromStr>::from_str("1580733493061982224102642506998085489258052950031005050616926032148684443068721819617638109822422025817760865738650").unwrap(),
        <Fp as std::str::FromStr>::from_str("2120085809980346347658418912345228674556840189092324973615155047510076539377582421094477427199660756057892003266260").unwrap(),
        <Fp as std::str::FromStr>::from_str("2931063856920074489991213592706123181795217105777923458970198160424184864319820345938320384765820615002087379202625").unwrap(),
        <Fp as std::str::FromStr>::from_str("3634752862255786778633521512827318855463765750440270000121873025280392646700033626519512004314174921695952488907036").unwrap(),
        <Fp as std::str::FromStr>::from_str("1294507634713475436209031771946300666248735314827817267504772563137113162405833758696084205208524338669398158984830").unwrap(),
        <Fp as std::str::FromStr>::from_str("114798453479363569901779346943141343003503211376947251274646193677028801959107629567000376881703165185002804693406").unwrap(),
    )),
    ((
        <Fp as std::str::FromStr>::from_str("4916438723201054042444019656898570362273600104737950912332066133041156126167531037694107148261784973791373741416916").unwrap(),
        <Fp as std::str::FromStr>::from_str("2051012425631842496541988522355880419451294963585346803386094216516304700350122283395835617980254056554805281571361").unwrap(),
        <Fp as std::str::FromStr>::from_str("3798823489123936531659900837301256429870899160904365915046540297606766455429074345739557832825816384178402417577821").unwrap(),
        <Fp as std::str::FromStr>::from_str("3488579879963562604710030332050196080084694331754868586303651819049352075134403758806818854394405488571472180191938").unwrap(),
        <Fp as std::str::FromStr>::from_str("4492130795397392969855395164821018678727495757238128952924370214482282522381731201562179077728641507166036172093705").unwrap(),
        <Fp as std::str::FromStr>::from_str("3317005458307697300506824179900015439367289946019131801104385804928666825382998172369005212575436969903579893443447").unwrap(),
    )),
    ((
        <Fp as std::str::FromStr>::from_str("107731235112341014056601334649087826174537370769102664035726912801386121391377851228232171846167086556123468987581").unwrap(),
        <Fp as std::str::FromStr>::from_str("1963962790595933730523174120044002265904658564588760373139608454726106709892708541735292461364495865625076343970834").unwrap(),
        <Fp as std::str::FromStr>::from_str("3772344704532092886341369246824801251481136974060204850537714655166359576252103570869664311322574776526783576771648").unwrap(),
        <Fp as std::str::FromStr>::from_str("3369417395837999027367642060154424196933460733323625212490000298947532714508580040543260359372818031671953511014123").unwrap(),
        <Fp as std::str::FromStr>::from_str("4175821498239090704227498873059231216626902485432216794466274428029831154765291942158615924553999615542684931548444").unwrap(),
        <Fp as std::str::FromStr>::from_str("4596802191575459284564869970438643099629314686704701685272361610637041796430580294413835914610048876437144774613753").unwrap(),
    )),
    ((
        <Fp as std::str::FromStr>::from_str("4526664922998713801045478841197727298417603686071738046788629310369593574178130371831574061517358789667110626054105").unwrap(),
        <Fp as std::str::FromStr>::from_str("2667786067761686000659307984720182570926199171791236728433548659000759742622466294074927440402001674004966896777550").unwrap(),
        <Fp as std::str::FromStr>::from_str("5129493253807975998519351351487075138002392217523224603409608224620269209607655478711987467602796326444862180226873").unwrap(),
        <Fp as std::str::FromStr>::from_str("4724524533410731353480555770462483048132518261498612055891908722191781632466157559343232579571932808201133332870995").unwrap(),
        <Fp as std::str::FromStr>::from_str("1399615561924155397199900618983918195829276511158286234509594550979958914007262146886462077109621809937162477157257").unwrap(),
        <Fp as std::str::FromStr>::from_str("2333105531115337450990014598715444884032287967420191090657707001012614193636424076105460534171237724334736546710446").unwrap(),
    )),
    ((
        <Fp as std::str::FromStr>::from_str("4123527344569577669056282593988661411196763903614399606087980628084902313779076470707110640219624026814533876564722").unwrap(),
        <Fp as std::str::FromStr>::from_str("4826645822222627154915673570829569698396877361785810097819887583105702919324340126296380184169339911799185770577323").unwrap(),
        <Fp as std::str::FromStr>::from_str("3027353026192835011515604555215610362579318356058808091941560670325717683229132386678654797899058293060394241339067").unwrap(),
        <Fp as std::str::FromStr>::from_str("1893342279078375893720965821698231537818292912881407850560073443595346713982419102655915637930765470196489924638426").unwrap(),
        <Fp as std::str::FromStr>::from_str("2987066520006040393510041781578790694448032988620567180549808503907388510730439170598442037636574758551237326517585").unwrap(),
        <Fp as std::str::FromStr>::from_str("5359779630837471919145405238596268591478195733546546739332100097411048452487104831506370355931579775006693301412204").unwrap(),
    )),
    ((
        <Fp as std::str::FromStr>::from_str("4912629693851117772591702754589926177602243346341736359735620883075700657248663514800994171572416686862701598040294").unwrap(),
        <Fp as std::str::FromStr>::from_str("2794185062119289427523238682792616130309230555534887179162536305702134719463420582069235713945987038549058324304842").unwrap(),
        <Fp as std::str::FromStr>::from_str("3668223185428705024105634945468964677340747480621538612583082295495362070898686851667449577863086303167734794958118").unwrap(),
        <Fp as std::str::FromStr>::from_str("1885533985152336743493791299787961985646628264863373253608270911882442035474983148909516194256200071297408931047513").unwrap(),
        <Fp as std::str::FromStr>::from_str("96577215787938354987539681438019148827270900406281053757281455870574490941975371463616142503892007018305065354990").unwrap(),
        <Fp as std::str::FromStr>::from_str("4590975612751681948840858609050355920090572361116944721088634123872268678971064004628732396556002735369572335641001").unwrap(),
    )),
    ((
        <Fp as std::str::FromStr>::from_str("1911057726536241295027707664426124497399379763866398366535692190141197755421585992526481373383742936016531519006971").unwrap(),
        <Fp as std::str::FromStr>::from_str("4767708062186886007204177389565948024439321902322222101514656319135279446572606976792211881563818963207465590202391").unwrap(),
        <Fp as std::str::FromStr>::from_str("1907033740076880931314857394526569925369503087727191592341538222127746347304051994688995974775713845723667345181865").unwrap(),
        <Fp as std::str::FromStr>::from_str("1576971660752356241883555524353080145175730420061533971632037189630762455211281262541408736807970856276220818929667").unwrap(),
        <Fp as std::str::FromStr>::from_str("829503277983351805259157580650425085639218298706140884831455228147071806891928077167672811837789611280449655050214").unwrap(),
        <Fp as std::str::FromStr>::from_str("1756398464986740625913060543533736393413666564249415436116821095310039259507115581393336410392807276157514835984499").unwrap(),
    )),
    ((
        <Fp as std::str::FromStr>::from_str("5024337537369005450568077688628459393381053291298376139972369846636479216251457004526489591434290880052740831323389").unwrap(),
        <Fp as std::str::FromStr>::from_str("243329854482099088875583668867255119261847081329212788111638378936806454156107058103196419674662040624666327192506").unwrap(),
        <Fp as std::str::FromStr>::from_str("4330163545923343810833214709269503909832448706659644591106183495009742425384776692209008020460802074034919882667156").unwrap(),
        <Fp as std::str::FromStr>::from_str("4746252481910923699031058431580647024618534370378744699707723637711718386819960443169105215582630805164566477915061").unwrap(),
        <Fp as std::str::FromStr>::from_str("4881904098552530317258681428870637086020848720937983433810060733832775275290507396271847059064285333750025015634555").unwrap(),
        <Fp as std::str::FromStr>::from_str("5533410041726567478516247267400321578296447732553340181372821608372766127968688407858150948235568435315038109321862").unwrap(),
    )),
    ((
        <Fp as std::str::FromStr>::from_str("970488399982572621523416338345697693754377405072362363350911261719989500807800736022320682081707538986984963195903").unwrap(),
        <Fp as std::str::FromStr>::from_str("2889776142353439084565779169764141093305210999753671948339956878173834062323396587087003698941509191636828412358371").unwrap(),
        <Fp as std::str::FromStr>::from_str("3795770522092825694576578189765811809029572199748020189153305452621968802363915137823591748554135968046298920834815").unwrap(),
        <Fp as std::str::FromStr>::from_str("1370588897308522589002735579591748157760974937243710348850465791283211725475054776537830886721435077995422031781461").unwrap(),
        <Fp as std::str::FromStr>::from_str("1556482929005394304300371586952479480345522015024596090660772863731774844815426547463537002235381701522069766536218").unwrap(),
        <Fp as std::str::FromStr>::from_str("2440771835720874093456981432602912746214896524570412137643602573594284517320646831335034391207075189412012475745043").unwrap(),
    )),
    ((
        <Fp as std::str::FromStr>::from_str("3499956327053992311789324315745279077218711522574396611145654815527085555633655891265950097145267897724655566156082").unwrap(),
        <Fp as std::str::FromStr>::from_str("4250726341623352245859193814958075653932439210552578930150640874506143643848176011936425569339283499036976370918547").unwrap(),
        <Fp as std::str::FromStr>::from_str("2277075619467092361075441637545474462708156505551901231294431119215104787945869965412279606012444168553048751531305").unwrap(),
        <Fp as std::str::FromStr>::from_str("5156632548154372308314396817752082262448465615602291512087163669501834087315996859928625857489259758171314588058684").unwrap(),
        <Fp as std::str::FromStr>::from_str("3549623035990464287836624902127543074314683544616644069999418936977157601068501815160870430922313809765697470461011").unwrap(),
        <Fp as std::str::FromStr>::from_str("4149192748600852083475900035990630534222222056341700086574476023821578193169627468582105359207744587896137324600702").unwrap(),
    ))]
}
