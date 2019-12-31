/*********************************************************************************************************

This source file implements Sonic's zk-proof primitive unit test suite driver.
The following tests are implemented:

1.
   This tests proving/verification of group addition of embedded curve in Montgomery form.
 
    For the variable labeling
    [1, u1, u2, u3, v1, v2, v3, Y]

    the Index constraints are

    a=[[0,-1,1,0,0,0,0,0], [0,0,0,0,0,0,0,1], [0,1,0,-1,0,0,0,0]]
    b=[[0,0,0, 0,0,0,0,1], [0,0,0,0,0,0,0,1], [0,0,0,0,0,0,0,1]]
    c=[[0,0,0,0,-1,1,0,0], [40962,1,1,1,0,0,0,0], [0,0,0,0,1,0,1,0]]

    The test verifies both positive and negative outcomes for satisfying and not satisfying witnesses

**********************************************************************************************************/

use circuits::index::Index;
use sprs::{CsMat, CsVecView};
use algebra::{Field, PairingEngine, curves::bls12_381::Bls12_381, UniformRand};
use oracle::poseidon::ArithmeticSpongeParams;
use protocol::prover::ProverProof;
use rand_core::{RngCore, OsRng};
use std::{io, io::Write};
use std::time::Instant;
use colored::Colorize;

// Poseidon MDS Matrix from Vandermonde's A*(B^(-1)) for SPONGE_CAPACITY+SPONGE_RATE=3
pub const MDS: [[&str; 3]; 3] = 
[[
    "6554484396890773809930967563523245729711319062565954727825457337492322648072",
    "13108968793781547619861935127046491459422638125131909455650914674984645296109",
    "32772421984453869049654837817616228648556595312829773639127286687461613240333"
],[
    "32772421984453869049654837817616228648556595312829773639127286687461613240325",
    "13108968793781547619861935127046491459422638125131909455650914674984645296117",
    "6554484396890773809930967563523245729711319062565954727825457337492322648072"
],[
    "6554484396890773809930967563523245729711319062565954727825457337492322648066",
    "13108968793781547619861935127046491459422638125131909455650914674984645296123",
    "32772421984453869049654837817616228648556595312829773639127286687461613240325"
]];

#[test]
fn group_addition()
{
    test::<Bls12_381>();
}

fn test<E: PairingEngine>()
where <E::Fr as std::str::FromStr>::Err : std::fmt::Debug
{
    let rng = &mut OsRng;

    // field unity element
    let one = E::Fr::one();
    // field negative unit element
    let neg1 = -one;
    // Jubjub Montgomery form addition coefficient
    let d = <E::Fr as std::str::FromStr>::from_str("40962").unwrap();

    // our circuit cinstraint system

    let mut a = CsMat::<E::Fr>::zero((5, 8));
    let mut b = CsMat::<E::Fr>::zero((5, 8));
    let mut c = CsMat::<E::Fr>::zero((5, 8));
    
    a = a
    .append_outer_csvec(CsVecView::<E::Fr>::new_view(8, &[1, 2], &[neg1, one]).unwrap())
    .append_outer_csvec(CsVecView::<E::Fr>::new_view(8, &[7], &[one]).unwrap())
    .append_outer_csvec(CsVecView::<E::Fr>::new_view(8, &[1, 3], &[one, neg1]).unwrap());

    b = b
    .append_outer_csvec(CsVecView::<E::Fr>::new_view(8, &[7], &[one]).unwrap())
    .append_outer_csvec(CsVecView::<E::Fr>::new_view(8, &[7], &[one]).unwrap())
    .append_outer_csvec(CsVecView::<E::Fr>::new_view(8, &[7], &[one]).unwrap());

    c = c
    .append_outer_csvec(CsVecView::<E::Fr>::new_view(8, &[4, 5], &[neg1, one]).unwrap())
    .append_outer_csvec(CsVecView::<E::Fr>::new_view(8, &[0, 1, 2, 3], &[d, one, one, one]).unwrap())
    .append_outer_csvec(CsVecView::<E::Fr>::new_view(8, &[4, 6], &[one, one]).unwrap());

    // initialise the random oracle argument parameters
    let oracle_params = ArithmeticSpongeParams::<E::Fr>
    {
        round_constants: (0..oracle::poseidon::ROUNDS_FULL+oracle::poseidon::ROUNDS_PARTIAL).map
        (
            |_| (0..oracle::poseidon::SPONGE_CAPACITY+oracle::poseidon::SPONGE_RATE).map
            (
                |_| E::Fr::rand(rng)
            ).collect()
        ).collect(),
        mds: (0..oracle::poseidon::SPONGE_CAPACITY+oracle::poseidon::SPONGE_RATE).map
        (
            |i| (0..oracle::poseidon::SPONGE_CAPACITY+oracle::poseidon::SPONGE_RATE).map
            (
                |j| <E::Fr as std::str::FromStr>::from_str(MDS[i][j]).unwrap()
            ).collect()
        ).collect(),
    };
    
    let index = Index::<E>::create(a, b, c, 4, oracle_params, rng).unwrap();

    positive::<E>(&index, rng);
    negative::<E>(&index);
}

fn positive<E: PairingEngine>(index: &Index<E>, rng: &mut dyn RngCore)
where <E::Fr as std::str::FromStr>::Err : std::fmt::Debug
{
    // We have the Index. Choose examples of satisfying witness for Jubjub
    let mut points = Vec::<(E::Fr, E::Fr, E::Fr, E::Fr, E::Fr, E::Fr)>::new();

    points.push
    ((
        <E::Fr as std::str::FromStr>::from_str("39900598045146223012556756807716424920707335624137772245793491633339245372791").unwrap(),
        <E::Fr as std::str::FromStr>::from_str("19522610678632181139421280814026404919985207966775669026179774191871943606653").unwrap(),
        <E::Fr as std::str::FromStr>::from_str("48934197009989825167092991726526856222164328684663249331109093477852060147733").unwrap(),
        <E::Fr as std::str::FromStr>::from_str("50259096194254601167318912534944730666226542320105166560321209423694650606560").unwrap(),
        <E::Fr as std::str::FromStr>::from_str("15764515098774177790925239246620906431547002604118650577468142494717802796928").unwrap(),
        <E::Fr as std::str::FromStr>::from_str("14798732615325349150320979963320223428315543728625063775641382092536664162688").unwrap(),
    ));
    points.push
    ((
        <E::Fr as std::str::FromStr>::from_str("25923147474075979060069318338116392787656784280616804797759495145164998750021").unwrap(),
        <E::Fr as std::str::FromStr>::from_str("43716254578720109487651597428661379925224843777261181628927821656821439339630").unwrap(),
        <E::Fr as std::str::FromStr>::from_str("42351814681451076199151323152124820305934300093844054116718111869480103233650").unwrap(),
        <E::Fr as std::str::FromStr>::from_str("33881819653570791195447169439202897827354386499031828990184061410002974805330").unwrap(),
        <E::Fr as std::str::FromStr>::from_str("4919844538762573811646856872009784538366778683480473304055379853715249098731").unwrap(),
        <E::Fr as std::str::FromStr>::from_str("37178397273534670577282229522392576998356064005415185099039278104178450762066").unwrap(),
    ));
    points.push
    ((
        <E::Fr as std::str::FromStr>::from_str("49017653408850725625526739137749442711130293011461072028820982007427442474311").unwrap(),
        <E::Fr as std::str::FromStr>::from_str("25847932691890007963269784216717895585361519157640866417075879502154730649075").unwrap(),
        <E::Fr as std::str::FromStr>::from_str("1417454226453017291218116736204838576301351597793326913043029045106151784994").unwrap(),
        <E::Fr as std::str::FromStr>::from_str("40323235498636709761851172717541146797170372392633912248703639124508961560").unwrap(),
        <E::Fr as std::str::FromStr>::from_str("12347121789936658511417879690123577523933914904280795738962042080575618558").unwrap(),
        <E::Fr as std::str::FromStr>::from_str("30870235433925418398744757705220790186842952065670620752935356701301433694095").unwrap(),
    ));
    points.push
    ((
        <E::Fr as std::str::FromStr>::from_str("50407445900087190258647900510129953661566228269153638729287654708468628548149").unwrap(),
        <E::Fr as std::str::FromStr>::from_str("42131569337029807235568807494705645840092877557895330618612226498178753946301").unwrap(),
        <E::Fr as std::str::FromStr>::from_str("45017302044410486710144166782608618045244636428035919462957881180439003368113").unwrap(),
        <E::Fr as std::str::FromStr>::from_str("17756010222368362404102981402468850213318191927820483846861529406441266214616").unwrap(),
        <E::Fr as std::str::FromStr>::from_str("3803857341411941868296646887907664295373365080355103999656672070297191821615").unwrap(),
        <E::Fr as std::str::FromStr>::from_str("17917698495221735539209745678811901837522872093346963791550899704180888036814").unwrap(),
    ));
    points.push
    ((
        <E::Fr as std::str::FromStr>::from_str("39434512678821042837977786344565071643395789200619711779484090172119204696533").unwrap(),
        <E::Fr as std::str::FromStr>::from_str("37229574527601167826150681951987437487976204451899331224105508895922630568296").unwrap(),
        <E::Fr as std::str::FromStr>::from_str("8909072902815300909605251572086538912716507209132718125887625063838127142273").unwrap(),
        <E::Fr as std::str::FromStr>::from_str("12476961004117444853767019347070021560252202139025672749006802564487591743237").unwrap(),
        <E::Fr as std::str::FromStr>::from_str("24448742723005498332520090089099276434406069579534364418908345134775525937888").unwrap(),
        <E::Fr as std::str::FromStr>::from_str("36511972506683351992911653449146811038362058445454104206710389644272999979637").unwrap(),
    ));
    points.push
    ((
        <E::Fr as std::str::FromStr>::from_str("26267267509225569848570189385493424676157302444873989503737268345568005110842").unwrap(),
        <E::Fr as std::str::FromStr>::from_str("46864394310116524526110945640362388199456686929976787658848511610202492278975").unwrap(),
        <E::Fr as std::str::FromStr>::from_str("42040198019798563434906923629428709437494141305965974855182003736757686958259").unwrap(),
        <E::Fr as std::str::FromStr>::from_str("42339900487334446296790170152366997761749669456129036518298414530481222491191").unwrap(),
        <E::Fr as std::str::FromStr>::from_str("52320560905158183449562635356293969288350162348606839258510942373259235303324").unwrap(),
        <E::Fr as std::str::FromStr>::from_str("12255222056343319194833774493628167841180168154297644797838209037752854579298").unwrap(),
    ));
    points.push
    ((
        <E::Fr as std::str::FromStr>::from_str("28168695561358077041423914972411778296159803320146945958671045280834661984132").unwrap(),
        <E::Fr as std::str::FromStr>::from_str("23770181492689438318816668908601239322810123539474622446709928976179139523195").unwrap(),
        <E::Fr as std::str::FromStr>::from_str("50197222109216143847927475796771252109068830580274273565860016909731380608122").unwrap(),
        <E::Fr as std::str::FromStr>::from_str("18436545288098591847204186762639787940507497045709895415061458057731054565919").unwrap(),
        <E::Fr as std::str::FromStr>::from_str("203353093219926751426212021643739973737900116715505005573452245048022995515").unwrap(),
        <E::Fr as std::str::FromStr>::from_str("27096751056160717682866650645848013527240410399809693754718320597107576536989").unwrap(),
    ));
    points.push
    ((
        <E::Fr as std::str::FromStr>::from_str("3047585300220486775186385761995629408712884167626975485698673215079559659028").unwrap(),
        <E::Fr as std::str::FromStr>::from_str("44316558209011042750478822961402114478021207693616763477985366674075970237565").unwrap(),
        <E::Fr as std::str::FromStr>::from_str("43921079358130097079114333840167929845406088424304054060401465714502803460105").unwrap(),
        <E::Fr as std::str::FromStr>::from_str("23525839299811620822468278907451615711994234008702721633922487926510276482273").unwrap(),
        <E::Fr as std::str::FromStr>::from_str("48611556739008965878633651955991944068100826645606863579232314334091491171979").unwrap(),
        <E::Fr as std::str::FromStr>::from_str("35384551787706645254591459169017393860159686891708166898342316167470132685884").unwrap(),
    ));
    points.push
    ((
        <E::Fr as std::str::FromStr>::from_str("32300897011189717701486069559506283927361158032006801663709770356339949728434").unwrap(),
        <E::Fr as std::str::FromStr>::from_str("4792262399127520389571296737782042595856566899449218325866762357624127503947").unwrap(),
        <E::Fr as std::str::FromStr>::from_str("50748083862459041094904407372332762930775275468085712313733238756555231940766").unwrap(),
        <E::Fr as std::str::FromStr>::from_str("18297890693878418241021054700543016065414648979012238402321918444540283635434").unwrap(),
        <E::Fr as std::str::FromStr>::from_str("23749334057388782035828272592793647093924673458817560685690125814520613205841").unwrap(),
        <E::Fr as std::str::FromStr>::from_str("36115806328542306473108942886096076768163312770561662723332884129788581076291").unwrap(),
    ));
    points.push
    ((
        <E::Fr as std::str::FromStr>::from_str("39852354202995913793695433543111048321283540193151388345634935000286693893548").unwrap(),
        <E::Fr as std::str::FromStr>::from_str("7112897566948223533413450024582670398451578731102747206336237450904818869421").unwrap(),
        <E::Fr as std::str::FromStr>::from_str("47742978716127391399957310601677429575928319522663735571251979751589564787492").unwrap(),
        <E::Fr as std::str::FromStr>::from_str("39662282691335108286000052456311770561854941840149691725850674048185081470579").unwrap(),
        <E::Fr as std::str::FromStr>::from_str("7190154498413002977209247455961519161016925948694165088103243580443733642112").unwrap(),
        <E::Fr as std::str::FromStr>::from_str("35541982422800796674122523097737462421824916917516037181856471508900001129911").unwrap(),
    ));

    println!("{}", "Prover 1000 zk-proofs computation".green());
    let mut start = Instant::now();

    let tests = 0..1000;
    let mut batch = Vec::new();
    for test in tests.clone()
    {
        let (u1, v1, u2, v2, u3, v3) = points[test % 10];
        let y = (v2 - &v1) / &(u2 - &u1);
        
        let mut witness = vec![E::Fr::zero(); 8];
        witness[0] = E::Fr::one();
        witness[1] = u1;
        witness[2] = u2;
        witness[3] = u3;
        witness[4] = v1;
        witness[5] = v2;
        witness[6] = v3;
        witness[7] = y;

        // verify the circuit satisfiability by the computed witness
        assert_eq!(index.verify(&witness), true);

        // add the proof to the batch
        batch.push(ProverProof::<E>::create(&witness, &index).unwrap());

        print!("{:?}\r", test);
        io::stdout().flush().unwrap();
    }
    println!("{}{:?}", "Execution time: ".yellow(), start.elapsed());

    // verify one proof serially
    match ProverProof::<E>::verify(&vec![batch[0].clone()], &index, rng)
    {
        Ok(_) => {}
        _ => {panic!("Failure verifying the prover's proof")}
    }

    // verify the proofs in batch
    println!("{}", "Verifier zk-proofs verification".green());
    start = Instant::now();
    match ProverProof::<E>::verify(&batch, &index, rng)
    {
        Err(error) => {panic!("Failure verifying the prover's proofs in batch: {}", error)},
        Ok(_) => {println!("{}{:?}", "Execution time: ".yellow(), start.elapsed());}
    }
}

fn negative<E: PairingEngine>(index: &Index<E>)
where <E::Fr as std::str::FromStr>::Err : std::fmt::Debug
{
    // build non-satisfying witness
    let u1 = <E::Fr as std::str::FromStr>::from_str("79900598045146223012556756807716424920707335624137772245793491633339245372791").unwrap();
    let v1 = <E::Fr as std::str::FromStr>::from_str("19522610678632181139421280814026404919985207966775669026179774191871943606653").unwrap();
    let u2 = <E::Fr as std::str::FromStr>::from_str("48934197009989825167092991726526856222164328684663249331109093477852060147733").unwrap();
    let v2 = <E::Fr as std::str::FromStr>::from_str("50259096194254601167318912534944730666226542320105166560321209423694650606560").unwrap();
    let u3 = <E::Fr as std::str::FromStr>::from_str("15764515098774177790925239246620906431547002604118650577468142494717802796928").unwrap();
    let v3 = <E::Fr as std::str::FromStr>::from_str("14798732615325349150320979963320223428315543728625063775641382092536664162688").unwrap();

    let y = (v2 - &v1) / &(u2 - &u1);
    
    let mut witness = vec![E::Fr::zero(); 8];
    witness[0] = E::Fr::one();
    witness[1] = u1;
    witness[2] = u2;
    witness[3] = u3;
    witness[4] = v1;
    witness[5] = v2;
    witness[6] = v3;
    witness[7] = y;

    // verify the circuit negative satisfiability by the computed witness
    assert_eq!(index.verify(&witness), false);

    // create proof
    match ProverProof::<E>::create(&witness, &index)
    {
        Ok(_) => {panic!("Failure invalidating the witness")}
        _ => {}
    }
}
