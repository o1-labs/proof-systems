/*********************************************************************************************************

This source file tests constraints for the Weierstrass curve y^2 = x^3 + 7 group addition
of non-special pairs of points

    (x2 - x1) * s = y2 - y1
    s * s = x1 + x2 + x3
    (x1 - x3) * s = y3 + y1

    For the variable labeling
    [1, x1, x2, x3, y1, y2, y3, s]

    the Index constraints are

    a=[[0,-1,1,0,0,0,0,0], [0,0,0,0,0,0,0,1], [0,1,0,-1,0,0,0,0]]
    b=[[0,0,0, 0,0,0,0,1], [0,0,0,0,0,0,0,1], [0,0,0,0,0,0,0,1]]
    c=[[0,0,0,0,-1,1,0,0], [0,1,1,1,0,0,0,0], [0,0,0,0,1,0,1,0]]

    The test verifies both positive and negative outcomes for satisfying and not satisfying witnesses

**********************************************************************************************************/

use algebra::{
    bn_382::{g1::Bn_382G1Parameters, Bn_382, Fp},
    One, Zero,
};
use colored::Colorize;
use marlin_protocol_pairing::{
    index::{Index, URSSpec},
    prover::ProverProof,
};
use oracle::{
    poseidon::{ArithmeticSpongeParams, MarlinSpongeConstants as SC},
    sponge::{DefaultFqSponge, DefaultFrSponge},
};
use rand_core::{OsRng, RngCore};
use sprs::{CsMat, CsVecView};
use std::time::Instant;
use std::{io, io::Write};

#[test]
fn pairing_marlin_group_addition() {
    test();
}

fn test()
where
    <Fp as std::str::FromStr>::Err: std::fmt::Debug,
{
    let rng = &mut OsRng;

    // field unity element
    let one = Fp::one();
    // field negative unit element
    let neg1 = -one;

    // our circuit cinstraint system

    let mut a = CsMat::<Fp>::zero((5, 8));
    let mut b = CsMat::<Fp>::zero((5, 8));
    let mut c = CsMat::<Fp>::zero((5, 8));

    a = a
        .append_outer_csvec(CsVecView::<Fp>::new_view(8, &[1, 2], &[neg1, one]).unwrap())
        .append_outer_csvec(CsVecView::<Fp>::new_view(8, &[7], &[one]).unwrap())
        .append_outer_csvec(CsVecView::<Fp>::new_view(8, &[1, 3], &[one, neg1]).unwrap());

    b = b
        .append_outer_csvec(CsVecView::<Fp>::new_view(8, &[7], &[one]).unwrap())
        .append_outer_csvec(CsVecView::<Fp>::new_view(8, &[7], &[one]).unwrap())
        .append_outer_csvec(CsVecView::<Fp>::new_view(8, &[7], &[one]).unwrap());

    c = c
        .append_outer_csvec(CsVecView::<Fp>::new_view(8, &[4, 5], &[neg1, one]).unwrap())
        .append_outer_csvec(CsVecView::<Fp>::new_view(8, &[1, 2, 3], &[one, one, one]).unwrap())
        .append_outer_csvec(CsVecView::<Fp>::new_view(8, &[4, 6], &[one, one]).unwrap());

    let index = Index::<Bn_382>::create(
        a,
        b,
        c,
        4,
        oracle::bn_382::fp::params() as ArithmeticSpongeParams<Fp>,
        oracle::bn_382::fq::params(),
        URSSpec::Generate(rng),
    )
    .unwrap();

    positive(&index, rng);
    negative(&index);
}

fn positive(index: &Index<Bn_382>, rng: &mut dyn RngCore)
where
    <Fp as std::str::FromStr>::Err: std::fmt::Debug,
{
    // We have the Index. Choose examples of satisfying witness for Jubjub
    let mut points = Vec::<(Fp, Fp, Fp, Fp, Fp, Fp)>::new();

    points.push
    ((
        <Fp as std::str::FromStr>::from_str("5172356774341916945486785014698808798139209652930291469942445827466617176873925086621674152688759641747407229992580").unwrap(),
        <Fp as std::str::FromStr>::from_str("5389835403017389419442092794364295847414750591777998334933723417842844526288891738232423481606681563583908752648585").unwrap(),
        <Fp as std::str::FromStr>::from_str("2546947049417344841111002212494667568252365848624282264487734777527422546757849528444366316986045677524512763495111").unwrap(),
        <Fp as std::str::FromStr>::from_str("1997638122333428225471467658615483900171126775340743769473169439761106892350780308959246670207945253590734533528364").unwrap(),
        <Fp as std::str::FromStr>::from_str("1674850877040352997414732903139735462343308610500259241884671999326597146560061364301738460545828640970450379452180").unwrap(),
        <Fp as std::str::FromStr>::from_str("3810650825927023273265535896307003193230881650215808774887308635589231174623309176102034870088533034962481600516076").unwrap(),
    ));
    points.push
    ((
        <Fp as std::str::FromStr>::from_str("3879795264457994863044345731122127563968659155286939955243630259499486647511831537480701720885511597385884746982820").unwrap(),
        <Fp as std::str::FromStr>::from_str("4823171665573330555096743029931952635270457039608368692692935088741396345392788384518311296090867219414881059352340").unwrap(),
        <Fp as std::str::FromStr>::from_str("1692323036934184376735474571456321002006109633293195186678241855264713104686985522712202951967918089219148092028572").unwrap(),
        <Fp as std::str::FromStr>::from_str("2209464651087650164731996745113926648329961483466062736793777916964189183192011121604379002548567728567290657913223").unwrap(),
        <Fp as std::str::FromStr>::from_str("2348163941780191517995518495987651490622892886012727100525794693244638137192599324030217113440751606847920180713803").unwrap(),
        <Fp as std::str::FromStr>::from_str("4454706851138822876793194715545840379207531303175432600221231008853712012121251240963548916110604582992115955653270").unwrap(),
    ));
    points.push
    ((
        <Fp as std::str::FromStr>::from_str("3400789538968233059173145658784600722588504237539048787023535803703264015099956088166134156568347966638071917915303").unwrap(),
        <Fp as std::str::FromStr>::from_str("621123523483818421378194114587761653395394010605097300573828630145594714262797932540228633935271287894833747678667").unwrap(),
        <Fp as std::str::FromStr>::from_str("1861078138229748651463580598306630340698695709298479313862504250753644022157264764048588857648999403515442211293648").unwrap(),
        <Fp as std::str::FromStr>::from_str("1402759138112536429766882866322191401455152786382634954470137274081091836807669830693235885007823455409845448532507").unwrap(),
        <Fp as std::str::FromStr>::from_str("2636112175785806489711342864806878604426303858096261709040701059465189456938740754404812820135345656228271794186839").unwrap(),
        <Fp as std::str::FromStr>::from_str("1256568754887691274941173078536147947138052455863623086244899444973367135605387356270847919765486881311208777164346").unwrap(),
    ));
    points.push
    ((
        <Fp as std::str::FromStr>::from_str("2478567523807803044823498814493552676784005345112820479889159785702537553699213407926528335598560536333529678173515").unwrap(),
        <Fp as std::str::FromStr>::from_str("1429610824224105819022096794824833725671346669787509086262428112046017634195256096695085888088513480739414116355434").unwrap(),
        <Fp as std::str::FromStr>::from_str("3433825202284744924898740933255472924238475834098304603334531696173905093307025097179470211930412153594898991640392").unwrap(),
        <Fp as std::str::FromStr>::from_str("5529106429103107036773519209541737196328462244684980153333799250346789650918590566278885361943445666893827919992773").unwrap(),
        <Fp as std::str::FromStr>::from_str("5249333193239921862286692659605834037127141134737902165494537075455136421133863013829009853775102133434705561997135").unwrap(),
        <Fp as std::str::FromStr>::from_str("5211707708935794515800600299494960538336380325290025964615311319580355838061988483441778157486971788761832422047706").unwrap(),
    ));
    points.push
    ((
        <Fp as std::str::FromStr>::from_str("147458112424376414621997978037198628281230983979066041123720454152322494857332053434681691878685856548608106856986").unwrap(),
        <Fp as std::str::FromStr>::from_str("632852117872999523570691722018024972892264322749710764059880290884632542786710748867063163428124193634651396659437").unwrap(),
        <Fp as std::str::FromStr>::from_str("5204093552607254614250701528632177968976746487946174226675406294342807100589579548450087150773804485277267337307130").unwrap(),
        <Fp as std::str::FromStr>::from_str("851406023642070633625219088663042661041353221500798086008906830050997727402745752304438325969120735726162271205108").unwrap(),
        <Fp as std::str::FromStr>::from_str("552295265751041791492069593853682243227582060223288941238331606487568169719678386470302944442375799241553902767182").unwrap(),
        <Fp as std::str::FromStr>::from_str("4336086719142104825567902974224061267890660930650361383496994062092647785535593948295151309544254618379516655470377").unwrap(),
    ));
    points.push
    ((
        <Fp as std::str::FromStr>::from_str("3490207600741665366625509959868394397282525671450798904036007522509182472793447492084168928458090353484314376763227").unwrap(),
        <Fp as std::str::FromStr>::from_str("1380831856252180204898789305050851997442924411267225484611979722147678679544436926354771128773582198021483648567385").unwrap(),
        <Fp as std::str::FromStr>::from_str("2120354557629067932550134046677825128518143332393404083881997101503789120924159322303640623764593822268029585313376").unwrap(),
        <Fp as std::str::FromStr>::from_str("1092991618363041304858357775932541289572587223808071420756973545520423631209105063078084300055221872301002741920688").unwrap(),
        <Fp as std::str::FromStr>::from_str("1605290030348149658176172535833602819662245808434194279040860609205244165195983512100400484862256425647560767969440").unwrap(),
        <Fp as std::str::FromStr>::from_str("2386993496848148656322316757008809090731757879923470103791246538433262277529128310992656680922383766720368477625156").unwrap(),
    ));
    points.push
    ((
        <Fp as std::str::FromStr>::from_str("1638374654853849195654124551691280460428083612823943462347619255956498862742720408888769748158996879556234032017620").unwrap(),
        <Fp as std::str::FromStr>::from_str("4696463046790812696644772536134730694383830429742760773846482828364760832740512122141679126896945492912370465987916").unwrap(),
        <Fp as std::str::FromStr>::from_str("3617243688932085408277715301069306617630380271027420929041113251867074342978965236280536563457836132453128954049534").unwrap(),
        <Fp as std::str::FromStr>::from_str("2710122816597306290503746828315039047582317305227168834547431135835634217761647011660061820624335511835127935174030").unwrap(),
        <Fp as std::str::FromStr>::from_str("921500447316892569376707206560342849122483342882261219690966701636629712782830468102915336061905457747788653057143").unwrap(),
        <Fp as std::str::FromStr>::from_str("5219418712123847153493507201307935981626191387915726486679485129683650510563888677270174906658570605360177547132711").unwrap(),
    ));
    points.push
    ((
        <Fp as std::str::FromStr>::from_str("576144473696397097973782254663713612741693587507998585657939643441374119925443781099855821247569616352554627949614").unwrap(),
        <Fp as std::str::FromStr>::from_str("5352236591966276361890332086598227314030542240238478455688676970553337435889652186551973571009168613697178579611699").unwrap(),
        <Fp as std::str::FromStr>::from_str("2828754515664145684784985226357118541310611243025336022554902550604084587189082200943584927907046900755954787015229").unwrap(),
        <Fp as std::str::FromStr>::from_str("3161205806116323471708492597862587351781150204219415964573810028295284392216145624207550645494399092340022177165126").unwrap(),
        <Fp as std::str::FromStr>::from_str("3902930166191849795957267143655917594898902685051373575284018871959934672462836199412877161316375535512304818449138").unwrap(),
        <Fp as std::str::FromStr>::from_str("3439537491778852191662884877340565420556723254526595771226976438865274837523196848563824604575428228181375925112367").unwrap(),
    ));
    points.push
    ((
        <Fp as std::str::FromStr>::from_str("3975857703851540404826772167355200868765839500201259530660426193330874994720636368264944650134867937994368133623424").unwrap(),
        <Fp as std::str::FromStr>::from_str("5404008797117176229768480661674266720465629504583055916114137135809171964682757270675407137380204829379800928806425").unwrap(),
        <Fp as std::str::FromStr>::from_str("5149775660547855706642619203137541130208039530617624930424186214694900226133029238205631813554575367645215651905718").unwrap(),
        <Fp as std::str::FromStr>::from_str("912560867533214342667610925727059581122160296223204528336760569329737606022773598716949469608418456841436717733650").unwrap(),
        <Fp as std::str::FromStr>::from_str("2361772560257806060391697637347795196697073007385082371009493637212597906287641517493257233187250924826177550515147").unwrap(),
        <Fp as std::str::FromStr>::from_str("1304527989810536849922023821350001495184930094181695710090607394133562298758385201023205221350985367173004379252620").unwrap(),
    ));
    points.push
    ((
        <Fp as std::str::FromStr>::from_str("5502226838017077786426654731704772400845471875650491266565363420906771040750427824367287841412217114884691397809929").unwrap(),
        <Fp as std::str::FromStr>::from_str("3558210182254086348603204259628694223851158529696790509955564950434596266578621349330875065217679787287369448875015").unwrap(),
        <Fp as std::str::FromStr>::from_str("1321172652000590462919749014481227416957437277585347677751917393570871798430478578222556789479124360282597488862528").unwrap(),
        <Fp as std::str::FromStr>::from_str("1817964682602513729710432198132831699408829439216417056703680523866007606577303266376792163132424248003554474817101").unwrap(),
        <Fp as std::str::FromStr>::from_str("3116498715141724683149051461624569979663973751357290170267796754661152457577855966867446609811524433931603777277670").unwrap(),
        <Fp as std::str::FromStr>::from_str("2773782014032351532784325670003998192667953688555790212612755975320369406749808761658203420299756946851710956379722").unwrap(),
    ));

    println!("{}", "Prover 1000 zk-proofs computation".green());
    let mut start = Instant::now();

    let tests = 0..1000;
    let mut batch = Vec::new();
    for test in tests.clone() {
        let (x1, y1, x2, y2, x3, y3) = points[test % 10];
        let s = (y2 - &y1) / &(x2 - &x1);

        let mut witness = vec![Fp::zero(); 8];
        witness[0] = Fp::one();
        witness[1] = x1;
        witness[2] = x2;
        witness[3] = x3;
        witness[4] = y1;
        witness[5] = y2;
        witness[6] = y3;
        witness[7] = s;

        // verify the circuit satisfiability by the computed witness
        assert_eq!(index.verify(&witness), true);

        // add the proof to the batch
        batch.push(ProverProof::create::<DefaultFqSponge<Bn_382G1Parameters, SC>, DefaultFrSponge<Fp, SC>>(&witness, &index).unwrap());

        print!("{:?}\r", test);
        io::stdout().flush().unwrap();
    }
    println!("{}{:?}", "Execution time: ".yellow(), start.elapsed());

    let verifier_index = index.verifier_index();
    // verify one proof serially
    match ProverProof::verify::<DefaultFqSponge<Bn_382G1Parameters, SC>, DefaultFrSponge<Fp, SC>>(
        &vec![batch[0].clone()],
        &verifier_index,
        rng,
    ) {
        Ok(_) => {}
        _ => panic!("Failure verifying the prover's proof"),
    }

    // verify the proofs in batch
    println!("{}", "Verifier zk-proofs verification".green());
    start = Instant::now();
    match ProverProof::verify::<DefaultFqSponge<Bn_382G1Parameters, SC>, DefaultFrSponge<Fp, SC>>(
        &batch,
        &verifier_index,
        rng,
    ) {
        Err(error) => panic!("Failure verifying the prover's proofs in batch: {}", error),
        Ok(_) => {
            println!("{}{:?}", "Execution time: ".yellow(), start.elapsed());
        }
    }
}

fn negative(index: &Index<Bn_382>)
where
    <Fp as std::str::FromStr>::Err: std::fmt::Debug,
{
    // build non-satisfying witness
    let x1 = <Fp as std::str::FromStr>::from_str("7502226838017077786426654731704772400845471875650491266565363420906771040750427824367287841412217114884691397809929").unwrap();
    let y1 = <Fp as std::str::FromStr>::from_str("3558210182254086348603204259628694223851158529696790509955564950434596266578621349330875065217679787287369448875015").unwrap();
    let x2 = <Fp as std::str::FromStr>::from_str("1321172652000590462919749014481227416957437277585347677751917393570871798430478578222556789479124360282597488862528").unwrap();
    let y2 = <Fp as std::str::FromStr>::from_str("1817964682602513729710432198132831699408829439216417056703680523866007606577303266376792163132424248003554474817101").unwrap();
    let x3 = <Fp as std::str::FromStr>::from_str("3116498715141724683149051461624569979663973751357290170267796754661152457577855966867446609811524433931603777277670").unwrap();
    let y3 = <Fp as std::str::FromStr>::from_str("2773782014032351532784325670003998192667953688555790212612755975320369406749808761658203420299756946851710956379722").unwrap();

    let s = (y2 - &y1) / &(x2 - &x1);

    let mut witness = vec![Fp::zero(); 8];
    witness[0] = Fp::one();
    witness[1] = x1;
    witness[2] = x2;
    witness[3] = x3;
    witness[4] = y1;
    witness[5] = y2;
    witness[6] = y3;
    witness[7] = s;

    // verify the circuit negative satisfiability by the computed witness
    assert_eq!(index.verify(&witness), false);

    // create proof
    match ProverProof::create::<DefaultFqSponge<Bn_382G1Parameters, SC>, DefaultFrSponge<Fp, SC>>(
        &witness, &index,
    ) {
        Ok(_) => panic!("Failure invalidating the witness"),
        _ => {}
    }
}
