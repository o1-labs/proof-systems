(* GC stress test for the kimchi-stubs OCaml FFI under an OCaml 5 runtime.

   Linking cleanly proves very little: the risk in the ocaml-rs 0.22 -> 1.x
   move is that values allocated by Rust are not correctly registered as GC
   roots, which shows up as silent memory corruption when the major GC runs
   or the heap is compacted, not as a link error.

   So this test does three things a smoke test would not:

     1. allocates a large number of custom blocks from Rust (CamlFp is a
        custom block holding a field element),
     2. keeps them reachable only from OCaml across forced major collections
        and heap compactions, which move blocks around, and
     3. reads every value back afterwards and checks it against a value
        computed independently, so a corrupted or stale pointer fails loudly
        instead of passing quietly.

   Run under OCAMLRUNPARAM=v=0x400 to see the collections actually happen. *)

type fp
type fp_vector

external fp_of_int : int -> fp = "caml_pasta_fp_of_int"
external fp_add : fp -> fp -> fp = "caml_pasta_fp_add"
external fp_mul : fp -> fp -> fp = "caml_pasta_fp_mul"
external fp_equal : fp -> fp -> bool = "caml_pasta_fp_equal"
external fp_to_string : fp -> string = "caml_pasta_fp_to_string"

external fp_vector_create : unit -> fp_vector = "caml_fp_vector_create"
external fp_vector_length : fp_vector -> int = "caml_fp_vector_length"
external fp_vector_emplace_back : fp_vector -> fp -> unit
  = "caml_fp_vector_emplace_back"
external fp_vector_get : fp_vector -> int -> fp = "caml_fp_vector_get"

let failures = ref 0

let check name cond =
  if not cond then begin
    incr failures;
    Printf.printf "  FAIL: %s\n%!" name
  end

(* Custom blocks allocated by Rust must survive major collections while only
   OCaml holds them. *)
let test_custom_blocks_survive_gc () =
  Printf.printf "custom blocks survive major GC + compaction\n%!";
  let n = 20_000 in
  let values = Array.init n (fun i -> fp_of_int i) in
  (* Churn the minor heap so the array's contents get promoted. *)
  for _ = 1 to 20 do
    ignore (Array.init 1_000 (fun i -> fp_of_int i))
  done;
  Gc.full_major ();
  Gc.compact ();
  (* Every element must still read back as the integer it was built from. *)
  let ok = ref true in
  Array.iteri
    (fun i v -> if not (fp_equal v (fp_of_int i)) then ok := false)
    values;
  check "all custom blocks intact after full_major + compact" !ok

(* Values produced by Rust and consumed by Rust again, across a GC. *)
let test_roundtrip_across_gc () =
  Printf.printf "arithmetic results survive GC between calls\n%!";
  let a = fp_of_int 111_111 in
  let b = fp_of_int 222_222 in
  let sum = fp_add a b in
  let product = fp_mul a b in
  Gc.full_major ();
  Gc.compact ();
  check "sum still correct after GC" (fp_equal sum (fp_of_int 333_333));
  check "sum survives re-addition" (fp_equal (fp_add a b) sum);
  check "product survives GC" (fp_equal (fp_mul a b) product)

(* Strings are allocated on the OCaml heap by Rust; a bad root registration
   here typically shows up as a garbled or truncated string. *)
let test_string_allocation () =
  Printf.printf "Rust-allocated OCaml strings survive GC\n%!";
  let strings = Array.init 5_000 (fun i -> fp_to_string (fp_of_int i)) in
  Gc.full_major ();
  Gc.compact ();
  let ok = ref true in
  Array.iteri
    (fun i s -> if s <> string_of_int i then ok := false)
    strings;
  check "all strings intact after GC" !ok

(* The Rc-backed custom pointer type, mutated from OCaml across collections. *)
let test_vector_across_gc () =
  Printf.printf "Rc-backed vectors survive GC while being mutated\n%!";
  let v = fp_vector_create () in
  for i = 0 to 4_999 do
    fp_vector_emplace_back v (fp_of_int i);
    if i mod 500 = 0 then Gc.full_major ()
  done;
  Gc.compact ();
  check "length preserved" (fp_vector_length v = 5_000);
  let ok = ref true in
  for i = 0 to 4_999 do
    if not (fp_equal (fp_vector_get v i) (fp_of_int i)) then ok := false
  done;
  check "all vector elements intact after GC" !ok

(* Allocate hard enough to force many collections on their own. *)
let test_allocation_pressure () =
  Printf.printf "sustained allocation pressure\n%!";
  let acc = ref (fp_of_int 0) in
  for i = 1 to 200_000 do
    acc := fp_add !acc (fp_of_int 1);
    if i mod 50_000 = 0 then Gc.full_major ()
  done;
  Gc.compact ();
  check "accumulator correct after 200k allocations"
    (fp_equal !acc (fp_of_int 200_000))

let () =
  Printf.printf "kimchi-stubs OCaml %s GC stress test\n%!" Sys.ocaml_version;
  test_custom_blocks_survive_gc ();
  test_roundtrip_across_gc ();
  test_string_allocation ();
  test_vector_across_gc ();
  test_allocation_pressure ();
  Gc.full_major ();
  Gc.compact ();
  if !failures = 0 then Printf.printf "\nOK: all GC checks passed\n%!"
  else begin
    Printf.printf "\nFAILED: %d check(s)\n%!" !failures;
    exit 1
  end
