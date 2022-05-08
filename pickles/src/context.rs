/// A recursive context can enforce constraints on "both side".
/// 
/// 
/// It has a "current side" (a proof system over Fp)
/// and a "complement side" (a proof system over Fp).
/// 
/// This enables us to have the entire computation for the verification of the
/// PlonK proof and accumulation described together and "prodecuurally"; 
/// even though the verification is spread across two proof systems.
/// 
/// By "flipping" the context and applying the same set of constraints obtain 
/// the full set of constraints for both sides.
/// 
/// This avoids writing the verifier twice: once for each side.
struct RecursiveContext {

}