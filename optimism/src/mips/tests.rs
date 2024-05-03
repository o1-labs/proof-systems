use crate::{
    folding::Curve,
    mips::{
        constraints::Env,
        interpreter::{
            ITypeInstruction::{self, *},
            Instruction::{self, *},
            JTypeInstruction::{self, *},
            RTypeInstruction::{self, *},
        },
        trace::MIPSTrace,
    },
    trace::Tracer,
};
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain as D};
use folding::{expressions::FoldingCompatibleExpr, FoldingScheme};
use strum::{EnumCount, IntoEnumIterator};

use super::folding::{MIPSFoldingConfig, MIPSStructure};

type Fp = ark_bn254::Fr;

// Manually change the number of constraints if they are modififed in the interpreter
#[test]
fn test_mips_number_constraints() {
    let domain_size = 1 << 8;

    // Initialize the environment and run the interpreter
    let mut constraints_env = Env::<Fp> {
        scratch_state_idx: 0,
        constraints: Vec::new(),
        lookups: Vec::new(),
    };

    // Keep track of the constraints and lookups of the sub-circuits
    let mips_circuit = MIPSTrace::<Fp>::new(domain_size, &mut constraints_env);

    let assert_num_constraints = |instr: &Instruction, num: usize| {
        assert_eq!(mips_circuit.constraints.get(instr).unwrap().len(), num)
    };

    let mut i = 0;
    for instr in Instruction::iter().flat_map(|x| x.into_iter()) {
        match instr {
            RType(rtype) => match rtype {
                JumpRegister | SyscallExitGroup | Sync => assert_num_constraints(&instr, 0),
                ShiftLeftLogical
                | ShiftRightLogical
                | ShiftRightArithmetic
                | ShiftLeftLogicalVariable
                | ShiftRightLogicalVariable
                | ShiftRightArithmeticVariable
                | JumpAndLinkRegister
                | SyscallReadHint
                | MoveFromHi
                | MoveFromLo
                | MoveToLo
                | MoveToHi
                | Add
                | AddUnsigned
                | Sub
                | SubUnsigned
                | And
                | Or
                | Xor
                | Nor
                | SetLessThan
                | SetLessThanUnsigned
                | MultiplyToRegister
                | CountLeadingOnes
                | CountLeadingZeros => assert_num_constraints(&instr, 3),
                MoveZero | MoveNonZero => assert_num_constraints(&instr, 5),
                SyscallReadOther | SyscallWriteHint | SyscallWriteOther | Multiply
                | MultiplyUnsigned | Div | DivUnsigned => assert_num_constraints(&instr, 6),
                SyscallOther => assert_num_constraints(&instr, 10),
                SyscallMmap => assert_num_constraints(&instr, 11),
                SyscallReadPreimage => assert_num_constraints(&instr, 21),
                SyscallFcntl => assert_num_constraints(&instr, 22),
                SyscallWritePreimage => assert_num_constraints(&instr, 30),
            },
            JType(jtype) => match jtype {
                Jump => assert_num_constraints(&instr, 0),
                JumpAndLink => assert_num_constraints(&instr, 3),
            },
            IType(itype) => match itype {
                BranchLeqZero | BranchGtZero | BranchLtZero | BranchGeqZero | Store8 | Store16 => {
                    assert_num_constraints(&instr, 0)
                }
                BranchEq | BranchNeq | Store32 => assert_num_constraints(&instr, 2),
                AddImmediate
                | AddImmediateUnsigned
                | SetLessThanImmediate
                | SetLessThanImmediateUnsigned
                | AndImmediate
                | OrImmediate
                | XorImmediate
                | LoadUpperImmediate
                | Load8
                | Load16
                | Load32
                | Load8Unsigned
                | Load16Unsigned
                | Store32Conditional => assert_num_constraints(&instr, 3),
                LoadWordLeft | LoadWordRight | StoreWordLeft | StoreWordRight => {
                    assert_num_constraints(&instr, 12)
                }
            },
        }
        i += 1;
    }
    assert_eq!(
        i,
        RTypeInstruction::COUNT + JTypeInstruction::COUNT + ITypeInstruction::COUNT
    );
}

#[test]
fn test_folding_mips_add_constraint() {
    let domain_size = 1 << 8;
    let domain = D::<Fp>::new(domain_size).unwrap();

    let mut srs = poly_commitment::srs::SRS::<Curve>::create(2);
    srs.add_lagrange_basis(domain);

    // Initialize the environment and run the interpreter
    let mut constraints_env = Env::<Fp> {
        scratch_state_idx: 0,
        constraints: Vec::new(),
        lookups: Vec::new(),
    };

    // Keep track of the constraints and lookups of the sub-circuits
    let mips_circuit = MIPSTrace::<Fp>::new(domain_size, &mut constraints_env);
    let add_constraints = &mips_circuit.constraints[&Instruction::RType(Add)];
    let add_constraints: Vec<FoldingCompatibleExpr<MIPSFoldingConfig>> = add_constraints
        .iter()
        .map(|x| FoldingCompatibleExpr::from(x.clone()))
        .collect::<Vec<_>>();
    let (folded_expr, ext_witness) =
        folding::expressions::folding_expression(add_constraints.clone());

    let structure = MIPSStructure {};

    // let left_instance = MIPSFoldingInstance {};
    let scheme = FoldingScheme::new(add_constraints, srs, domain, structure);
    // println!("{:?}", scheme.expression)
}
