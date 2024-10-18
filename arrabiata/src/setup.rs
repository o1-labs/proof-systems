#[derive(Clone, Debug)]
pub struct Env<C: ArrabiataCurve> {
    /// The parameter a is the coefficients of the elliptic curve in affine
    /// coordinates.
    pub a: BigInt,
    pub idx_var_pi: usize,
    // Add public selectors
    // pub selectors: Vec<Selector>,
    // Add activated gadget?
    // pub activated_gadget: Option<Gadget>,
}

impl<C: ArrabiataCurve> Env<C>
where
    <<C as CommitmentCurve>::Params as CurveConfig>::BaseField: PrimeField,
{
    pub fn new() -> Self {
        // This check might not be useful
        let a: BigInt = <C as CommitmentCurve>::Params::COEFF_A.to_biguint().into();
        assert!(
            a < C::ScalarField::modulus_biguint().into(),
            "a is too large"
        );
        // TODO: add selectors
        // TODO: add activate gadget?

        Self { a, idx_var_pi: 0 }
    }
}

/// An environment to build constraints.
/// The constraint environment is mostly useful when we want to perform a Nova
/// proof.
/// The constraint environment must be instantiated only once, at the last step
/// of the computation.
impl<C: ArrabiataCurve> InterpreterEnv for Env<C> {
    type Position = (Column, CurrOrNext);

    type Variable = E<C::ScalarField>;

    // No effect at setup time
    fn allocate(&mut self) -> Self::Position {}

    // Only witness + constraint environment.
    // This is used to allocate private input.
    fn allocate_next_row(&mut self) -> Self::Position {}

    // TODO: Maybe only witness
    fn read_position(&self, pos: Self::Position) -> Self::Variable {}

    // Important!
    fn allocate_public_input(&mut self) -> Self::Position {
        assert!(self.idx_var_pi < NUMBER_OF_PUBLIC_INPUTS, "Maximum number of public inputs reached ({NUMBER_OF_PUBLIC_INPUTS}), increase the number of public inputs");
        let pos = Column::PublicInput(self.idx_var_pi);
        self.idx_var_pi += 1;
        (pos, CurrOrNext::Curr)
    }

    fn constant(&self, value: BigInt) -> Self::Variable {
        let v = value.to_biguint().unwrap();
        let v = C::ScalarField::from_biguint(&v).unwrap();
        let v_inner = Operations::from(Literal(v));
        Self::Variable::constant(v_inner)
    }

    /// Return the corresponding expression regarding the selected public input
    fn write_public_input(&mut self, pos: Self::Position, _v: BigInt) -> Self::Variable {
        self.read_position(pos)
    }

    /// Return the corresponding expression regarding the selected column
    // Only witness + constraint environment.
    fn write_column(&mut self, pos: Self::Position, v: Self::Variable) -> Self::Variable {}

    // FIXME: do we need?
    fn activate_gadget(&mut self, gadget: Gadget) {}

    // FIXME: do we need?
    fn add_constraint(&mut self, constraint: Self::Variable) {}

    // FIXME: do we need?
    fn constrain_boolean(&mut self, x: Self::Variable) {}

    // FIXME: do we need?
    fn assert_zero(&mut self, x: Self::Variable) {
        self.add_constraint(x);
    }

    // FIXME: do we need?
    fn assert_equal(&mut self, _x: Self::Variable, _y: Self::Variable) {}

    // FIXME: do we need?
    unsafe fn bitmask_be(
        &mut self,
        x: &Self::Variable,
        _highest_bit: u32,
        _lowest_bit: u32,
        _pos: Self::Position,
    ) -> Self::Variable {
        x
    }

    // FIXME: do we need?
    fn square(&mut self, _pos: Self::Position, x: Self::Variable) -> Self::Variable {
        x
    }

    // This is witness-only. We simply return the corresponding expression to
    // use later in constraints
    fn fetch_input(&mut self, pos: Self::Position) -> Self::Variable {}

    fn reset(&mut self) {
        self.idx_var = 0;
        self.idx_var_next_row = 0;
        self.idx_var_pi = 0;
        self.constraints.clear();
        self.activated_gadget = None;
    }

    fn coin_folding_combiner(&mut self, pos: Self::Position) -> Self::Variable {
        self.read_position(pos)
    }

    fn load_poseidon_state(&mut self, pos: Self::Position, _i: usize) -> Self::Variable {
        self.read_position(pos)
    }

    // Witness-only
    unsafe fn save_poseidon_state(&mut self, _x: Self::Variable, _i: usize) {}

    fn get_poseidon_round_constant(
        &mut self,
        pos: Self::Position,
        _round: usize,
        _i: usize,
    ) -> Self::Variable {
        let (col, row) = pos;
        match col {
            Column::PublicInput(_) => (),
            _ => panic!("Only public inputs can be used as round constants"),
        };
        Expr::Atom(ExprInner::Cell(Variable { col, row }))
    }

    fn get_poseidon_mds_matrix(&mut self, i: usize, j: usize) -> Self::Variable {
        let v = C::sponge_params().mds[i][j];
        let v_inner = Operations::from(Literal(v));
        Self::Variable::constant(v_inner)
    }

    unsafe fn fetch_value_to_absorb(
        &mut self,
        pos: Self::Position,
        _curr_round: usize,
    ) -> Self::Variable {
        self.read_position(pos)
    }

    unsafe fn load_temporary_accumulators(
        &mut self,
        pos_x: Self::Position,
        pos_y: Self::Position,
        _side: Side,
    ) -> (Self::Variable, Self::Variable) {
        let x = self.read_position(pos_x);
        let y = self.read_position(pos_y);
        (x, y)
    }

    // witness only
    unsafe fn save_temporary_accumulators(
        &mut self,
        _x: Self::Variable,
        _y: Self::Variable,
        _side: Side,
    ) {
    }

    /// Inverse of a variable
    ///
    /// # Safety
    ///
    /// Zero is not allowed as an input.
    unsafe fn inverse(&mut self, pos: Self::Position, x: Self::Variable) -> Self::Variable {
        let v = self.read_position(pos);
        let res = v.clone() * x.clone();
        self.assert_equal(res.clone(), self.one());
        v
    }

    unsafe fn is_same_ec_point(
        &mut self,
        pos: Self::Position,
        _x1: Self::Variable,
        _y1: Self::Variable,
        _x2: Self::Variable,
        _y2: Self::Variable,
    ) -> Self::Variable {
        self.read_position(pos)
    }

    fn zero(&self) -> Self::Variable {
        self.constant(BigInt::from(0_usize))
    }

    fn one(&self) -> Self::Variable {
        self.constant(BigInt::from(1_usize))
    }

    /// Double the elliptic curve point given by the affine coordinates
    /// `(x1, y1)` and save the result in the registers `pos_x` and `pos_y`.
    fn double_ec_point(
        &mut self,
        pos_x: Self::Position,
        pos_y: Self::Position,
        x1: Self::Variable,
        y1: Self::Variable,
    ) -> (Self::Variable, Self::Variable) {
        let lambda = {
            let pos = self.allocate();
            self.read_position(pos)
        };
        let x3 = self.read_position(pos_x);
        let y3 = self.read_position(pos_y);

        // λ 2y1 = 3x1^2 + a
        let x1_square = x1.clone() * x1.clone();
        let two_x1_square = x1_square.clone() + x1_square.clone();
        let three_x1_square = two_x1_square.clone() + x1_square.clone();
        let two_y1 = y1.clone() + y1.clone();
        let res = lambda.clone() * two_y1 - (three_x1_square + self.constant(self.a.clone()));
        self.assert_zero(res);
        // x3 = λ^2 - 2 x1
        self.assert_equal(
            x3.clone(),
            lambda.clone() * lambda.clone() - x1.clone() - x1.clone(),
        );
        // y3 = λ(x1 - x3) - y1
        self.assert_equal(
            y3.clone(),
            lambda.clone() * (x1.clone() - x3.clone()) - y1.clone(),
        );
        (x3, y3.clone())
    }

    fn compute_lambda(
        &mut self,
        pos: Self::Position,
        is_same_point: Self::Variable,
        x1: Self::Variable,
        y1: Self::Variable,
        x2: Self::Variable,
        y2: Self::Variable,
    ) -> Self::Variable {
        let lambda = self.read_position(pos);
        let lhs = lambda.clone() * (x1.clone() - x2.clone()) - (y1.clone() - y2.clone());
        let rhs = {
            let x1_square = x1.clone() * x1.clone();
            let two_x1_square = x1_square.clone() + x1_square.clone();
            let three_x1_square = two_x1_square.clone() + x1_square.clone();
            let two_y1 = y1.clone() + y1.clone();
            lambda.clone() * two_y1 - (three_x1_square + self.constant(self.a.clone()))
        };
        let res = is_same_point.clone() * lhs + (self.one() - is_same_point.clone()) * rhs;
        self.assert_zero(res);
        lambda
    }
}
