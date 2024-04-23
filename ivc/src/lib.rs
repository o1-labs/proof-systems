pub mod poseidon;
// mod sumcheck;

/*
IVC circuit
inputs:
    private:
        - i
        - z_0 (final beta)
        - z_i (beta so far)
        - u_i (u_i.x = H(i,z_0,z_i,U_i))
        - U_i
outputs:
    private:
        - i + 1
        - z_0
        - z_{i+1} = f(z_i)
        - U{i+1} = fold(U_i,u_i)
    public:
        - H(i+1,z_0,z_{i+1},U_{i+1})

things to do:
    - hash U_i to check u_i.x and for the folding challenge r
    - hash u_i for the folding challenge
    - hash U_{i+1} for the output
    - fold challenges by native multiplication
    - fold commitments through msm
    - use subsets of the hashing to create the challenges used by msm and by ceirtain lookups
    - decompose scalars to be passed to be passed to msm
*/
