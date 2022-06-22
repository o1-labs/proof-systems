# Domain

Plonk needs a domain to encode the circuit on (for each point we can encode a row/constraint/gate).
We choose a domain $H$ such that it is a multiplicative subgroup of the scalar field of our curve.

## 2-adicity

Furthermore, as FFT (used for interpolation, [see the section on FFTs](https://o1-labs.github.io/proof-systems/fundamentals/zkbook_fft.html)) works best in domains of size $2^k$ for some $k$, we choose $H$ to be a subgroup of order $2^k$.

Since the [pasta curves](https://o1-labs.github.io/proof-systems/specs/pasta.html) both have scalar fields of prime orders $p$ and $q$, their multiplicative subgroup is of order $p-1$ and $q-1$ respectively (without the zero element). 
[The pasta curves were generated](https://forum.zcashcommunity.com/t/noob-question-about-plonk-halo2/39098) specifically so that both $p-1$ and $q-1$ are multiples of $2^{32}$.

We say that they have *2-adicity* of 32.

Looking at the definition of one of the pasta fields in [Rust](https://github.com/o1-labs/proof-systems/blob/c3883db4d96e847591ec98682e37511ea5ab826a/curves/src/pasta/fields/fq.rs#L13) you can see that it is defined specifically for a trait related to FFTs:

```rust
impl FftParameters for FqParameters {
    type BigInt = BigInteger;

    const TWO_ADICITY: u32 = 32;

    #[rustfmt::skip]
    const TWO_ADIC_ROOT_OF_UNITY: BigInteger = BigInteger([
        0x218077428c9942de, 0xcc49578921b60494, 0xac2e5d27b2efbee2, 0xb79fa897f2db056
    ]);
```

The 2-adicity of 32 means that there's a multiplicative subgroup of size $2^{32}$ that exists in the field.
The code above also defines a generator $g$ for it, such that $g^{2^{32}} = 1$ and $g^i \neq 1$ for $i \in [[1, 2^{32}-1]]$ (so it's a **primitive** $2^{32}$-th root of unity).

[Lagrange's theorem](https://en.wikipedia.org/wiki/Lagrange%27s_theorem_(group_theory\)) tells us that if we have a group of order $n$, then we'll have subgroups with orders dividing $n$. So in our case, we have subgroups with all the powers of 2, up to the 32-th power of 2.

To find any of these groups, it is pretty straight forward as well. Notice that:

* let $h = g^2$, then $h^{2^{31}} = g^{2^{32}} = 1$ and so $h$ generates a subgroup of order 31
* let $t = g^{2^2}$, then $t^{2^{30}} = g^{2^{32}} = 1$ and so $t$ generates a subgroup of order 30
* and so on...

In [arkworks](https://github.com/arkworks-rs/algebra/blob/master/ff/src/fields/mod.rs#L216) you can see how this is implemented:

```rust
let size = n.next_power_of_two() as u64;
let log_size_of_group = ark_std::log2(usize::try_from(size).expect("too large"));
omega = Self::TWO_ADIC_ROOT_OF_UNITY;
for _ in log_size_of_group..Self::TWO_ADICITY {
    omega.square_in_place();
}
```

this allows you to easily find subgroups of different sizes of powers of 2, which is useful in zero-knowledge proof systems as FFT optimizations apply well on domains that are powers of 2. You can read more about that in the [mina book](https://o1-labs.github.io/proof-systems/fundamentals/zkbook_fft.html).

## Efficient computation of the vanishing polynomial

For each curve, we generate a domain $H$ as the set $H = {1, \omega, \omega^2, \cdots, \omega^{n-1}}$. 
As we work in a multiplicative subgroup, the polynomial that vanishes in all of these points can be written and efficiently calculated as $Z_H(x) = x^{|H|} - 1$.  
This is because, by definition, $\omega^{|H|} = 1$. If $x \in H$, then $x = \omega^i$ for some $i$, and we have:

$$x^{|H|} = (\omega^i)^{|H|} = (\omega^{|H|})^i = 1^i = 1$$

This optimization is important, as without it calculating the vanishing polynomial would take a number of operations linear in $|H|$ (which is not doable in a verifier circuit, for recursion). 
With the optimization, it takes us a logarithmic number of operation (using [exponentiation by squaring](https://en.wikipedia.org/wiki/Exponentiation_by_squaring)) to calculate the vanishing polynomial.
