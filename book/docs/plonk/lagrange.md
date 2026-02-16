# Lagrange basis in multiplicative subgroups

What's a lagrange base?

$L_i(x) = 1$ if $x = g^i$, $0$ otherwise.

## What's the formula?

[Arkworks](https://github.com/arkworks-rs/algebra/blob/e7eeea3f2ac7d621f68089b978097403dd02e91b/poly/src/domain/radix2/mod.rs#L116)
has the formula to construct a lagrange base:

> Evaluate all Lagrange polynomials at $\tau$ to get the lagrange coefficients.
> Define the following as
>
> - $H$: The coset we are in, with generator $g$ and offset $h$
> - $m$: The size of the coset $H$
> - $Z_H$: The vanishing polynomial for $H$.
>   $Z_H(x) = \prod_{i \in [m]} (x - h \cdot g^i) = x^m - h^m$
> - $v_i$: A sequence of values, where $v_0 = \frac{1}{m * h^{m-1}}$, and
>   $v_{i + 1} = g \cdot v_i$
>
> We then compute $L_{i,H}(\tau)$ as
> $L_{i,H}(\tau) = Z_H(\tau) \cdot \frac{v_i}{\tau - h g^i}$
>
> However, if $\tau$ in $H$, both the numerator and denominator equal 0 when i
> corresponds to the value tau equals, and the coefficient is 0 everywhere else.
> We handle this case separately, and we can easily detect by checking if the
> vanishing poly is 0.

following this, for $h=1$ we have:

- $L_0(x) = \frac{Z_H(x)}{m(x-1)}$
- $L_1(x) = \frac{Z_H(x)g}{m(x-g)}$
- $L_2(x) = \frac{Z_H(x)g^2}{m(x-g^2)}$
- and so on

## What's the logic here?

https://en.wikipedia.org/wiki/Lagrange_polynomial#Barycentric_form
