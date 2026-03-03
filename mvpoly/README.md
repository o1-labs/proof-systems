# MVPoly: play with multi-variate polynomials

This library aims to provide algorithms and different representations to
manipulate multivariate polynomials.

## Notation

$\mathbb{F}^{\le d}[X_1, \cdots, X_{N}]$ is the vector space over the finite
field $\mathbb{F}$ of multivariate polynomials with $N$ variables and of maximum
degree $d$.

For instance, for multivariate polynomials with two variables, and maximum
degree 2, the set is

```math
\mathbb{F}^{\le 2}[X_{1}, X_{2}] = \left\{ a_{0} + a_{1} X_{1} + a_{2} X_{2} + a_{3} X_{1} X_{2} + a_{4} X_{1}^2 + a_{5} X_{2}^2 \, | \, a_{i} \in \mathbb{F} \right\}
```

The normal form of a multivariate polynomials is the multi-variate polynomials
whose monomials are all different, i.e. the coefficients are in the "canonical"
(sic) base
$\{ \prod_{k = 1}^{N} X_{i_{1}}^{n_{i_{1}}} \cdots X_{i_{k}}^{n_{k}}
\}$ where
$\sum_{k = 1}^{N} n_{i_{k}} \le d$.

For instance, the canonical base of $\mathbb{F}^{\le 2}[X_{1}, X_{2}]$ is the
set $\{ 1, X_{1}, X_{2}, X_{1} X_{2}, X_{1}^2, X_{2}^2 \}$

Examples:

- $X_{1} + X_{2}$ is in normal form
- $X_{1} + 42 X_{1}$ is not in normal form
- $X_{1} (X_{1} + X_{2})$ is not in normal form
- $X_{1}^2 + X_{1} X_{2}$ is in normal form

## Resources

This README is partially or fully imported from the document
[Sympolyc - symbolic computation on multi-variate polynomials using prime numbers](https://hackmd.io/@dannywillems/SyHar7p5A)
