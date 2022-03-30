# Domain

Plonk needs a domain to encode the circuit on. We choose a domain $H$ such that it is a multiplicative subgroup of the scalar field of our curve. Furthermore, as FFT (used for interpolation) works best in domains of size $2^k$ for some $k$, we choose $H$ to be a subgroup of order $2^k$.
Since the [pasta curves]() both have scalar fields of prime orders $p$ and $q$, their multiplicative subgroup is of order $p-1$ and $q-1$ respectively (without the zero element). 
As such, [the pasta curves were generated](https://forum.zcashcommunity.com/t/noob-question-about-plonk-halo2/39098) specifically to allow this:

> the fields of the Pasta curves that were generated for Halo 2 have $q-1$ as a multiple of $2^{32}$, so any power of $2$ up to $2^{32}$ can be used.

(see [Lagrange's theorem](https://en.wikipedia.org/wiki/Lagrange%27s_theorem_(group_theory)) for more details)

For each curve, we generate a domain $H$ as the set $H = {1, \omega, \omega^2, \cdots}$. As we work in a multiplicative subgroup, the polynomial that vanishes in all of these points can be written and efficiently calculated as $Z_H(x) = x^{|H|} - 1$.  
This is because, by definition, $\omega^{|H|} = 1$. If $x \in H$, then $x = \omega^i$ for some $i$, and we have:

$$x^{|H|} = (\omega^i)^{|H|} = (\omega^{|H|})^i = 1^i = 1$$
