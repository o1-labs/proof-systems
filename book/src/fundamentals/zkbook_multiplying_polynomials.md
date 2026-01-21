### Multiplying polynomials

The algorithm that allows us to multiply polynomials in $O(n \log n)$ is called
the **Cooley-Tukey fast Fourier transform**, or **FFT** for short. It was
discovered by [Gauss](https://en.wikipedia.org/wiki/Carl_Friedrich_Gauss) 160
years earlier, but then separately rediscovered and publicized by Cooley-Tukey.

The heart of Cooley-Tukey FFT is actually about converting between coefficient
and evaluation representations, rather than the multiplication itself. Given
polynomials $p$ and $q$ in dense coefficient representation, it works like this.

1.  Convert $p$ and $q$ from coefficient to evaluation form in $O(n\log n)$
    using Cooley-Tukey FFT
2.  Compute $r = p*q$ in evaluation form by multiplying their points pairwise in
    $O(n)$
3.  Convert $r$ back to coefficient form in $O(n\log n)$ using the inverse
    Cooley-Tukey FFT

The key observation is that we can choose any $n$ distinct evaluation points to
represent any degree $n - 1$ polynomial. The Cooley-Tukey FFT works by selecting
points that yield an efficient FFT algorithm. These points are fixed and work
for any polynomials of a given degree.

The next section describes the Cooley-Tukey FFT in detail.
