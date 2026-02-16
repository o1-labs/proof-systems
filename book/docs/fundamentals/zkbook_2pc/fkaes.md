# Fixed-Key-AES Hashes

Using fixed-key AES as a hash function in this context can be traced back to the
work of Bellare et al. [BHKR13](https://eprint.iacr.org/2013/426.pdf), who
considered fixed-key AES for circuit garbling. Prior to that point, most
implementations of garbled circuits used a hash function such as $\sha$,
modelled as a random oracle. But Bellare et al. showed that using fixed-key AES
can be up to $50\times$ faster than using a cryptographic hash function due to
hardware support for AES provided by modern processors.

Prior to [BHKR13](https://eprint.iacr.org/2013/426.pdf) CPU time was the main
bottleneck for protocols based on circuit garbling; after the introduction of
fixed-key cipher garbling, network throughput became the dominant factor. For
this reason, fixed-key AES has been almost universally adopted in subsequent
implementations of garbled circuits.

Several instantiations of hash function based on fix-key AES are proposed
inspired by the work of Bellare et al. However, most of them have some security
flaws as pointed out by [GKWY20](https://eprint.iacr.org/2019/074.pdf). (GKWY20)
also proposes a provable secure instantiation satisfies the property called
Tweakable Circular Correlation Robustness (TCCR). More discussions about the
concrete security of fixed-key AES based hash are introduced in
[GKWWY20](https://eprint.iacr.org/2019/1168.pdf).

The TCCR hash based on fixed-key AES is defined as follows.

$$\sH(i,x) = \mathsf{TCCR\_Hash}(i,x) = \pi(\pi(x)\oplus i)\oplus\pi(x),$$ where
$x$ is a $128$-bit string, $i$ a public $128$-bit $\mathsf{tweak}$, and
$\pi(x) = \aes(k,x)$ for any fixed-key $k$.
