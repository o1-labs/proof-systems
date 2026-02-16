# OT Extension

To meet the large-scale demand of OTs, OT extensions can be used. An OT
extension protocol works by running a small number of base OTs that are used as
a base for obtaining many OTs via the use of cheap symmetric cryptographic
operations only. This is conceptually similar to hybrid encryption.

In this subsection, we focus on the maliciously secure OT extension presented in
[KOS15](https://eprint.iacr.org/2016/602.pdf).

To be compatible with the garbled circuit optimizations, Correlated OT (COT) is
considered here. COT is a variant of OT, where the sender chooses a secret
string $\Delta$ and the receiver has a choice bit $b$. After the protocol, then
sender obtains two strings $\sX_0 = \sX$ and $\sX_1 = \sX\oplus \Delta$ and the
receiver obtains $\sX_b$, where $\sX$ is a random string.

```text
                    Sender                               Receiver

                                      +----------+
                       Delta  ------->|          |<------ b
                                      | COT Prot.|
     x_0 = x, x_1 = x + Delta <-------|          |-------> x_b
                                      +----------+
```

**Notation**. Let $\lambda$ be the security parameter, we use $\lambda = 128$ in
zkOracles. Identify $\bF^\lambda_2$ with the finite field $\bF_{2^\lambda}$. Use
"$\cdot$" for multiplication in $\bF_{2^{ \lambda}}$ and "$\star$" for the
component-wise product in $\bF_{2}^\lambda$. Given a matrix $A$, denote its rows
by subindices $\mathbf{a}_i$ and its columns by superindices $\mathbf{a}^k$. Use
$\mathbf{v}[i]$ to denote the $i$-th entry of $\mathbf{v}$.

The KOS15 OT protocol to generate $\ell(\gg \lambda)$ OTs is described as
follows.

- **Initialize**
  1. The receiver samples $\lambda$ pairs of $\lambda$-bit seeds
     $\{(\mathbf{k}_0^i,\mathbf{k}_1^i)\}_{i=1}^\lambda$.

  2. The sender choose a uniformly random $\lambda$-bit string $\Delta$.

  3. The two parties calls the base OT with inputs $\Delta$ and
     $\{(\mathbf{k}_0^i,\mathbf{k}_1^i)\}_{i=1}^\lambda$.
     - Note that the sender acts as the receiver in the base OT, and the
       receiver acts as the sender in the base OT.

  4. The sender obtains $\mathbf{k}^i_{\Delta_i}$ for $i\in[\lambda]$.

- **Extend**
  1. The receiver takes as input the choice bits $x_1,...,x_\ell$, defines
     $\ell' = \ell + \lambda + s$, where $s$ is the statistic parameter, and we
     set $s = 40$ in zkOracles. Let
     $\mathbf{x} = x_1\|x_2\|...\|x_\ell\|\mathbf{x}'\in \bF_2^{\ell'}$, with
     $\mathbf{x}'\in\bF_2^{\ell'-\ell}$ uniformly chosen.

  2. The receiver defines vectors $\mathbf{x}_1,...,\mathbf{x}_{\ell'}$ as
     $\mathbf{x}_i = \mathbf{x}[i]\cdot (1,...,1)\in \bF_2^{\lambda}$ for
     $i\in[\ell']$.
  3. The receiver expands $\mathbf{k}_0^i$ and $\mathbf{k}_1^i$ with a pseudo
     random generator ($\prg$), letting
     $$\mathbf{t}_0^i = \prg(\mathbf{k}_0^i)\in\bF_2^{\ell'}~~\text{and}~~\mathbf{t}_1^i = \prg(\mathbf{k}_1^i)\in\bF_2^{\ell'}~~\text{for}~~ i\in[\lambda]$$

  4. The sender expands $\mathbf{k}^i_{\Delta_i}$ with the same $\prg$ and gets
     $$\mathbf{t}_{\Delta_i}^i = \prg(\mathbf{k}_{\Delta_i}^i)~~\text{for}~~ i\in[\lambda]$$

  5. The receiver computes
     $$\mathbf{u}^i = \mathbf{t}_0^i\oplus\mathbf{t}_1^i\oplus\mathbf{x}\in\bF_2^{\ell'}~~\text{for}~~i\in[\lambda]$$
     and sends them to the sender.

  6. The sender computes
     $$\mathbf{q}^i = \Delta_i\cdot \mathbf{u}^i \oplus \mathbf{t}^i_{\Delta_i} = \mathbf{t}_0^i \oplus \Delta_i\cdot\mathbf{x}\in\bF_2^{\ell'}~~\text{for}~~i\in[\lambda]$$

  7. Let $\mathbf{q}_j$ be the $j$-th row of the $\ell'\times \lambda$ matrix
     $Q = [\mathbf{q}^1|\mathbf{q}^2|\cdots|\mathbf{q}^\lambda]$, and similarly
     let $\mathbf{t}_j$ be the $j$-th row of
     $T = [\mathbf{t}_0^1|\mathbf{t}_0^2|\cdots|\mathbf{t}_0^\lambda]$. Note
     that
     $$\mathbf{q}_j = \mathbf{t}_j \oplus (\mathbf{x}_j\star\Delta) = \mathbf{t}_j\oplus (\mathbf{x}[j]\cdot \Delta)~~\text{for}~~j\in[\ell']$$

- **Correlation Check**
  1. The sender and receiver run a
     $\pi_{\mathsf{RAND}}(\bF_{2^\lambda}^{\ell'})$ protocol to obtain random
     elements $\chi_1,...,\chi_{\ell'}$.
     $\pi_{\mathsf{RAND}}(\bF_{2^\lambda}^{\ell'})$ will be described later.

  2. The receiver computes
     $$x = \sum_{j = 1}^{\ell'}\mathbf{x}[j]\cdot \chi_j~~\text{and}~~ t = \sum_{j=1}^{\ell'}\mathbf{t}_j\cdot \chi_j $$
     and sends them to the sender.

  3. The sender computes $$q = \sum_{j=1}^{\ell'}\mathbf{q}_j\cdot \chi_j$$ and
     checks $t = q\oplus x\cdot \Delta$. If the check fails, abort.

- **Output**
  1. The sender computes
     $$\mathbf{v}_j = \sH(j,\mathbf{q}_j)\oplus\sH(j,\mathbf{q}_j\oplus\Delta)\oplus\Delta~~\text{for}~~ j\in [\ell]$$
     and sends them to the receiver. $\sH$ is a tweakable hash function as used
     in garbled circuit.

  2. The sender outputs
     $$(\sH(j,\mathbf{q}_j),~\sH(j,\mathbf{q}_j)\oplus \Delta)$$

  3. For $j\in[\ell]$, the receiver outputs the following:
     $$~\text{If}~~x_j = 0,~~\text{outputs}~~ \sH(j,\mathbf{t}_j);~~\text{If}~~x_j = 1,~~\text{outputs}~~\sH(j,\mathbf{t}_j)\oplus \mathbf{v}_j$$

This ends the description of the KOS15 protocol. We note that a very
[recent work](https://eprint.iacr.org/2022/192.pdf) pointed out that there is a
flaw in the security proof of the main lemma of KOS15 and provided a fix, which
is less efficient. They also pointed out that this the original KOS15 protocol
is still secure in practice. Therefore, we choose the original KOS15 protocol in
zkOracles in this version.

We begin to describe the $\pi_{\mathsf{RAND}}(\bF_{2^\lambda}^\ell)$ protocol as
follows.

- The sender and receiver locally choose uniformly $128$-bit random seeds $s_0$
  and $s_1$, respectively.

- The sender and receiver compute commitments of the seeds by choosing $128$-bit
  random strings $r_0,r_1$ and generate $c_0 = \sha(s_0\|r_0)$ and
  $c_1 = \sha(s_1\|r_1)$, respectively.

- The sender sends $c_0$ to the receiver, and the receiver sends $c_1$ to the
  sender.

- On receiving the commitments, the sender and receiver open the commitments by
  sending $(s_0,r_0)$ and $(s_1,r_1)$ to each other, respectively.

- The sender checks $c_1$ by re-computing it with $s_1,r_1$, and the receiver
  checks $c_0$ by re-computing it with $s_0,r_0$. If checks fail, abort.

- The sender and receiver locally compute $s = s_0\oplus s_1$ and generate
  random elements with a $\prg$ as $$\chi_1,...,\chi_\ell\leftarrow \prg(s)$$
