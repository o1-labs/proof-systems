# ZKDocs
ZKDocs provides comprehensive, detailed, and interactive documentation on zero-knowledge proof systems and related primitives.

At [Trail of Bits](https://www.trailofbits.com/), we audit many implementations of non-standardized cryptographic protocols and often find the same issues. As we discovered more instances of these bugs, we wanted to find a way to prevent them in the future. Unfortunately, for these protocols, the burden is on the developers to figure out all of the low-level implementation details and security pitfalls.

We hope that ZKDocs can fill in this gap and benefit the larger cryptography community.

### Comprehensive
We aim to be both self-contained and comprehensive in the topics related to zero-knowledge proof systems, from descriptions of simple systems like Schnorr’s identification protocol, to complex proof systems like Paillier-Blum modulus. We also cover cryptographic primitives such as: random sampling, Fiat-Shamir transformation, and Shamir's Secret Sharing.


### Detailed
We describe each protocol in great detail, including all necessary setup, sanity-checks, auxiliary algorithms, further references, and potential security pitfalls with their associated severity.


### Interactive

The protocol descriptions are interactive, letting you modify variable names. This allows you to match the variable names in ZKdocs' specification to the variable names in your code, making it easier to find bugs and missing assertions.

![Basic interactivity usage](/static/figs/demo.gif)

Interactivity features:
 - Click on a variable to highlight it across the document.
 - Type or paste with a variable highlighted to edit its name. Press `Enter` or `Escape` to stop editing.
 - Press the `Reset variables names` button to reset the names of all variables on the current page (variable names are independent across different pages)

----

## Roadmap

### Zero-knowledge proof systems
 - [x] Schnorr basic identification protocol
 - [x] Schnorr variants
 - [x] Product of primes
 - [x] Square-free zkp
 - [x] Short proofs for factoring
 - [x] Girault's identification
 - [x] Paillier-Blum Modulus ZK
 - [ ] Discrete log equality
 - [ ] Ring-Pedersen Parameters ZK
 - [ ] STARK
 - [ ] Paillier range proofs
 - [ ] Bulletproofs
 - [ ] Sonic
 - [ ] Plonk

### Primitives
 - [x] Fiat-Shamir transformation
 - [x] Rejection sampling
 - [x] Nothing-up-my-sleeve constructions
 - [x] Shamir secret sharing
 - [x] Feldman's VSS
 - [ ] Fujisaki-Okamoto commitments
 - [ ] Pedersen commitments
 - [ ] HVZK and NIZK

### Common attacks and issues
 - [x] Using HVZKP in the wrong context: two attacks when verifiers are not so honest
 - [ ] Golden-shoe attack
 - [ ] Alpha-rays: attacking others by having short keys
 - [ ] Replay attacks on ZKPs

----


## Dependencies
 - [hugo](https://gohugo.io/documentation/) - install with

    `brew install hugo`

## Running locally
 - `hugo server --minify --theme book`

## How to contribute
 - The file [schnorr.md](content/docs/example/zero-knowledge-protocols/schnorr.md) is an example of a complete protocol.
 - [interactive_variables.js](static/js/interactive_variables.js) has all the variable renaming logic.
 - The Sigma protocols are structured in latex in 3 columns: Alice column, arrow_column, Verifier column. To write the protocols, you can use helpful latex macros:
   - `\work{Work for Alice}{Work for Bob}` - writes work in both Alice's and Bob's column
   - `\alicework{Work for Alice}`, `\bobwork{Work for Bob}` - writes work for either Alice or Bob
   - `\alicebob{Alice work}{message description}{Bob work}`, `\bobalice{Alice work}{message description}{Bob work}` - writes an arrow from alice to bob, or from bob to alice
   - In markdown you would write
```latex
{{< rawhtml >}}
 $$
 \begin{array}{c}
 \work{\varprover}{\varverifier}
 \alicework{\samplezqs{\varr}}
 \alicework{\varu = \varg^\varr}
 \alicebob{}{\varu}{}
 \bobwork{\sample{\varc}}
 \bobalice{}{\varc}{}
 \alicework{\varz = \varr + \varx\cdot \varc}
 \alicebob{}{\varz}{}
 \bobwork{\varg^{\varz} \equalQ \varu \cdot \varh^\varc }
 \end{array}
 $$
{{< /rawhtml >}}
```
 - [header.html](themes/book/layouts/partials/docs/header.html) has all latex macros if more need to be added. In particular it includes all interactive variable macros that the javascript handles afterwards. So, if you write `$\varz$` it will default to a `z` but the user can change its name anywhere on the page.
