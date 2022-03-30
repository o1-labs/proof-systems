# Pasta Curves

The two curves pallas and vesta (pa(llas ve)sta) created by the Zcash team.
Each curve's scalar field is the other curve's base field, which is practical for recursion (see Pickles).

* [supporting evidence](https://github.com/zcash/pasta)
* mina parameters: https://github.com/o1-labs/proof-systems/tree/master/curves/src/pasta
* arkworks [ark-pallas](https://docs.rs/ark-pallas/0.3.0/ark_pallas/), [pallas](https://github.com/arkworks-rs/curves/tree/master/pallas) and [vesta](https://github.com/arkworks-rs/curves/tree/master/vesta)

Note that in general Fq refers to the base field (in which the curve is defined over), while Fr refers to the scalar field (defined by the order of the curve).
But in our code, because of the cycles:

* Fp refers to the base field of Pallas, and the scalar field of Vesta
* Fq refers to the base field of Vesta, and the scalar field of Pallas

TODO: change the naming of Fp and Fq to avoid ambiguity with the conventional Fq and Fr.

## Pallas

* curve equation: $y^2 = x^3 + 5$
* base field: $28948022309329048855892746252171976963363056481941560715954676764349967630337$
* scalar field: $28948022309329048855892746252171976963363056481941647379679742748393362948097$
* mina generator: $(1, 12418654782883325593414442427049395787963493412651469444558597405572177144507)$
* arkworks generator: $(-1, 2)$


## Vesta

* curve equation: $y^2 = x^3 + 5$
* base field: $28948022309329048855892746252171976963363056481941647379679742748393362948097$
* scalar field: $28948022309329048855892746252171976963363056481941560715954676764349967630337$
* mina generator: $(1, 11426906929455361843568202299992114520848200991084027513389447476559454104162)$
* arkworks generator: $(-1, 2)$
