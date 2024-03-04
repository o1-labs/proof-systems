## Kimchi Foreign Field gate serialization subcircuit

The 15/16 bulletproof challenges will be given as 88 limbs, the encoding used by Kimchi.
A circuit would be required to convert into 15 bits limbs that will be used for the MSM algorithm.
We will use one row = one decomposition.

We have the following circuit shape:

| $b_{0}$ | $b_{1}$ | $b_{2}$ | $c_{0}$ | $c_{1}$ | ... | $c_{16}$ | $b_{2, 0}$ | $b_{2, 1}$ | ... | $b_{2, 19}$ |
| ------- | ------- | ------- | ------- | ------- | --- | -------- | ---------  | ---------  | --- | ----------- |
| ...     | ...     | ...     | ...     | ...     | ... | ...      | ...        |  ...       | ... | ...         |
| ...     | ...     | ...     | ...     | ...     | ... | ...      | ...        |  ...       | ... | ...         |

We can suppose that $b_{2}$ is only on 80 bits as the input is maximum
$BN254(\mathbb{F}_{scalar})$, which is 254 bits long.
We will decompose $b_{2}$ in chunks of 4 bits:

$$b_{2} = \sum_{i = 0}^{19} b_{2, i} 2^{4 i}$$

And we will add the following constraint:

1. For the first 180 bits:

$$b_{0} + b_{1} 2^88 + b_{2, 0} * 2^{88 * 2} - \sum_{j = 0}^{11} c_{j} 2^{15 j} = 0$$

2. For the remaining 75 bits:

$$c_{12} + c_{13} * 2^{15} + c_{14} 2^{15 * 2} + c_{15} 2^{15 * 3} + c_{16} 2^{15 * 4} = \sum_{j = 1}^{19} b_{2, j} * 2^{4 (j - 1)}$$

with additional lookups.

$b_{0}$, $b_{1}$ and $b_{2}$ are the decomposition on 88 bits given by the
foreign field gate in Kimchi. The values $c_{0}$, $\cdots$, $c_{16}$ are the limbs
required for the MSM circuit. Each limbs $c_{i}$ will be on 15 bits.
