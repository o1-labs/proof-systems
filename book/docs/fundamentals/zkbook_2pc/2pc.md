# Full Protocol

With garbled circuit and oblivious transfer, we are ready to describe the
well-known Yao's method to construct secure two-party computation protocols for
any polynomial-size function.

Given any function $F(x,y)$, where $x$ is the private input of Alice, and $y$ is
the private input of Bob. Let $x = x_1\|x_2\|\cdots\|x_{\ell_1}$ and
$y = y_1\|y_2\|\cdots\|y_{\ell_2}$, where $x_i$ and $y_i$ are bits.

Let Alice be the garbler and Bob be the evaluator, Yao's protocol is described
as follows.

- Alice and Bob run a COT protocol to generate $\ell_2$ OTs, where Alice is the
  sender and Bob is the receiver. Alice obtains
  $(\sY_1,\sY_1\oplus \Delta),...,(\sY_{\ell_2},\sY_{\ell_2}\oplus\Delta)$, and
  Bob obtains
  $(\sY_1\oplus y_1\cdot\Delta,...,\sY_{\ell_2}\oplus y_{\ell_2}\cdot \Delta)$

- Alice chooses uniformly random labels $\sX_1,\sX_2,...,\sX_{\ell_1}$. Alice
  uses $(\sX_1,...,\sX_{\ell_1},\sY_1,...,\sY_{\ell_2})$ and global $\Delta$ to
  generate the garbled circuit of $F$ and sends $\gc(F)$ to Bob. Alice also
  sends the decoding information to Bob.

- Alice encodes her inputs and sends
  $\sX_1\oplus x_1\cdot\Delta,...,\sX_{\ell_1}\oplus x_{\ell_1}\cdot \Delta$ to
  Bob.

- With the encoded $\sX$ labels and $\sY$ labels, Bob evaluates $\gc(F)$ to get
  the output labels, and then decodes these output labels with decoding
  information and gets the output bits.
