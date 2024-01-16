# Overview of Pickles

Pickles is a recursion layer built on top of Kimchi. The complexity of pickles as a protocol lies in specifying how to verify previous kimchi inside of the current ones. And it gets quite complicated with many concrete details. Working over two curves requires us to have different circuits and a "mirrored" structure, some computations are deferred for efficiency, and one needs to carefully keep track of the accumulators. In this section we provide a general overview of pickles, while next sections in the same chapter dive into the actual implementation details.

Pickles works over Pasta, a cycle of curves consisting of Pallas and Vesta, and thus it defines two generic circuits, one for each curve. Each can be thought of as a parallel instantiation of a kimchi proof systems. These circuits are not symmetric and have somewhat different function:
- **Step circuit**: this is the main circuit that contains application logic. Each step circuit verifies a statement and potentially several (at most 2) other wrap proofs.
- **Wrap circuit**: this circuit merely verifies the step circuit, and does not have its own application logic. The intuition is that every time an application statement is proven it's done in Step, and then the resulting proof is immediately wrapped using Wrap.

Both Step and Wrap circuits additionally do a lot of recursive verification of the previous steps. Without getting too technical, Step (without lost of generality) does the following:
1. Verify the application logic statement
2. Verify that the previous Wrap proof is valid (but perform only main checks that are efficient)
3. Verify that the previous Step proof is valid (perform the secondary checks that were inefficient to perform when the previous Step was Wrapped)
4. Verify that the previous Step correctly aggregated the previous accumulator, that is $\mathsf{acc}_1 = \mathsf{Aggregate}(\mathsf{acc}_0, \pi_{\mathsf{step},1})$.
    - *@volhovm: this is probably simplistic if not incorrect. Improve.*

The diagram roughly illustrates the interplay of the two kimchi instances.

![Overview](./pickles_structure_overview.svg)
