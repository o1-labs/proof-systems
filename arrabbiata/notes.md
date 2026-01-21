## Notes to be removed later

We can go around 30 columns if we want stay around 2^13 rows for the IVC.

Currently, with 17 columns, we have to perform 20 + 3 (degree 3 folding) MSM
which cost 256 rows each. Therefore, we need 23 \* 256 rows = ~2^12-~2^13 rows.

It leaves only:

- SRS = 2^16: 2^16 - 2^13 = 57k rows for computations
- SRS = 2^17: 2^17 - 2^13 = 122k rows for computations

Note that we also need lookups. Lookups require, per instance, `m`, `t`,
"accumulator φ" and some lookup partial sums. It must also be folded.

If we use a "horizontal layout" (i.e. IVC next to APP), we could use the spare
rows to build some non-uniform circuits like SuperNova does by selecting an
instruction, and have more than one accumulators.

### Cross terms computation

based on the idea of computing on-the-fly: we might need to keep for each row
the partial evaluations, and define a polynomial in the second homogeneous value
`u''`.

See PDF in drive for the formula, but we can recursively populate a contiguous
array with the individual powers, and keep an index to get the appropriate
power. With this method, we avoid recomputing the powers of a certain value.
Repeated multiplications can also be avoided. The contiguous array is passed as
a parameter on the stack to the function. The CPU cache should be big enough to
handle for low-degree folding schemes (like 5 or 6).

### Next steps

- [x] Method to compute cross-terms (2502)
- [ ] Change EC scalar multiplication to use the permutation argument later. ->
      1 day
- [ ] Permutation argument -> 2-3 days
  - We don't necessarily need it in folding because it is linear.
- [ ] Coining challenges + verification en circuit
- [ ] Compute cross-terms with the existing expressions and commit to it + pass
      as public input
- [ ] Compute challenge r
