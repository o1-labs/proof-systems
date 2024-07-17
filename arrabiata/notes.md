## Notes to be removed later

We can go around 30 columns if we want stay around 2^13 rows for the IVC.

Currently, with 17 columns, we have to perform 20 + 3 (degree 3 folding) MSM which cost 256 rows
each. Therefore, we need 23 * 256 rows = ~2^12-~2^13 rows.

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


