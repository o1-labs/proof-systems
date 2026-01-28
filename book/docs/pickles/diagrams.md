# Pickles Technical Diagrams

This section contains a series of diagrams giving an overview of implementation
of pickles, closely following the structures and abstractions in the code.
However, they are very technical and are primarily intended for developer use.
The primary source of all the images in this section is
[`pickles_structure.drawio`](./pickles_structure.drawio) file, and if one edits
it one must re-generate the `.svg` renders by doing "export -> selection".

The legend of the diagrams is quite straightforward:

- The black boxes are data structures that have names and labels following the
  implementation.
  - `MFNStep`/`MFNWrap` is an abbreviation from `MessagesForNextStep` and
    `MessagesForNextWrap` that is used for brevity. Most other datatypes are
    exactly the same as in the codebase.
- The blue boxes are computations. Sometimes, when the computation is trivial or
  only vaguely indicated, it is denoted as a text sign directly on an arrow.
- Arrows are blue by default and denote moving a piece of data from one place to
  another with no (or very little) change. Light blue arrows are denoting
  witness query that is implemented through the `handler` mechanism. The
  "chicken foot" connector means that this arrow accesses just one field in an
  array: such an arrow could connect e.g. a input field of type `old_a: A` in a
  structure `Vec<(A,B)>` to an output `new_a: A`, which just means that we are
  inside a `for` loop and this computation is done for all the elements in the
  vector/array.
- Colour of the field is sometimes introduced and denotes how many steps ago was
  this piece of data created. The absence of the colour means either that (1)
  the data structure contains different subfields of different origin, or that
  (2) it was not coloured but it could be. The colours are assigned according to
  the following convention:

![](/img/pickles/pickles_structure_legend_1.svg)

### Wrap Computatiton and Deferred Values

The following is the diagram that explains the Wrap computation. The left half
of it corresponds to the `wrap.ml` file and the general logic of proof creation,
while the right part of it is `wrap_main.ml`/`wrap_verifier.ml` and explains
in-circuit computation.

[ ![](/img/pickles/pickles_structure_wrap.svg) ](/img/pickles/pickles_structure_wrap.svg)

This diagram explains the `deferred_values` computation which is in the heart of
`wrap.ml` represented as a blue box in the middle of the left pane of the main
Wrap diagram. Deferred values for Wrap are computed as follows:

[ ![](/img/pickles/pickles_structure_wrap_deferred_values.svg) ](/img/pickles/pickles_structure_wrap_deferred_values.svg)

### Step Computation

The following is the diagram that explains the Step computation, similarly to
Wrap. The left half of it corresponds to the general logic in `step.ml`, and the
right part of it is `step_main.ml` and explains in-circuit computation. We
provide no `deferred_values` computation diagram for Step, but it is very
conceptually similar to the one already presented for Wrap.

[ ![](/img/pickles/pickles_structure_step.svg) ](/img/pickles/pickles_structure_step.svg)
