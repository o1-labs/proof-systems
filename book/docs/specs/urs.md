# Universal Reference String (URS)

:::note

Note that the URS is called SRS in our codebase at the moment. SRS is incorrect,
as it is used in the presence of a trusted setup (which kimchi does not have).
This needs to be fixed.

:::

The URS comprises of:

- `Gs`: an arbitrary ordered list of curve points that can be used to commit to
  a polynomial in a non-hiding way.
- `H`: a blinding curve point that can be used to add hiding to a polynomial
  commitment scheme.

The URS is generated deterministically, and thus can be rederived if not stored.

As different circuits of different size do not share the same domain, and the
size of the domain is directly equal to the number of `Gs` curve points we use
to commit to polynomials, we often want to share the same URS of maximum size
across many circuits (constraint systems). Circuit associated with smaller
domains will simply use a truncation of the shared URS.

:::note

A circuit's domain is generated as the first power of 2 that is equal, or
larger, to the number of gates used in the circuit (including zero-knowledge
gates).

:::

## Group map

TODO: specify this part

## Curve points to commit to a polynomial

The following pseudo-code specifies how the `Gs` curve points, as well as the
`H` curve point, are generated.

```python
def create(depth):
    # generators
    Gs = []
    for i in range(0, depth):
        digest = Blake2b512.hash(be_encode(i))
        Gs.push(point_of_random_bytes(digest))

    # blinding point
    digest = (b"srs_misc" || be_encode(0))
    H = point_of_random_bytes(digest)

    #
    return (Gs, H)

def point_of_random_bytes(random_bytes):
    # packing in bit-representation
    const N: usize = 31
    let mut bits = [false; 8 * N]
    for i in range(0, N) {
        for j in range(0, 8) {
            bits[8 * i + j] = (random_bytes[i] >> j) & 1 == 1;
        }
    }

    let n = BigInt::from_bits_be(&bits);
    let t = G::BaseField::from_repr(n)
    return map.to_group(t)
```

TODO: specify `map.to_group` in the previous section.

## URS values in practice

As there is no limit to the number of commitment curve points you can generate,
we only provide the first three ones to serve as test vectors.

TODO: specify the encoding

### Vesta

**`Gs`**.

```
G0 = (x=121C4426885FD5A9701385AAF8D43E52E7660F1FC5AFC5F6468CC55312FC60F8, y=21B439C01247EA3518C5DDEB324E4CB108AF617780DDF766D96D3FD8AB028B70)
G1 = (x=26C9349FF7FB4AB230A6F6AEF045F451FBBE9B37C43C3274E2AA4B82D131FD26, y=1996274D67EC0464C51F79CCFA1F511C2AABB666ABE67733EE8185B71B27A504)
G2 = (x=26985F27306586711466C5B2C28754AA62FE33516D75CEF1F7751F1A169713FD, y=2E8930092FE6A18B331CE0E6E27B413AA18E76394F18A2835DA9FAE10AA3229D)
```

**`H`**:

```
H = (x=092060386301C999AAB4F263757836369CA27975E28BC7A8E5B2CE5B26262201, y=314FC4D83AE66A509F9D41BE6165F2606A209A9B5805EE85CE20249C5EBCBE26)
```

### Pallas

```
G0 = (x363D83141FD1E0540718FADBA7278ABAEEDB46D7A3F050F2CFF1DF4F300C9C30, y=034C68F4079B4F338A19BE2D7BFA44B395C65B9790DD273F361327446C778764)
G1 = (x2CC40B77D87665244AE5EB5304E8744004C80061AD08476A0F0656C13134EA45, y=28146EC860159DB55CB5EA5B14F0AA2F8751DEDFE0DDAFD1C313B15575C4B4AC)
G2 = (x2808BC21BEB90314377BF6130285FABE6CE4B8A4457FB25BC95EBA0083DF27E3, y=1E04E53DD6395FAB8018D7FE98F9C7FAB39C40BFBE48589626A7B8532728B002)
```

**`H`**:

```
H = (x221B959DACD2052AAE26193FCA36B53279866A4FBBAB0D5A2F828B5FD7778201, y=058C8F1105CAE57F4891EADC9B85C8954E5067190E155E61D66855ACE69C16C0)
```
