# User Flows

The user will probably want some local CLI in order to formulate requests to the storage provider (SP). This cli will probably write some files to the system that they will need/want later (e.g. commitments, diffs).


In order to recreate the e2e test script, the SP server will need to implement something like the following API.

```rust
type Fp = Vesta::ScalarField
```

### User creates storage blob with SP
The user submits the data along with the commitment to this data. The commitment is used by the server as a "checksum", throwing an error if they do not match.

`POST /blob`
```json
{
  "commitment": PolyComm<Vesta>,
  "data": Vec<u8>,
}
```

Response: 
```json
{}
```

### User posts a diff for data to SP
The user posts a diff in order to update the data, along with the commitment to the data after applying the diff. The server will throw an error if the commitment does not match what they compute.

`POST /blob/<commitment>`
```json
{
    "commitment": PolyComm<Vesta>,
    "diff": {
        "chunks": Vec<Vec<(usize, Fp)>>,
        "new_byte_len": usize
    }
}
```

### User reads contents of a storage blob (Without Proof) from SP
The user can read the data from the server without a `Read Proof`.

`GET /blob/<commitment>`

Response:
```json
{ 
    "data": Vec<u8> 
}
```

### User can request a storage proof for their data
`GET /blob/<commitment>/storage-proof?challenge=<random-field-elem>`
The user can generate a random `Fp` challenge point for evaluation and request a storage proof from the SP.

Response:
```json
{
    "evaluation": Fp,
    "proof": OpeningProof<Vesta>
}
```

