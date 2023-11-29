To run the demo:
* create an executable file `rpcs.sh` that looks like
  ```bash
  #!/usr/bin/env bash
  export L1RPC=http://xxxxxxxxx
  export L2RPC=http://xxxxxxxxx
  ```
* run the `run-code.sh` script.

This will
* generate the initial state,
* execute the OP program,
* execute the OP program through the cannon MIPS VM,
* execute the OP program through the kimchi MIPS VM prover.

The initial state will be output to a file with format `YYYY-MM-DD-HH-MM-SS-op-program-data-log.sh`.

If you want to re-run against an existing state, pass the environment variable `FILENAME=YYYY-MM-DD-HH-MM-SS-op-program-data-log.sh` to the `run-code.sh` script.
