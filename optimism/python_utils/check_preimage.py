import rlp
from eth_utils import keccak
import sys

data = sys.argv[1]
decoded_data = rlp.decode(bytes.fromhex(data))
for i in decoded_data:
    print(i.hex())
