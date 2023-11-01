import rlp
from eth_utils import keccak
import sys
import fire


class Utils:
    def decode_block(self, hex_data):
        decoded_data = rlp.decode(bytes.fromhex(hex_data))
        for i in decoded_data:
            print(i.hex())

    def check_hash(self, hex_data):
        b = bytes.fromhex(hex_data)
        print(keccak(b).hex())


if __name__ == "__main__":
    fire.Fire(Utils)
