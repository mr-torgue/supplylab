'''
python reader_config.py [-n number of readers] [-m mode]
generates n configuration files and headers according to mode m
'''
import argparse
import json
import hashlib, secrets, binascii

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import _serialization
from tinyec import registry

parser = argparse.ArgumentParser(description='Generate keys and header files')
parser.add_argument('-n', dest='nr_readers', type=int, nargs=1,
                    help='Number of readers', required=True)
parser.add_argument('-m', dest='mode', type=int, nargs=1,
                    help='Mode: Bu and Li(1), ...', required=True)

args = parser.parse_args()
nr_readers = args.nr_readers[0]
mode  = args.mode[0]
print("Generating %d secrets in mode %d" % (nr_readers, mode))
# Bu and Li
if mode == 1:
    curve = registry.get_curve('secp256r1')
    # generate and store master key
    private_key = Ed25519PrivateKey.generate()
    data = {"master": {"public": private_key.public_key().public_bytes_raw().hex(), 
                    "private": private_key.private_bytes_raw().hex()}, "readers": []}
    for i in range(nr_readers):
        # generate private key
        private_key = Ed25519PrivateKey.generate()
        privKey = secrets.randbelow(curve.field.n)
        pubKey = privKey * curve.g
        # get bytes for both keys and add it to the json object
        data["readers"].append({"public": private_key.public_key().public_bytes_raw().hex(), 
                                "private": private_key.private_bytes_raw().hex(),
                                "public2": hex(pubKey.x)[2:] + hex(pubKey.y % 2)[2:],
                                "private2": hex(privKey)[2:]})
    with open("keyfile.json", "w") as f:
        json.dump(data, f, indent=4)
else:
    print("Mode not supported!")