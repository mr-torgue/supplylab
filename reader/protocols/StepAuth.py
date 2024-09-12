import json
import os
import struct
import pickle
import traceback

from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA256, HMAC
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from ecies.utils import generate_key
from ecies import ECIES_CONFIG
from ecies import encrypt, decrypt
from ecies import hex2sk, hex2pk
from Tag import Tag

'''
Implements all logic for the StepAuth protocol.
We use the eciespy library to share a key using ECC.
We use the secp256k1 curve because this is supported by most implementations.
'''
class StepAuth:

    # settings for storing
    ECIES_CONFIG.symmetric_algorithm = "aes-256-ecb"
    ECIES_CONFIG.is_ephemeral_key_compressed = False
    ECIES_CONFIG.is_hkdf_key_compressed = False

    '''
    StepAuth needs to generate:
    1. a key pair for the issuer (this script)
    2. key pairs for all readers
    We use the secp256k1 curve 
    '''
    @staticmethod
    def generate_reader_configs(nr_readers: int, valid_paths: list, dir: str):
        # define tag and reader identifier size in bytes 
        reader_ID_size = 4
        tag_ID_size = 4

         # generate and store master key
        key = ECC.generate(curve="p256")
        sk_bytes = key.export_key(format="DER")
        pk_bytes = key.public_key().export_key(format="raw")
        data = {"master": {
                        "public": pk_bytes.hex(),
                        "private": sk_bytes.hex()
                    }, 
                    "reader_id_size": reader_ID_size,
                    "tag_id_size": tag_ID_size,
                    "readers": []
                }

        # generate keyfile.json
        for i in range(nr_readers):
            # generate private key
            key = generate_key()
            sk_bytes_reader = key.secret
            pk_bytes_reader = key.public_key.format(False)
            # get bytes for both keys and add it to the json object
            data["readers"].append({"id": i,
                                    "public": pk_bytes_reader.hex(), 
                                    "private": sk_bytes_reader.hex()})
        with open("%s/keyfile.json" % dir, "w") as f:
            json.dump(data, f, indent=4)

        # generate reader settings file
        c_string_data = ""
        for i in range(nr_readers):
            os.mkdir("%s/reader_%d" % (dir, i))

            c_string_data = "uint32_t nrReaders = %d;\n" % nr_readers
            c_string_data += "uint32_t readerIdSize = %d;\n" % reader_ID_size
            c_string_data += "uint32_t tagIdSize = %d;\n" % tag_ID_size

            # convert reader ID to  byte array
            c_string_data += "uint8_t readerId[%d] = {" % (reader_ID_size)
            for _byte in i.to_bytes(reader_ID_size, 'big'):
                c_string_data += "%d, " % _byte
            c_string_data = c_string_data[:-2]
            c_string_data += "};\n"

            # convert private key to bytes
            _bytes = bytes.fromhex(data["readers"][i]["private"])
            c_string_data += "uint8_t privKey[%d] = {" % (len(_bytes))
            for _byte in _bytes:
                c_string_data += "%d, " % _byte
            c_string_data = c_string_data[:-2]
            c_string_data += "};\n"

            # store public key of issuer (ignore the 0x4 at the beginning)
            c_string_data += "uint8_t pubKeyIssuer[%d] = {" % (len(pk_bytes[1:]))
            for _byte in pk_bytes[1:]:
                c_string_data += "%d, " % _byte
            c_string_data = c_string_data[:-2]
            c_string_data += "};\n"
            
            with open("%s/reader_%d/settings.h" % (dir, i), "w") as f:
                f.write(c_string_data)
        
    '''
    Tag secrets are generates as M_{R1} || sig_{issuer}(M_{R1}),
        where M = Enc_{R1}(K) || Enc_{K}(R1, R2, M_{R2})
    '''
    @staticmethod
    def generate_tag_secret(tag: int, path: list, data: dict):
        # import key and sizes from settings
        issuer_sk = ECC.import_key(bytes.fromhex(data["master"]["private"]))
        issuer_pk = issuer_sk.public_key()
        reader_ID_size = data["reader_id_size"]
        tag_ID_size = data["tag_id_size"]

        # start with the last element
        for i in range(len(path))[::-1]:
            reader = path[i]
            # check if it is the last reader
            if i == len(path) - 1:
                # 192 bits
                message = pad(struct.pack(">%ds%ds%ds" % (reader_ID_size, reader_ID_size, tag_ID_size), 
                            reader.to_bytes(reader_ID_size, 'big'), reader.to_bytes(reader_ID_size, 'big'), tag.to_bytes(tag_ID_size, 'big')), 16)
            else:
                # 128 + ...
                message = pad(struct.pack(">%ds%ds%ds" % (reader_ID_size, reader_ID_size, len(cryptogram)), 
                            reader.to_bytes(reader_ID_size, 'big'), path[i + 1].to_bytes(reader_ID_size, 'big'), cryptogram), 16)
            
            # obtain keys
            privKey = data["readers"][reader]["private"];
            pubKey = data["readers"][reader]["public"];

            # encrypt, sign, and combine the message (remove trailing 0x4)
            c = encrypt(pubKey, message)[1:]
            h = SHA256.new(c)
            signer = DSS.new(issuer_sk, 'fips-186-3')
            signature = signer.sign(h)
            #print("hash length: %d\nhash: %s" % (len(h.digest()), h.hexdigest()))
            #print("signature length: %d\nsignature: %s" % (len(signature), signature.hex()))
            cryptogram = b"".join([c, signature])
        cryptogram = len(cryptogram).to_bytes(2, 'big') + cryptogram
        print("tag content length: %d\ntag content: %s" % (len(cryptogram), cryptogram.hex()))
        tagObj = Tag(tag, cryptogram, "stepauth")
        with open("%d.tag" % (tag), "wb") as f:
            pickle.dump(tagObj, f)

    '''

    '''
    @staticmethod
    def decrypt_tag(tag: Tag, path: list):
        print("Size of tag secret for path length %d: %d" % (len(path), len(cryptogram)))
        print("DECRYPTING")
        for i in range(len(path)):
            reader = path[i]
            privKey = data["readers"][reader]["private"];
            pubKey = data["readers"][reader]["public"];
            h = SHA256.new(cryptogram[:-64])
            verifier = DSS.new(issuer_pk, "deterministic-rfc6979")
            try:
                verifier.verify(h, cryptogram[-64:])
                print("The message is authentic.")
            except ValueError:
                print("The message is not authentic.")
            m = unpad(decrypt(privKey, cryptogram[64:]), 16)
            cryptogram = m[2:]
            print(m)

    '''
    reader only updates if it is the step in the path
    '''
    @staticmethod
    def update_tag(reader: int, tag: Tag, data: dict):
        reader_ID_size = data["reader_id_size"]
        tag_ID_size = data["tag_id_size"]

        # get message from verify_tag (if successful)
        (success, m) = StepAuth.verify_tag(reader, tag, data)

        # if verify holds, do the update
        if success:
            readerID = m[:reader_ID_size]
            nextReaderID = m[reader_ID_size:2*reader_ID_size]
            # check if it is the last message
            if readerID == nextReaderID:
                print("Tag has finished!")
            cryptogram = m[2*reader_ID_size:]
            cryptogram = len(cryptogram).to_bytes(2, 'big') + cryptogram
            print("tag content length: %d\ntag content: %s" % (len(cryptogram), cryptogram.hex()))
            tag.updateTagContent(reader, cryptogram)
            with open("%d.tag" % (tag.id), "wb") as f:
                pickle.dump(tag, f)
        else:
            print("Verification was not successful!")

    '''
    verifies if reader is the next step in the path by:
    1) checking the signature
    2) checking if reader id matches after decryption
    returs a tuple (bool verified, bytearray result)
    '''
    @staticmethod
    def verify_tag(reader: int, tag: Tag, data: dict) -> (bool, bytearray):
        # load keys and other data
        issuer_sk = ECC.import_key(bytes.fromhex(data["master"]["private"]))
        issuer_pk = issuer_sk.public_key()
        privKey =  data["readers"][reader]["private"]
        pubKey = data["readers"][reader]["public"];
        reader_ID_size = data["reader_id_size"]
        tag_ID_size = data["tag_id_size"]

        # load tag content and hash
        cryptogram = tag.content[2:]
        content = cryptogram[:-64]
        signature = cryptogram[-64:] # last 64 bytes
        h = SHA256.new(content)
        print("Digest: %s\nPublic key: %s\nSignature: %s" % (h.hexdigest(), issuer_pk.export_key(format="raw").hex(), signature.hex()))
        verifier = DSS.new(issuer_pk, 'fips-186-3')
        content = b'\x04' + content # add the 0x04 prefix again
        try:
            verifier.verify(h, signature)
            print("The message is authentic.")
            m = decrypt(privKey, content)
            print(m.hex())
            m = unpad(m, 16)
            print(m.hex())
            readerID = m[:reader_ID_size]
            print(readerID)
            nextReaderID = m[reader_ID_size:2*reader_ID_size]
            if int.from_bytes(readerID, "big") == reader:
                print("Tag %d has been verified by reader %d" % (tag.id, reader))
                return (True, m)
            else:
                print("Could not decrypt message. Make sure you use the right reader!")
        except ValueError as e:
            print("Message is not authentic: %s" % (e))
            traceback.print_exc()
        return (False, None)