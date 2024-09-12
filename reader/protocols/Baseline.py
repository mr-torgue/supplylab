import secrets
import random
import json
import os
import pickle
import struct

from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Tag import Tag

'''
The baseline uses a simple tag secret based on a shared key.
Every reader appends its ID to the tag secret, leading to Enc(k, r1, ..., rn).
Checking is just decrypting and reading the path. 
'''
class Baseline:


    '''
    Only data that is needed is a shared key k, reader ID, and the reader length in bytes
    '''
    @staticmethod
    def generate_reader_configs(nr_readers: int, valid_paths: list, dir: str):
        # we use four bytes for reader ID's
        reader_ID_size = 4

        # generate and store aes key
        nr_bytes = 32
        aes_key = get_random_bytes(nr_bytes)
        data = {"key": aes_key.hex(), "reader_ID_size": reader_ID_size}
        c_string_shared_key = "uint8_t sharedKey[%d] = {" % (nr_bytes)
        for _byte in aes_key:
            c_string_shared_key += "%d, " % _byte
        # remove last two elements [, ]
        c_string_shared_key = c_string_shared_key[:-2]
        c_string_shared_key += "};\n"

        # write configuration to json file
        with open("%s/keyfile.json" % (dir), "w") as f:
            json.dump(data, f, indent=4)
        
        # create header files for all readers
        for i in range(nr_readers):
            os.mkdir("%s/reader_%d" % (dir, i))
            c_string_data = "uint32_t readerIdSize = %d;\n" % reader_ID_size

            # convert reader ID to bytes
            c_string_data += "uint8_t readerId[%d] = {" % reader_ID_size
            for _byte in i.to_bytes(reader_ID_size, 'big'):
                c_string_data += "%d, " % _byte
            # remove last two elements [, ]
            c_string_data = c_string_data[:-2]
            c_string_data += "};\n"

            # add shared key
            c_string_data += c_string_shared_key
            with open("%s/reader_%d/settings.h" % (dir, i), "w") as f:
                f.write(c_string_data)
        
    '''
    Encrypts the tag identifier with key 
    '''
    @staticmethod
    def generate_tag_secret(tag: int, data: dict):
        message = tag.to_bytes(data["reader_ID_size"], 'big')
        message = struct.pack(">H%ds" % len(message), len(message), message)
        print("Plaintext message: %s" % message.hex())
        cipher = AES.new(bytes.fromhex(data["key"]), AES.MODE_GCM)
        c, ctag = cipher.encrypt_and_digest(message)
        cryptogram = cipher.nonce + ctag + c
        print("ciphertext length: %d (nonce %d, tag %d)\nciphertext: %s" % (len(cryptogram), len(cipher.nonce), len(ctag), cryptogram.hex()))

        # creata tag object
        cryptogram = len(cryptogram).to_bytes(2, 'big') + cryptogram
        tagObj = Tag(tag, cryptogram, "baseline")
        with open("%d.tag" % (tag), "wb") as f:
            pickle.dump(tagObj, f)

    '''
    '''
    @staticmethod
    def decrypt_tag(tag: Tag, path: list):
        None

    '''
    Decrypts message, adds its own identifier and reencrypts
    '''
    @staticmethod
    def update_tag(reader: int, tag: Tag, data: dict):
        None

    '''
    Decrypts message and returns the path that has been followed
    '''
    @staticmethod
    def verify_tag(tag: Tag, data: dict) -> (bool, bytearray):
        # load keys and other data
        k = data["key"]
        reader_ID_size = data["reader_ID_size"]

        # load tag content and decrypt
        nonce = tag.content[2:18]
        ctag = tag.content[18:34]
        ciphertext = tag.content[34:]
        cipher = AES.new(bytes.fromhex(data["key"]), AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt(ciphertext)
        try:
            cipher.verify(ctag)
            print("The message is authentic: %s" % plaintext.hex())
            
            # check if every 4 bytes is a valid reader

        except ValueError:
            print("Key incorrect or message corrupted")
