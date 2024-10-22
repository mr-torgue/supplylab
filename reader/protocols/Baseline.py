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
Every reader appends its ID to the tag secret, leading to Enc(k, t, r1, ..., rn).
Checking is just decrypting and reading the path. 
'''
class Baseline:


    '''
    Sets up the baseline scheme by generating a shared key k
    Generates a c header file and a json settings file
    '''
    @staticmethod
    def generate_reader_configs(nr_readers: int, valid_paths: list, dir: str):
        # we use four bytes for reader ID's
        reader_ID_size = 4

        # generate and store aes key
        nr_bytes = 32
        aes_key = get_random_bytes(nr_bytes)
        data = { "dir": dir,
                 "key": aes_key.hex(), 
                 "reader_id_size": reader_ID_size
                }

        # represent the shared key
        c_string_shared_key = "const uint8_t sharedKey[%d] = {" % (nr_bytes)
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
            c_string_data = "const char *readerLabel = \"Baseline\";\n"
            c_string_data += "const char *MQTT_CLIENT_ID = \"Baseline RFID READER %d\";\n" % i
            c_string_data += "const uint32_t readerIdSize = %d;\n" % reader_ID_size

            # convert reader ID to bytes
            c_string_data += "const uint32_t readerId = %d;\n" % i
            c_string_data += "const uint8_t readerIdBytes[%d] = {" % reader_ID_size
            for _byte in i.to_bytes(reader_ID_size, 'big'):
                c_string_data += "%d, " % _byte
            # remove last two elements [, ]
            c_string_data = c_string_data[:-2]
            c_string_data += "};\n"

            # add shared key
            c_string_data += c_string_shared_key
            with open("%s/reader_%d/scheme_settings.h" % (dir, i), "w") as f:
                f.write(c_string_data)
        
    '''
    Encrypts the tag identifier with key 
    '''
    @staticmethod
    def generate_tag_secret(tag: int, data: dict):
        message = tag.to_bytes(data["reader_id_size"], 'big')
        print("Plaintext message: %s" % message.hex())
        cipher = AES.new(bytes.fromhex(data["key"]), AES.MODE_GCM)
        c, ctag = cipher.encrypt_and_digest(message)
        cryptogram = cipher.nonce + ctag + c

        # create tag object
        cryptogram = len(cryptogram).to_bytes(2, 'big') + cryptogram
        print("ciphertext length: %d (nonce %d, tag %d)\nciphertext: %s" % (len(cryptogram), len(cipher.nonce), len(ctag), cryptogram.hex()))
        tagObj = Tag(tag, cryptogram, "baseline")
        with open("%s/%d.tag" % (data["dir"], tag), "wb") as f:
            pickle.dump(tagObj, f)


    '''
    Decrypts message, adds its own identifier and reencrypts
    '''
    @staticmethod
    def update_tag(reader: int, tag: Tag, data: dict):
        # load keys and other data
        k = data["key"]
        reader_ID_size = data["reader_id_size"]
        (success, m) = Baseline.verify_tag(tag, data)
        if success:
            reader_bytes = reader.to_bytes(data["reader_id_size"], "big")
            message = struct.pack(">%ds%ds" % (len(m), data["reader_id_size"]), m, reader_bytes)
            print("New plaintext message: %s" % message.hex())
            cipher = AES.new(bytes.fromhex(data["key"]), AES.MODE_GCM)
            c, ctag = cipher.encrypt_and_digest(message)
            cryptogram = cipher.nonce + ctag + c

            # create tag object
            cryptogram = len(cryptogram).to_bytes(2, 'big') + cryptogram
            print("ciphertext length: %d (nonce %d, tag %d)\nciphertext: %s" % (len(cryptogram), len(cipher.nonce), len(ctag), cryptogram.hex()))
            tag.updateTagContent(reader, cryptogram)
            with open("%s/%d.tag" % (data["dir"], tag.id), "wb") as f:
                pickle.dump(tag, f)

    '''
    Decrypts message and returns the path that has been followed
    '''
    @staticmethod
    def verify_tag(tag: Tag, data: dict) -> (bool, bytearray):
        # load keys and other data
        k = data["key"]
        reader_ID_size = data["reader_id_size"]

        # load tag content and decrypt
        nonce = tag.content[2:18]
        ctag = tag.content[18:34]
        ciphertext = tag.content[34:]
        cipher = AES.new(bytes.fromhex(data["key"]), AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt(ciphertext)
        try:
            cipher.verify(ctag)
            print("nonce: %s\ntag: %s\nc: %s\nkey: %s" % (nonce.hex(), ctag.hex(), ciphertext.hex(), data["key"]))
            print("The message (%s) is authentic: %s" % (tag.content.hex(), plaintext.hex()))
            return (True, plaintext)
            # check if every 4 bytes is a valid reader

        except ValueError as e:
            print("Key incorrect or message corrupted. Error message: %s" % (e))
            return (False, None)