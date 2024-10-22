import secrets
import json
import struct
import pickle
import os
import mysql.connector

from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
from Crypto.Hash import SHA1
from Crypto.Hash import MD5
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Tag import Tag

'''
Implements all the details for the RF-Chain protocol
RF-Chain has an online and offline secret
'''
class RFChain:

    # mysql settings
    _host="192.168.0.100" #"10.229.105.235"
    _user="user"
    _pass="password"  #"pass"

    '''
    All the readers have a shared key k and a key pair 
    We use the ECDSA signature algorithm with the p256 curve
    k is a 32 byte random key
    Currently, we use SHA1 as a hashing algorithm (considered insecure) because the authors of RF-Chain use this as well
    '''
    @staticmethod
    def generate_reader_configs(nr_readers: int, valid_paths: list, dir: str):
        # generate keys
        key = ECC.generate(curve="p256")
        sk_bytes = key.export_key(format="DER")
        pk_bytes = key.public_key().export_key(format="raw", compress=False)
        k = secrets.token_bytes(32)
        curveSizeBytes = int(key._curve.modulus_bits / 8)
        hashBytes = 32 # change if using another hash function!

        # initialize data for settings file
        data = { 
                "dir": dir,
                "k": k.hex(),
                "curve": key.curve,
                "curvebytes": curveSizeBytes,
                "hashBytes": hashBytes,
                "readers": []
            }

        # generate keys for the readers, make sure to use the same curve
        for i in range(nr_readers):
            # generate key pair
            key = ECC.generate(curve="p256")
            sk_bytes = key.export_key(format="DER")
            pk_bytes = key.public_key().export_key(format="raw", compress=False)
            data["readers"].append({ 
                                    "id": i, 
                                    "public": pk_bytes.hex(), 
                                    "private": key.d.to_bytes(curveSizeBytes, "big").hex(), 
                                    "private-DER": sk_bytes.hex() 
                                })
        # write to json file
        with open("%s/keyfile.json" % (dir), "w") as f:
            json.dump(data, f, indent=4)
        
        # write header files
        for i in range(nr_readers):
            c_string_data = ""
            os.mkdir("%s/reader_%d" % (dir, i))
            # write labels
            c_string_data += "const char *readerLabel = \"RF-Chain\";\n"
            c_string_data += "const char *MQTT_CLIENT_ID = \"RF-Chain RFID READER %d\";\n" % i

            # write reader ID and curve size in bytes
            c_string_data += "const uint16_t curveSizeBytes = %d;\n" % curveSizeBytes
            c_string_data += "const uint16_t hashBytes = %d;\n" % hashBytes
            c_string_data += "const uint32_t readerId = %d;\n" % i
            c_string_data += "const uint16_t nrReaders = %d;\n" % nr_readers
        
            # write k
            c_string_data += "const uint8_t k[%d] = {" % (len(k))
            for _byte in k:
                c_string_data += "%d, " % _byte
            c_string_data = c_string_data[:-2] # remove ", "
            c_string_data += "};\n"

            # write private key
            c_string_data += "const uint8_t privKey[%d] = {" % (curveSizeBytes)
            for _byte in bytes.fromhex(data["readers"][i]["private"]):
                c_string_data += "%d, " % _byte
            c_string_data = c_string_data[:-2] # remove ", "
            c_string_data += "};\n"

            # add all public keys and other settings
            c_string_data += "const uint8_t pubKeys[%d][%d] = {" % (nr_readers, 2 * curveSizeBytes)
            for reader in data["readers"]:
                c_string_data += "{"
                for _byte in bytes.fromhex(reader["public"])[1:]:
                    c_string_data += "%d, " % _byte
                c_string_data = c_string_data[:-2] # remove ", "
                c_string_data += "}, "
            c_string_data = c_string_data[:-2] # remove ", "
            c_string_data += "};\n"

            # write to file
            with open("%s/reader_%d/scheme_settings.h" % (dir, i), "w") as f:
                f.write(c_string_data)

            # create new database
            mydb = mysql.connector.connect(
                host=RFChain._host,
                user=RFChain._user,
                password=RFChain._pass,
            )
            cursor = mydb.cursor()
            create_table = ("CREATE TABLE IF NOT EXISTS RFChain.TagDB ("
                            "`id` int(10) NOT NULL AUTO_INCREMENT,"
                            "`tagID` VARCHAR(64) NOT NULL,"  
                            "`b` VARCHAR(256) NOT NULL,"
                            "`reader` int(10) NOT NULL,"
                            "`timestamp` DATETIME DEFAULT CURRENT_TIMESTAMP,"
                            "CONSTRAINT UC_TagDB UNIQUE (id, tagID)"
                            ")")
            cursor.execute(create_table)
            query = "DELETE FROM RFChain.TagDB"
            cursor.execute(query)
            mydb.commit()
            cursor.close()
            mydb.close()

    '''
    Generates a tag secret
    Format: ID || Enc_k(h_1, m, S) || a_1
    The first part is for the next reader, the second part are the signatures
    '''
    @staticmethod
    def generate_tag_secret(reader: int, tag: int, data: dict):

        # load data
        key = bytes.fromhex(data["k"])
        privkey = ECC.import_key(bytes.fromhex(data["readers"][reader]["private-DER"]))
        signer = DSS.new(privkey, 'fips-186-3')

        # generate random values
        pwd = secrets.token_bytes(8)
        r = secrets.token_bytes(4)
        ID = secrets.token_bytes(4)
        f = secrets.token_bytes(4)
        BLF = secrets.token_bytes(4)
        index = 1
        
        # generate first part of the message (h_1, m, S)
        # h1 = ID(4) || f(4) || pwd(8) || r(4) || index(2)
        h1 = struct.pack(">4s4s8s4s2s", ID, f, pwd, r, index.to_bytes(2, "big"))
        # m = reader(2) || ID(4) || BLF(4)
        m = struct.pack(">h4s4s", reader, ID, BLF)
        hash_m = SHA256.new(m)
        S = signer.sign(hash_m)
        reader_msg = struct.pack(">%ds%ds%ds" % (len(h1), len(m), len(S)), h1, m, S)
        cipher = AES.new(key, AES.MODE_GCM)
        c, ctag = cipher.encrypt_and_digest(reader_msg)
        print("Generating a message for:\nh: %s\nm: %s\n" % (h1.hex(), m.hex()))

        # create offline secret
        # double hash is needed later on
        signer = DSS.new(privkey, 'fips-186-3')
        a0 = SHA256.new(ID + f + pwd + r).digest()
        a1 = signer.sign(SHA256.new(a0))
        k1 = SHA256.new(h1).digest()

        # pack into tag secret
        print("Offline secret:\nID: %s\nNonce:%s\nTag: %s\nShared msg: %s(%d)\na value: %s" % (ID.hex(), cipher.nonce.hex(), ctag.hex(), c.hex(), len(c), a1.hex()))
        offline_tag_secret = struct.pack(">4s%ds%ds%ds%ds" % (len(cipher.nonce), len(ctag), len(c), len(a1)), ID, cipher.nonce, ctag, c, a1)
        print("Complete message(%d): %s\n" % (len(offline_tag_secret), offline_tag_secret.hex()))

        # create online secret
        b1 = hex(int.from_bytes(a0, "big") ^ int.from_bytes(k1, "big"))[2:]
        print("Online secret:\nk: %s\na0: %s" % (hex(int.from_bytes(k1, "big")), int.from_bytes(a0, "big")))
        cipher = AES.new(k1, AES.MODE_ECB)
        ID1 = cipher.encrypt(pad(ID, 16))
        online_tag_secret = {"b": b1}

        # write to the tag
        tagObj = Tag(tag, offline_tag_secret, "rfchain")
        tagObj.updateOnlineStorage(reader, ID1.hex(), online_tag_secret)
        with open("%s/%d.tag" % (data["dir"], tag), "wb") as f:
            pickle.dump(tagObj, f)

        # write to mysql
        mydb = mysql.connector.connect(
            host=RFChain._host,
            user=RFChain._user,
            password=RFChain._pass,
        )
        cursor = mydb.cursor()
        add_online_secret = ("INSERT INTO RFChain.TagDB "
                            "(tagID, b, reader) "
                            "VALUES (%s, %s, %s)")
        data_online_secret = (ID1.hex(), b1, reader)
        cursor.execute(add_online_secret, data_online_secret)
        mydb.commit()
        cursor.close()
        mydb.close()
               


    '''
    updates the tag according to the RF-Chain scheme
    first it verifies the tag
    after that it creates a new signature by signing ai
    it also uploads a new online secret
    input format  : ID || Enc_k(h_i, m, S) || a_i
    output format : ID || Enc_k(h_i+1, m, S) || a_i+1
    '''
    @staticmethod
    def update_tag(reader: int, tag: Tag, data: dict):
        # verify tag and read data
        (success, x) = RFChain.verify_tag(tag, data)
        if success:        
            (ID, hi, m, S, ai) = x
            # load private key and sign new  ai+1
            privkey = ECC.import_key(bytes.fromhex(data["readers"][reader]["private-DER"]))
            signer = DSS.new(privkey, 'fips-186-3')
            ai_1 = signer.sign(SHA256.new(ai))
            print("new ai_1: %s" % (ai_1.hex()))

            # create a new hi with index increased by 1
            index = int.from_bytes(hi[-2:], "big")
            index += 1
            hi_1 = struct.pack(">%ds2s" % (len(hi[:-2])), hi[:-2], index.to_bytes(2, "big"))
            print("hi: %s" % (hi_1.hex()))
            # create a new k and b
            ki_1 = SHA256.new(hi_1).digest() 
            print("new key: %s" % (ki_1.hex()))
            bi_1 = hex(int.from_bytes(ai, "big") ^ int.from_bytes(ki_1, "big"))[2:]
            print("new bi_1: %s" % (bi_1))
            cipher = AES.new(ki_1, AES.MODE_ECB)
            IDi_1 = cipher.encrypt(pad(ID, 16))

            # prepare new secrets
            reader_msg = struct.pack(">%ds%ds%ds" % (len(hi_1), len(m), len(S)), hi_1, m, S)
            key = bytes.fromhex(data["k"])
            cipher = AES.new(key, AES.MODE_GCM)
            c, ctag = cipher.encrypt_and_digest(reader_msg)          
            offline_tag_secret = struct.pack(">4s%ds%ds%ds%ds" % (len(cipher.nonce), len(ctag), len(c), len(ai_1)), ID, cipher.nonce, ctag, c, ai_1)
            online_tag_secret = {"b": bi_1}  

            # write secrets
            tag.updateOnlineStorage(reader, IDi_1.hex(), online_tag_secret)
            tag.updateTagContent(reader, offline_tag_secret)
            with open("%s/%d.tag" % (data["dir"], tag.id), "wb") as f:
                pickle.dump(tag, f)

            # write to mysql
            mydb = mysql.connector.connect(
                host=RFChain._host,
                user=RFChain._user,
                password=RFChain._pass,
            )
            cursor = mydb.cursor()
            add_online_secret = ("INSERT INTO RFChain.TagDB "
                                "(tagID, b, reader) "
                                "VALUES (%s, %s, %s)")
            data_online_secret = (IDi_1.hex(), bi_1, reader)
            cursor.execute(add_online_secret, data_online_secret)
            mydb.commit()
            cursor.close()
            mydb.close()
        else:
            print("Could not verify tag!")


    '''
    verifies the tag by checking the following:
    1. the shared reader message has a valid AES tag (GCM mode)
    2. S is a signature of m
    3. ai+1 is a signature of ai
    4. optionally, check for all values of i
    5. optionally, check if a0 is equal to H(ID, f, pwd, r)
    '''
    @staticmethod
    def verify_tag(tag: Tag, data: dict, depth=0) -> (bool, bytearray):
        # get info from data
        key = bytes.fromhex(data["k"])
        curvesize = data["curvebytes"]

        # load info from tag content
        ID = tag.content[:4]
        nonce = tag.content[4:20]
        ctag = tag.content[20:36]
        ciphertext = tag.content[36:132]
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt(ciphertext)

        # verify if the share message (h, m, S) is authentic
        try:
            print("Verifying ctag: %s" % ctag.hex())
            cipher.verify(ctag)
            # get values from plaintext
            h = plaintext[:22]
            f = plaintext[4:8]
            pwd = plaintext[8:16]
            r = plaintext[16:20]
            m = plaintext[22:32]
            S = plaintext[32:96]
            index = int.from_bytes(h[-2:], "big")

            try:
                # get offline and online secret
                a = tag.content[132:196]
                ai = a
                print("Found tag with the following content:\nindex: %d\nh: %s\nm: %s\nS: %s\na: %s\n" % (index, h.hex(), m.hex(), S.hex(), a.hex()))

                # check how many checks we need to do
                for i in range(1, index + 1)[-depth:][::-1]:
                    # set hi
                    hi = struct.pack(">%ds2s" % (len(h[:-2])), h[:-2], i.to_bytes(2, "big"))

                    # calculate new ki and IDi
                    ki = SHA256.new(hi).digest()
                    cipher = AES.new(ki, AES.MODE_ECB)
                    IDi = cipher.encrypt(pad(ID, 16))
                    IDi = IDi.hex()

                    # get the online secret from tag or DB
                    '''
                    bi_entry = tag.getOnlineStorageMsg(IDi)
                    if bi_entry == None:
                        print("Could not find online secret!")
                        return (False, None)
                    reader = bi_entry["reader"]
                    bi = int(bi_entry["b"], 16)
                    '''
                    # read from mysql
                    mydb = mysql.connector.connect(
                        host=RFChain._host,
                        user=RFChain._user,
                        password=RFChain._pass,
                    )
                    cursor = mydb.cursor(buffered=True)
                    query = ("SELECT reader, b FROM RFChain.TagDB WHERE tagID = %s LIMIT 1")
                    cursor.execute(query, (IDi, ))
                    if cursor.rowcount != 1:
                        print("Could not find online secret!")
                        return (False, None)
                    bi_entry = cursor.fetchone()
                    reader = bi_entry[0]
                    bi = int(bi_entry[1], 16)
                    cursor.close()
                    mydb.close()

                    privkey = ECC.import_key(bytes.fromhex(data["readers"][reader]["private-DER"]))
                    ai_1 = bi ^ int.from_bytes(ki, "big")
                    print("Verifying:\nindex: %d\nh: %s\nk: %s\na: %s\na-1: %s\nb: %s\n" % (i, hi.hex(), ki.hex(), ai.hex(), ai_1.to_bytes(64, "big").hex(), bi_entry))
                    verifier = DSS.new(privkey, "fips-186-3")
                    # if 1, the previous a was a hash (32 bytes)
                    if i == 1:
                        ai_1_bytes = ai_1.to_bytes(32, "big")
                        verifier.verify(SHA256.new(ai_1_bytes), ai)
                        a0 = struct.pack(">4s4s8s4s", ID, f, pwd, r)
                        hash = SHA256.new(a0)
                        if ai_1_bytes.hex() != hash.hexdigest():
                            print("could not verify hash of a0!")
                            return (False, None)
                    # else it was a signature (64 bytes)
                    else:
                        ai_1_bytes = ai_1.to_bytes(64, "big")
                        verifier.verify(SHA256.new(ai_1_bytes), ai)
                        # set ai to the next value
                        ai = ai_1_bytes

                # verify the message
                try:
                    producer = int.from_bytes(m[:2], "big")
                    privkey = ECC.import_key(bytes.fromhex(data["readers"][producer]["private-DER"]))
                    verifier = DSS.new(privkey, "fips-186-3")
                    verifier.verify(SHA256.new(m), S)
                    print("Successful verification!")
                    return (True, (ID, h, m, S, a))
                except ValueError as e:
                    print("S is an invalid signature: %s" % (e))
            except ValueError as e:
                print("Tag content contains invalid signature: %s" % (e))
        except ValueError as e:
            print("The shared message is not authentic! Error: %s" % (e))
        return (False, None)