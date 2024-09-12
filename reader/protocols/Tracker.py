import secrets
import random
import json
import os
import pickle

from Crypto.Hash import SHA256, HMAC
from ecc.curve import Curve25519, ShortWeierstrassCurve, Point
from ecc.key import gen_keypair
from ecc.cipher import ElGamal
from Tag import Tag

'''
implements all logic for the tracker protocol
'''
class Tracker:

    '''
    Tracker generates the following:
      1) the key pair used for elgamal encryption
      2) a shared key used for calculating the hmac
      3) the coeficient a for each reader
      4) valid paths based on provided path file

    Tracker uses the secp160r1 Curve
    each reader receives its coeficient and the point of evaluation x0
    manager receives all coeficients, x0, key k, valid paths, and private key
    '''
    @staticmethod
    def generate_reader_configs(nr_readers: int, valid_paths: list, dir: str):
        # define secp160r1
        secp160r1 = ShortWeierstrassCurve(
            name="secp160r1",
            a=0xffffffffffffffffffffffffffffffff7ffffffc,
            b=0x1c97befc54bd7a8b65acf89f81d4d4adc565fa45,
            p=0xffffffffffffffffffffffffffffffff7fffffff,
            n=0x0100000000000000000001f4c8f927aed3ca752257,
            G_x=0x4a96b5688ef573284664698968c38bb913cbfc82,
            G_y=0x23a628553168947d59dcc912042351377ac5fb32
        )
        # size of the curve (x and y)
        curveSizeBytes = 20
        # size of n (can be different)
        nSize = 21; 
        
        # calculate key pair
        pri_key, pub_key = gen_keypair(secp160r1)
        # Curve uses field Fp for its coordinates
        p = secp160r1.p
        # the order of points
        n = secp160r1.n

        # create shared key between manager and issuer
        k = secrets.token_bytes(curveSizeBytes)

        # any x should be a genator except for 0 and 1
        x0 = 2 + random.randrange(n - 2)
        a0 = random.randrange(n)

        # generate a random point P for the mapping
        P = Point(secp160r1.G_x, secp160r1.G_y, secp160r1) 

        # prepare json data
        data = {"public": {
                    "x": pub_key.x, 
                    "y": pub_key.y
                },
                "private": pri_key,
                "curve": {
                    "name": secp160r1.name,
                    "a": secp160r1.a,
                    "b": secp160r1.b,
                    "p": p,
                    "n": n,
                    "Gx": secp160r1.G_x,
                    "Gy": secp160r1.G_y,
                    "size": curveSizeBytes,
                    "n_size": nSize 
                },
                "k": k.hex(),
                "x0": x0,
                "a0": a0,
                "P": {
                    "x": P.x, 
                    "y": P.y
                }, 
                "readers": [],
                "valid_paths": []}

        # generate values for a
        for i in range(nr_readers):
            data["readers"].append({"id": i, "a": random.randrange(n)})

        # calculate valid paths
        valid_paths_evaluations = []
        print(valid_paths)
        for path in valid_paths:
            path_len = len(path)
            eval = (a0 * x0**path_len) % n
            for i in range(len(path)):
                eval += (data["readers"][path[i]]["a"] * x0**(path_len - 1 - i)) % n
            eval_ec = P * eval
            valid_paths_evaluations.append(eval_ec)
            data["valid_paths"].append({"label": str(path),"x": eval_ec.x, "y": eval_ec.y})
        # write to json file
        with open("%s/keyfile.json" % (dir), "w") as f:
            json.dump(data, f, indent=4)

        # generate reader settings file for readers that need to do the update
        for i in range(nr_readers):
            c_string_data = ""
            os.mkdir("%s/reader_%d" % (dir, i))
            # write reader ID and curve size in bytes
            c_string_data += "uint16_t curveSizeBytes = %d;\n" % curveSizeBytes
            c_string_data += "uint32_t readerId = %d;\n" % i

            # write x0
            c_string_data += "uint8_t x0[%d] = {" % (nSize)
            for _byte in x0.to_bytes(nSize, 'big'):
                c_string_data += "%d, " % _byte
            c_string_data = c_string_data[:-2] # remove ", "
            c_string_data += "};\n"

            # write a
            c_string_data += "uint8_t a[%d] = {" % (nSize)
            for _byte in data["readers"][i]["a"].to_bytes(nSize, 'big'):
                c_string_data += "%d, " % _byte
            c_string_data = c_string_data[:-2] # remove ", "
            c_string_data += "};\n"

            # write public key
            c_string_data += "uint8_t pubKey[%d] = {" % (2 * curveSizeBytes)
            for _byte in data["public"]["x"].to_bytes(curveSizeBytes, 'big'):
                c_string_data += "%d, " % _byte
            for _byte in data["public"]["y"].to_bytes(curveSizeBytes, 'big'):
                c_string_data += "%d, " % _byte
            c_string_data = c_string_data[:-2] # remove ", "
            c_string_data += "};\n"   

            # write P
            c_string_data += "uint8_t P[%d] = {" % (2 * curveSizeBytes)
            for _byte in data["P"]["x"].to_bytes(curveSizeBytes, 'big'):
                c_string_data += "%d, " % _byte
            for _byte in data["P"]["y"].to_bytes(curveSizeBytes, 'big'):
                c_string_data += "%d, " % _byte
            c_string_data = c_string_data[:-2] # remove ", "
            c_string_data += "};\n"   

            with open("%s/reader_%d/settings.h" % (dir, i), "w") as f:
                f.write(c_string_data)

        # generate reader settings file for readers that need to do the verification (manager)
        c_string_data = ""
        os.mkdir("%s/manager_%d" % (dir, nr_readers))
        # write reader ID and curve size in bytes
        c_string_data += "uint16_t curveSizeBytes = %d;\n" % curveSizeBytes 
        c_string_data += "uint16_t nrPointsSizeBytes = %d;\n" % nSize
        c_string_data += "uint16_t nrPaths = %d;\n" % len(data["valid_paths"])
        c_string_data += "uint16_t nrReaders = %d;\n" % nr_readers
        c_string_data += "uint32_t readerId = %d;\n" % nr_readers

        # write x0
        c_string_data += "uint8_t x0[%d] = {" % (nSize)
        for _byte in x0.to_bytes(nSize, 'big'):
            c_string_data += "%d, " % _byte
        c_string_data = c_string_data[:-2] # remove ", "
        c_string_data += "};\n"

        # write all values of a
        c_string_data += "uint8_t a[%d][%d] = {" % (nr_readers, nSize)
        for reader in data["readers"]:
            c_string_data += "{"
            for _byte in reader["a"].to_bytes(nSize, 'big'):
                c_string_data += "%d, " % _byte
            c_string_data = c_string_data[:-2] # remove ", "
            c_string_data += "}, "
        c_string_data = c_string_data[:-2] # remove ", "
        c_string_data += "};\n"

        # write k as a string
        c_string_data += "char *k = \"%s\";\n" % (k.hex())

        # write public key
        c_string_data += "uint8_t pubKey[%d] = {" % (2 * curveSizeBytes)
        for _byte in data["public"]["x"].to_bytes(curveSizeBytes, 'big'):
            c_string_data += "%d, " % _byte
        for _byte in data["public"]["y"].to_bytes(curveSizeBytes, 'big'):
            c_string_data += "%d, " % _byte
        c_string_data = c_string_data[:-2] # remove ", "
        c_string_data += "};\n"   

        # write private key (+1 because taken from n)
        c_string_data += "uint8_t privKey[%d] = {" % (curveSizeBytes + 1)
        for _byte in data["private"].to_bytes(curveSizeBytes + 1, 'big'):
            c_string_data += "%d, " % _byte
        c_string_data = c_string_data[:-2] # remove ", "
        c_string_data += "};\n"   

        # write P
        c_string_data += "uint8_t P[%d] = {" % (2 * curveSizeBytes)
        for _byte in data["P"]["x"].to_bytes(curveSizeBytes, 'big'):
            c_string_data += "%d, " % _byte
        for _byte in data["P"]["y"].to_bytes(curveSizeBytes, 'big'):
            c_string_data += "%d, " % _byte
        c_string_data = c_string_data[:-2] # remove ", "
        c_string_data += "};\n"   

        # write path evaluations, store as a 2D array the point gets encoded as a 2 x curveSizeBytes array (x, y)
        c_string_data += "uint8_t valid_paths[%d][%d] = {" % (len(data["valid_paths"]), 2 * curveSizeBytes)
        for valid_path in data["valid_paths"]:
            c_string_data += "{"
            for _byte in valid_path["x"].to_bytes(curveSizeBytes, 'big'):
                c_string_data += "%d, " % _byte
            for _byte in valid_path["y"].to_bytes(curveSizeBytes, 'big'):
                c_string_data += "%d, " % _byte
            c_string_data = c_string_data[:-2] # remove ", "
            c_string_data += "}, "
        c_string_data = c_string_data[:-2] # remove ", "
        c_string_data += "};\n"

        # add path labels
        c_string_data += "char *valid_path_labels[] = {";
        for valid_path in data["valid_paths"]:
            c_string_data += "\"%s\", " % (valid_path["label"])
        c_string_data = c_string_data[:-2] # remove ", "
        c_string_data += "};\n"


        # add all public keys and other settings
        with open("%s/manager_%d/settings.h" % (dir, nr_readers), "w") as f:
            f.write(c_string_data)


    '''
    helper function that loads the curve from the json file (note: misleading name)
    '''
    @staticmethod
    def load_curve(config):
        # load secp160r1
        secp160r1 = ShortWeierstrassCurve(
            name=config["curve"]["name"],
            a=config["curve"]["a"],
            b=config["curve"]["b"],
            p=config["curve"]["p"],
            n=config["curve"]["n"],
            G_x=config["curve"]["Gx"],
            G_y=config["curve"]["Gy"]
        )
        curveSizeBytes = config["curve"]["size"]
        return (secp160r1, curveSizeBytes)

    '''
    loads all the data from the config file
    '''
    @staticmethod
    def load_config(config):
        # load secp160r1
        (secp160r1, curveSizeBytes) = Tracker.load_curve(config)

        # load config data from json file
        pub_key = Point(config["public"]["x"], config["public"]["y"], secp160r1)
        pri_key = config["private"]
        k = config["k"]
        n = config["curve"]["n"]
        a0 = config["a0"]
        P = Point(config["P"]["x"], config["P"]["y"], secp160r1)
        return (secp160r1, curveSizeBytes, pub_key, pri_key, k, n, a0, P)

    '''
    point compression function, needed if we want so save space
    '''
    @staticmethod
    def compress_point(point: Point, curveSizeBytes: int) -> int:
        _bytes = point.x.to_bytes(curveSizeBytes, 'big')
        if point.y % 2 == 0:
            return b'\x02' + _bytes
        return b'\x03' + _bytes
        
    '''
    Tracker
      Reader to reader communication: no
      Reader to back-end communication: no
      Tag secret: (E(ID), E(HMAC(k, ID)), E(polynomial))
    
    ID is a random point on the secp160r1 curve
    k is the shared key
    polynomial is the current evaluation of the polynomial
    E is a ECC ElGamal encryption using curvey secp160r1
    HMAC is an HMAC algorithm using SHA256 
    '''
    @staticmethod
    def generate_tag_secret(tag: int, data: dict):
        (secp160r1, curveSizeBytes, pub_key, pri_key, k, n, a0, P) = Tracker.load_config(data)

        # generate a random ID (public key is a random point) 
        _, ID = gen_keypair(secp160r1)

        # Generate HMAC(k, ID)
        hash = HMAC.new(str(k).encode(), digestmod=SHA256)
        hash.update(ID.x.to_bytes(curveSizeBytes, 'big'))
        hash.update(ID.y.to_bytes(curveSizeBytes, 'big'))
        digest = int(hash.hexdigest(), 16)
        # values need to be stored as points
        digest_point = digest * P
        polynomial_point = ((digest * a0) % n) * P

        # encryption is done over points because we have a custom mapping
        cipher = ElGamal(secp160r1)
        print("PLAINTEXT:\nID: (%d, %d)\nHMAC(ID): (%d, %d)\nPoynomial: (%d, %d)\n" % (ID.x, ID.y, digest_point.x, digest_point.y, polynomial_point.x, polynomial_point.y))
        C_ID_1, C_ID_2 = cipher.encrypt_point(ID, pub_key, None)
        C_hash_1, C_hash_2 = cipher.encrypt_point(digest_point, pub_key, None)    
        C_polynomial_1, C_polynomial_2 = cipher.encrypt_point(polynomial_point, pub_key, None)


        # write to output to a file
        print("""CIPHERTEXT:
ID: (%d, %d)
ID 2: (%d, %d)
HMAC(ID):(%d, %d)
HMAC(ID) 2:(%d, %d)
Polynomial: (%d, %d)
Polynomial 2: (%d, %d)
""" % (C_ID_1.x, C_ID_1.y, 
        C_ID_2.x, C_ID_2.y,
        C_hash_1.x, C_hash_1.y,
        C_hash_2.x, C_hash_2.y,  
        C_polynomial_1.x, C_polynomial_1.y,
        C_polynomial_2.x, C_polynomial_2.y))

        message = b""
        for point in [C_ID_1, C_ID_2, C_hash_1, C_hash_2, C_polynomial_1, C_polynomial_2]:
            message += point.x.to_bytes(curveSizeBytes, 'big') + point.y.to_bytes(curveSizeBytes, 'big') 
        print("tag content length: %d\ntag content: %s" % (len(message), message.hex()))
        tagObj = Tag(tag, message, "tracker")
        with open("%d.tag" % (tag), "wb") as f:
            pickle.dump(tagObj, f)


        # Decrypt
        P_ID = cipher.decrypt_point(pri_key, C_ID_1, C_ID_2)
        P_hash = cipher.decrypt_point(pri_key, C_hash_1, C_hash_2)
        P_polynomial = cipher.decrypt_point(pri_key, C_polynomial_1, C_polynomial_2)
        print("PLAINTEXT(DEC):\nID: (%d, %d)\nHMAC(ID): (%d, %d)\nPoynomial: (%d, %d)\n" % (P_ID.x, P_ID.y, P_hash.x, P_hash.y, P_polynomial.x, P_polynomial.y))


    @staticmethod
    def decrypt_tag_standard(tag: Tag):
        None

    '''
    converts the tag content into points
    throws an error if the tag content is not 12 * curveSize (in bytes)
    '''
    @staticmethod
    def tag_content_to_points(tag: Tag, secp160r1: ShortWeierstrassCurve, curveSizeBytes: int):
        if len(tag.content) != 12 * curveSizeBytes:
            raise Exception("tag content should be equal to 6 * %d = %d, but it is %d" % (curveSizeBytes, 6 * curveSizeBytes, len(tag.content)))
        points = []
        for i in range(0, 12, 2):
            points.append(Point(int.from_bytes(tag.content[i * curveSizeBytes : (i + 1) * curveSizeBytes], 'big'), 
                                int.from_bytes(tag.content[(i + 1) * curveSizeBytes : (i + 2) * curveSizeBytes], 'big'), secp160r1))
        C_ID_1, C_ID_2 = (points[0], points[1])
        C_hash_1, C_hash_2  = (points[2], points[3])
        C_polynomial_1, C_polynomial_2  = (points[4], points[5])
        return points

    '''
    tag content should be: (C_ID.x, C_ID.y), (C_HMAC.x, C_HMAC.y), (C_poly.x, C_poly.y)
    update function is fr_{i}(x) = x0 * x + HMAC(k, ID) * ai
    technically, all values should be reencrypted as well
    '''
    @staticmethod
    def update_tag(reader: int, tag: Tag, data: dict):
        # load config values
        (secp160r1, curveSizeBytes) = Tracker.load_curve(data)
        x0 = data["x0"]
        ai = data["readers"][reader]["a"]
        pub_key = Point(data["public"]["x"], data["public"]["y"], secp160r1)
        P = Point(data["P"]["x"], data["P"]["y"], secp160r1)

        # get the tag points
        C_ID_1, C_ID_2, C_hash_1, C_hash_2, C_polynomial_1, C_polynomial_2  = Tracker.tag_content_to_points(tag, secp160r1, curveSizeBytes)

        # print the ciphertext for debugging
        print("""CIPHERTEXT:
    ID: (%d, %d)
    ID 2: (%d, %d)
    HMAC(ID):(%d, %d)
    HMAC(ID) 2:(%d, %d)
    Polynomial: (%d, %d)
    Polynomial 2: (%d, %d)
    """ % (C_ID_1.x, C_ID_1.y, 
        C_ID_2.x, C_ID_2.y,
        C_hash_1.x, C_hash_1.y,
        C_hash_2.x, C_hash_2.y,  
        C_polynomial_1.x, C_polynomial_1.y,
        C_polynomial_2.x, C_polynomial_2.y))

        # calculate new ciphertexts
        new_C_poly_1 = x0 * C_polynomial_1 + ai * C_hash_1
        new_C_poly_2 = x0 * C_polynomial_2 + ai * C_hash_2

        # reencrypt to prevent linking attacks
        r_ID = random.randrange(secp160r1.n)
        new_C_ID_1, new_C_ID_2 = (r_ID * P + C_ID_1, r_ID * pub_key + C_ID_2)
        r_hash = random.randrange(secp160r1.n)
        new_C_hash_1, new_C_hash_2 = (r_hash * P + C_hash_1, r_hash * pub_key + C_hash_2)
        r_poly = random.randrange(secp160r1.n)
        new_C_poly_1, new_C_poly_2 = (r_poly * P + new_C_poly_1, r_poly * pub_key + new_C_poly_2)

        # new points array
        new_points = [new_C_ID_1, new_C_ID_2, new_C_hash_1, new_C_hash_2, new_C_poly_1, new_C_poly_2]

        # print new ciphertext
        print("NEW CIPHERTEXT:\nPolynomial: (%d, %d)\nPolynomial 2: (%d, %d)\n" % (new_C_poly_1.x, new_C_poly_1.y, new_C_poly_2.x, new_C_poly_2.y))   
        message = b""
        for new_point in new_points:
            message += new_point.x.to_bytes(curveSizeBytes, 'big') + new_point.y.to_bytes(curveSizeBytes, 'big') 
        tag.updateTagContent(reader, message)
        with open("1.tag", "wb") as f:
            pickle.dump(tag, f)
        print("tag content length: %d\ntag content: %s" % (len(message), message.hex()))

    '''
    tag content should be: (C_ID.x, C_ID.y), (C_HMAC.x, C_HMAC.y), (C_poly.x, C_poly.y)
    verify contains of three steps:
      1) decrypting and checking ID (Not Supported Yet)
      2) decrypting and checking the HMAC
      3) decrypting the polynomial and check with known evaluations
    '''
    @staticmethod
    def verify_tag(tag: Tag, data: dict):
        (secp160r1, curveSizeBytes, pub_key, pri_key, k, q, a0, P) = Tracker.load_config(data)

        # get the tag points
        C_ID_1, C_ID_2, C_hash_1, C_hash_2, C_polynomial_1, C_polynomial_2  = Tracker.tag_content_to_points(tag, secp160r1, curveSizeBytes)

        # decrypt
        cipher = ElGamal(secp160r1)
        P_ID = cipher.decrypt_point(pri_key, C_ID_1, C_ID_2)
        print("P_ID: %s%s" % (P_ID.x.to_bytes(curveSizeBytes, 'big').hex(), P_ID.y.to_bytes(curveSizeBytes, 'big').hex()))
        if True: # placeholder for DB check
            P_hash = cipher.decrypt_point(pri_key, C_hash_1, C_hash_2)
            print("P_hash: %s%s" % (P_hash.x.to_bytes(curveSizeBytes, 'big').hex(), P_hash.y.to_bytes(curveSizeBytes, 'big').hex()))
            # Generate HMAC(k, ID)
            print("k: %s" % (str(k).encode()))
            hash = HMAC.new(str(k).encode(), digestmod=SHA256)
            print("k digest: %s" % (hash.hexdigest()))
            hash.update(P_ID.x.to_bytes(curveSizeBytes, 'big'))
            hash.update(P_ID.y.to_bytes(curveSizeBytes, 'big'))
            digest = int(hash.hexdigest(), 16)
            print("digest: %s" % (hash.hexdigest()))
            # values need to be stored as points
            digest_point = digest * P
            print("digest_point: %s%s" % (digest_point.x.to_bytes(curveSizeBytes, 'big').hex(), digest_point.y.to_bytes(curveSizeBytes, 'big').hex()))
            if P_hash == digest_point:
                P_polynomial = cipher.decrypt_point(pri_key, C_polynomial_1, C_polynomial_2)
                print("P_polynomial: %s%s" % (P_polynomial.x.to_bytes(curveSizeBytes, 'big').hex(), P_polynomial.y.to_bytes(curveSizeBytes, 'big').hex()))
                print("PLAINTEXT: (%d, %d)" % (P_polynomial.x, P_polynomial.y))
                for path in data["valid_paths"]:
                    eval = Point(path["x"], path["y"], secp160r1)
                    tmp = eval * digest
                    print("tmp: %s%s" % (tmp.x.to_bytes(curveSizeBytes, 'big').hex(), tmp.y.to_bytes(curveSizeBytes, 'big').hex()))
                    print("Testing path: (%d, %d)" % (eval.x, eval.y))
                    if eval * digest == P_polynomial:
                        print("Match found: tag followed path %s" % (str(path["label"])))
                        print("PLAINTEXT(DEC):\nID: (%d, %d)\nHMAC(ID): (%d, %d)\nPoynomial: (%d, %d)\n" % (P_ID.x, P_ID.y, P_hash.x, P_hash.y, P_polynomial.x, P_polynomial.y))
                        exit(0)
                print("No match found!")
            else:
                raise(ValueError("HMAC could not be verified!"))
        else:
            raise(ValueError("ID has already been processed!"))