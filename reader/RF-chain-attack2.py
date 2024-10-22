import pickle
import json
import os
import shutil
import mysql.connector
import traceback

from Tag import Tag
from pprint import pprint
from protocols.RFChain import RFChain
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from ecpy.curves import Curve, Point

'''
Attack 2:
b[i] = a[i-1] xor H(h[i]) is vulnerable because operands are different sizes
a[0] is a hash
a[i], i > 0 is a signature
H(h[i]) is also a hash

Assuming we use SHA256 and ECDSA:
So, b[1] is well defined: both operands have 32 bytes
b[i], i > 1, is not well-defined. One operand is 32 bytes, the other 64
This means that the left 32 bytes of a[i] are readable in plain


'''

# we use the secp256r1 curve
curve = Curve.get_curve('secp256r1')
test = int("594212d5f7632fc217008ac94f365383b1b8bb669d4da3553ba85c659856bad170e8dfa6ae33f2910f7e00d2bdbe50131c0a0fa236a6b543797522e738ef18f8", 16)
test_bytes = test.to_bytes(64, "big")
test_x = test_bytes[:32]
y1 = curve.y_recover(int.from_bytes(test_x))
y2 = curve.y_recover(int.from_bytes(test_x), sign=1)
print("x: %s" % test_x.hex())
print("y1: %s" % hex(y1)[2:])
print("y2: %s" % hex(y2)[2:])
P  = Point(0x594212d5f7632fc217008ac94f365383b1b8bb669d4da3553ba85c659856bad1,
           0x70e8dfa6ae33f2910f7e00d2bdbe50131c0a0fa236a6b543797522e738ef18f8,
           curve)


exit()

# create some tags
dir = "attack2"
if os.path.exists(dir):
    shutil.rmtree(dir)
os.mkdir(dir)
RFChain.generate_reader_configs(10, None, dir)
data = json.load(open("%s/keyfile.json" % (dir)))
RFChain.generate_tag_secret(1, 1, data)
RFChain.generate_tag_secret(1, 2, data)

with open("1.tag", 'rb') as tagfile:    
    with open("2.tag", 'rb') as tagfile2:    
        tag = pickle.load(tagfile)   
        tag2 = pickle.load(tagfile2)

        # do some updates
        RFChain.update_tag(1, tag, data)
        RFChain.update_tag(3, tag, data)
        #RFChain.update_tag(5, tag, data)
        #RFChain.update_tag(7, tag, data)
        #RFChain.update_tag(6, tag2, data)
        #RFChain.update_tag(4, tag2, data)
        #RFChain.update_tag(2, tag2, data)

        # get all data
        mydb = mysql.connector.connect(
            host="10.229.105.235",
            user="user",
            password="pass",
            #auth_plugin="mysql_native_password"
        )
        cursor = mydb.cursor()
        query = ("SELECT * FROM RFChain.TagDB")
        cursor.execute(query)
        B = cursor.fetchall()
        cursor.close()
        mydb.close()


        # get all X and Y variables 
        X = []
        Y = []
        print(len(B))
        for val in B:
            #print(val)
            IDx = val[1]
            bx = int(val[2], 16)
            reader = val[3]
            try:
                bit_length = bx.bit_length()
                if bit_length <= 256:
                    None # what to do?
                else:
                    bx_bytes = bx.to_bytes(64, "big")
                    x = bx_bytes[:32]
                    y1 = curve.y_recover(int.from_bytes(x))
                    y2 = curve.y_recover(int.from_bytes(x), sign=1)
                    print("x: %s" % x.hex())
                    print("y1: %s" % hex(y1)[2:])
                    print("y2: %s" % hex(y2)[2:])
                    X.append(x)
            except Exception as e:
                print(e)
                traceback.print_exc()
