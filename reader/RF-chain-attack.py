import pickle
import json

from Tag import Tag
from pprint import pprint
from protocols.RFChain import RFChain
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

'''
Shows that the attack can work
'''

# read the tag
tagID = int(input("Specify tag ID: "))
with open("%d.tag" % tagID, 'rb') as tagfile:    
    tag = pickle.load(tagfile)
    
    # attacker needs to know two things, an ID, and the content of the blockchain
    # ID can be found on the tag
    # content of blockchain is public
    ID = tag.content[:4]
    a = tag.content[130:194]

    # now the attacker has to wait for an update since this a value is new
    data = json.load(open("out/keyfile.json"))
    RFChain.update_tag(1, tag, data)
    

    B = tag.onlineStorage["storage"]
    print("Found identifier: %s" % ID.hex())

    path = []

    # check values
    for IDx, val in B.items():
        try:
            hx = int.from_bytes(a, "big") ^ val[0]["b"]
            hx = hx.to_bytes(64, "big")
            hx = hx[32:]
            print(hx.hex())
            #kx = SHA256.new(hx).digest() 
            cipher = AES.new(hx, AES.MODE_ECB)
            IDx2 = cipher.encrypt(pad(ID, 16))
            if IDx == IDx2.hex():
                print("Found match for ID: %s with b value: %d" % (IDx2.hex(), val[0]["b"]))
                path.append(IDx2.hex())
                a = val[0]["b"]
                break
        except:
            None
