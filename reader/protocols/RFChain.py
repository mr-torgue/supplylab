

from Tag import Tag

'''
'''
class RFChain:


    '''
    '''
    @staticmethod
    def generate_reader_configs(nr_readers: int, valid_paths: list, dir: str):
        data = { "readers": [] }
        # generate keys
        for i in range(nr_readers):
            mykey = RSA.generate(4096)
            mykeydata = mykey.export_key(format='DER').hex()
            data["readers"].append({ "id": i, "key": mykeydata })
        
    '''
    '''
    @staticmethod
    def generate_tag_secret(tag: int, path: list, data: dict):
        pwd = secrets.randbits(64)
        r = secrets.randbits(32)
        index = 1
        ID = input("Give tag identifier: ")
        f = input("Give tag EPC: ")
        a0 = SHA256.new(ID + f + pwd + r)
        key = ECC.import_key(open('privkey.der').read())
        signer = DSS.new(key, 'fips-186-3')
        a1 = signer.sign(a0)
        h1 = ID + f + pwd + r + index
        b1 = a0 ^ SHA256.new(h1)

    '''
    '''
    @staticmethod
    def decrypt_tag(tag: Tag, path: list):
        None

    '''
    '''
    @staticmethod
    def update_tag(reader: int, tag: Tag, data: dict):
        None

    '''
    '''
    @staticmethod
    def verify_tag(reader: int, tag: Tag, data: dict) -> (bool, bytearray):
        None