import pickle
import time

'''
Tag represents a physical RFID tag
'''
class Tag:  
    def __init__(self, id, content: bytearray, mode):  
        if(isinstance(content, (bytes, bytearray))):
            self.id = id 
            self.content = content
            self.history = []
            self.onlineStorage = {"events": [], "storage": {}}
            self.mode = mode
        else:
            print("Content should be a byte array!")

    '''
    updates the tag content
    overwrites current value
    old value is copied to history for debug purposes
    '''
    def updateTagContent(self, reader, content: bytearray):
        if(isinstance(content, (bytes, bytearray))):
            self.onlineStorage["events"].append({"reader": reader, "type": "update", "msg": "reader %d updated tag %d at %f" % (reader, self.id, time.time())})
            self.history.append(self.content)
            self.content = content
        else:
            print("Content should be a byte array!")

    def readTag(self, reader):
        self.onlineStorage["events"].append({"reader": reader, "type": "read", "msg": "reader %d read tag %d at %f" % (reader, self.id, time.time())})

    '''
    adds a new message to the storage
    '''
    def updateOnlineStorage(self, reader, k, v):
        if k not in self.onlineStorage["storage"]:
            self.onlineStorage["storage"][k] = []
        v["timestamp"] = time.time()
        v["reader"] = reader
        self.onlineStorage["storage"][k].append(v)
        self.onlineStorage["events"].append({"reader": reader, "type": "read", "msg": "reader %d updated online storage for tag %d at %f with ID %s" % (reader, self.id, time.time(), k)})

    '''
    read message from storage
    '''
    def getOnlineStorageMsg(self, k, index=0):
        if k not in self.onlineStorage["storage"]:
            print("key %s does not exist!" % k)
        else:
            return self.onlineStorage["storage"][k][0]