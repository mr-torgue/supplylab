import pickle

class Tag:  
    def __init__(self, id, content: bytearray, mode):  
        if(isinstance(content, (bytes, bytearray))):
            self.id = id 
            self.content = content
            self.history = []
            self.onlineStorage = []
            self.mode = mode
        else:
            print("Content should be a byte array!")

    def updateTagContent(self, reader, content: bytearray):
        if(isinstance(content, (bytes, bytearray))):
            self.onlineStorage.append({"reader": reader, "type": "update", "msg": "reader %d updated tag %d" % (reader, self.id)})
            self.history.append(self.content)
            self.content = content
        else:
            print("Content should be a byte array!")

    def readTag(self, reader):
        self.onlineStorage.append({"reader": reader, "type": "read", "msg": "reader %d read tag %d" % (reader, self.id)})

    def updateOnlineStorage(self, reader, msg):
        self.onlineStorage.append({"reader": reader, "type": "read", "msg": msg})