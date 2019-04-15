import json
import socket
import sys
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import (padding, rsa, utils)

sys.path.append('..')
from src.utils import *
from src.const import *
# from src.auctionType.bid import *
import src.modules.ccTools as ccTools

class Message:
    def __init__(self,packetId,MsgType,Signature="",Cert=""):
        # see (..).const.packetTypes
        self.id = packetId
        # request or response?
        self.type = MsgType
        
        self.data = {}
        self.signature = Signature
        self.cert = Cert

        self.data["id"] = self.id
        self.data["type"] = self.type

    # encodes the message to base64 encoded data
    def strToByteArray(self):
        # info('DATA SIZE: ' + str(len(self.data)))
        # info('SIG SIZE: ' + str(len(self.signature)))
        # info('CERT SIZE: ' + str(len(self.cert)))
        # info('JSON SIZE: ' + str(len(self.toJson())))
        # info('BYTES JSON SIZE: ' + str(len(bytes(self.toJson(), "utf-8"))))
        # info('B64 JSON SIZE: ' + str(len(base64.b64encode(bytes(self.toJson(), "utf-8")))))
        return bytes(self.toJson(), "utf-8")
    
    # converts msg to json
    def toJson(self):
        return json.dumps({"data": self.data, "signature": self.signature, "certificate": self.cert}, ensure_ascii=False)

    def toDict(self):
        return {"data": self.data, "signature": self.signature, "certificate": self.cert}

    def setData(self, key, value):
        self.data[key] = value

    def getData(self):
        return self.data

    def setSignature(self, signature):
        self.signature = signature

    def getSignature(self):
        return self.signature

    def setCertificate(self, Cert):
        self.cert = Cert

    def getCertificate(self):
        return self.cert

    def getId(self):
        return self.id

    def getType(self):
        return self.type

    def unpack(self, message, decode=True):
        if decode:
            decoded_msg = byteArrayToStr(message)
        else:
            decoded_msg = message

        # Read the values of message and updates packet data
        try:
            self.setSignature(decoded_msg['signature'])
        except:
            error('Signature Missing', True)
            raise ValueError

    def sign_message_CC(self, slot):
        data_ordered = json.dumps(sorted(self.data))
        data_to_sign = data_ordered.encode('utf-8')
        sig, cert = ccTools.sign_data_CC_certificate(slot, data_to_sign)
        self.setSignature(sig.hex())
        self.setCertificate(cert.hex())
        return True

    def sign_message(self, privKey):
        data_ordered = json.dumps(sorted(self.data))
        data_to_sign = data_ordered.encode('utf-8')
        sig = bytes(privKey.sign(data_to_sign, padding.PKCS1v15(), hashes.SHA256()))
        self.setSignature(sig.hex())
        return True

    def verify_signature(self, pubKey):
        try:
            data_ordered = json.dumps(sorted(self.data))
            pubKey.verify(bytes.fromhex(self.getSignature()), data_ordered.encode('utf-8'), padding.PKCS1v15(), hashes.SHA256())
            return True
        except:
            return False


# decodes the base64 encoded data to str
def byteArrayToStr(msg):
    return json.loads(msg.decode('utf-8'))