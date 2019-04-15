import os
import sys

sys.path.append('..')

from src.utils import *
from src.const import *
from src.messageType.message import *
from src.messageType.messageReq import *
from src.messageType.messageRsp import *


def test_message_module():
    msg = EC_Request()
    msg.data["hello there"] = "general kenobi"
    info(msg.toJson(), True) 
    info(msg.strToByteArray())
    info(byteArrayToStr(msg.strToByteArray()))
    info('id: ' + str(byteArrayToStr(msg.strToByteArray())['id']))
    info('hello there: ' + str(byteArrayToStr(msg.strToByteArray())['data']['hello there']))
    msg.setSymKey('ola')
    info(msg.toJson()) 
    bytearr = msg.pack()
    info(msg.toJson())
    msg2 = EC_Request()
    msg2.unpack(bytearr)
    info(msg2.toJson()) 

def test_json():
    msg = {}
    msg1 = {}
    msg2 = {}

    msg1['hello_there'] = 'general_kenobi'
    msg2 = json.dumps(msg1, ensure_ascii=False)
    msg3 = json.loads(msg2)

    msg['id'] = 1
    msg['data'] = {'msg1':msg1 ,'msg2': msg2, 'msg3': msg3}

    info(msg)


test_json()