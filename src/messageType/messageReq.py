import sys

sys.path.append('..')
from src.utils import *
from src.const import *
from src.messageType.message import *

# Message requests super
class Message_Request(Message):
    def __init__(self,packetId):
        super().__init__(packetId, 'Request')

    # pack message data
    def pack(self):
        return Message.strToByteArray(self)

# Create auction Request 
class Create_Auction_Request(Message_Request):
    def __init__(self, packetId):
        super().__init__(packetId)
        self.auction_type = None
        self.claim_time = None
        self.time_limit = None
        self.name = None
        self.description = None

    def getAuctionType(self):
        if self.auction_type != None and int(self.auction_type) in auction_type.values():
            return self.auction_type
        else:
            error(EMPTY_STRING,True)
            raise ValueError

    def setAuctionType(self, aucType):
        if auction_type != None and int(aucType) in auction_type.values():
            self.auction_type = aucType
            Message.setData(self, 'auction_type', self.auction_type)
        else :
            error(EMPTY_STRING,True)
            raise ValueError

    def getClaimTime(self):
        if self.claim_time != None:
            return self.claim_time
        else:
            error(EMPTY_STRING,True)
            raise ValueError

    def setClaimTime(self, claim_time):
        if claim_time != None:
            self.claim_time = claim_time
            Message.setData(self, 'claim_time', self.claim_time)
        else :
            error(EMPTY_STRING, True)

    def getTimeLimit(self):
        if self.time_limit != None:
            return self.time_limit
        else:
            error(EMPTY_STRING,True)
            raise ValueError

    def setTimeLimit(self, time_limit):
        if time_limit != None:
            self.time_limit = time_limit
            Message.setData(self,'time_limit', self.time_limit) 
        else :
            error(EMPTY_STRING,True)

    def getName(self):
        if self.name != None:
            return self.name
        else:
            error(EMPTY_STRING,True)
            raise ValueError

    def setName(self, name):
        if name != None:
            self.name = name
            Message.setData(self,'name', self.name) 
        else :
            error(EMPTY_STRING,True)

    def getDescription(self):
        if self.description != None:
            return self.description
        else:
            error(EMPTY_STRING,True)
            raise ValueError

    def setDescription(self, description):
        if description != None:
            self.description = description
            Message.setData(self,'description', self.description) 
        else :
            error(EMPTY_STRING,True)


    # unpack message data
    def unpack(self, message):
        super().unpack(message)
        decoded_msg = byteArrayToStr(message)

        try:
            self.setAuctionType(decoded_msg['data']['auction_type'])
        except:
            error('Auction Type Missing', True)

        try:
            self.setClaimTime(decoded_msg['data']['claim_time'])
        except:
            error('Claim Time Missing', True)
            raise ValueError
        
        try:
            self.setTimeLimit(decoded_msg['data']['time_limit'])
        except:
            error('Time Limit Missing', True)
            raise ValueError

        try:
            self.setName(decoded_msg['data']['name'])
        except:
            error('Name Missing', True)
            raise ValueError

        try:
            self.setDescription(decoded_msg['data']['description'])
        except:
            error('Description Missing', True)
            raise ValueError

# Create auction Request Client -> Manager
class Create_Auction_CM_Request(Create_Auction_Request):
    def __init__(self):
        super().__init__(packetIds['CREATE_AUCTION_CM'])

    def unpack(self, message):
        super().unpack(message)
        decoded_msg = byteArrayToStr(message)

        # Read the values of message and updates packet data
        try:
            self.setCertificate(decoded_msg['certificate'])
        except:
            error('Certificate Missing', True)
            raise ValueError



# Create auction Request Manager -> Repository
class Create_Auction_MR_Request(Create_Auction_Request):
    def __init__(self):
        super().__init__(packetIds['CREATE_AUCTION_MR'])

# Terminate auction Request
class Terminate_Auction_Request(Message_Request):
    def __init__(self, packetId):
        super().__init__(packetId)
        self.auction_id = None

    def getAuctionId(self):
        if self.auction_id != None:
            return self.auction_id
        else:
            error(EMPTY_STRING,True)
            raise ValueError

    def setAuctionId(self,auction_id):
        if auction_id != None:
            self.auction_id = auction_id
            Message.setData(self,'auction_id', self.auction_id) 
        else :
            error(EMPTY_STRING,True)
            raise ValueError

    # unpack message data
    def unpack(self, message):
        super().unpack(message)
        decoded_msg = byteArrayToStr(message)
        
        # Read the values of message and updates packet data
        try:
            self.setAuctionId(decoded_msg['data']['auction_id'])
        except:
            error('Auction Id Missing',True)
            raise ValueError

# Terminate auction Request Client -> Manager
class Terminate_Auction_CM_Request(Terminate_Auction_Request):
    def __init__(self):
        super().__init__(packetIds['TERMINATE_AUCTION_CM'])

    def unpack(self, message):
        super().unpack(message)
        decoded_msg = byteArrayToStr(message)

        # Read the values of message and updates packet data
        try:
            self.setCertificate(decoded_msg['certificate'])
        except:
            error('Certificate Missing', True)
            raise ValueError

# Terminate auction Request Manager -> Repository
class Terminate_Auction_MR_Request(Terminate_Auction_Request):
    def __init__(self):
        super().__init__(packetIds['TERMINATE_AUCTION_MR'])

# List auctions Request
class List_Auctions_CR_Request(Message_Request):
    def __init__(self):
        super().__init__(packetIds['LIST_AUCTIONS_CR'])
        # all, closed, open
        self.auction_type = None

    def getAuctionType(self):
        if self.auction_type != None and int(self.auction_type) in auction_all_states.values():
            return self.auction_type
        else:
            error(EMPTY_STRING,True)
            raise ValueError

    def setAuctionType(self,auction_type):
        if auction_type != None and int(auction_type) in auction_all_states.values():
            self.auction_type = auction_type
            Message.setData(self, 'auction_type', self.auction_type)
        else:
            error(EMPTY_STRING, True)
            raise ValueError

    # unpack message data
    def unpack(self, message):
        super().unpack(message)
        decoded_msg = byteArrayToStr(message)
        
        # Read the values of message and updates packet data
        try:
            self.setAuctionType(decoded_msg['data']['auction_type'])
        except:
            error('Auction Type Missing',True)
            raise ValueError

# List bids of auction Request
class List_Bids_CR_Request(Message_Request):
    def __init__(self):
        super().__init__(packetIds['LIST_BIDS_CR'])
        self.auction_id = None

    def getAuctionId(self):
        if self.auction_id != None:
            return self.auction_id
        else:
            error(EMPTY_STRING,True)
            raise ValueError

    def setAuctionId(self,auction_id):
        if auction_id != None:
            self.auction_id = auction_id
            Message.setData(self, 'auction_id', self.auction_id)
        else :
            error(EMPTY_STRING, True)
            raise ValueError

    # unpack message data
    def unpack(self, message):
        super().unpack(message)
        decoded_msg = byteArrayToStr(message)
        
        # Read the values of message and updates packet data
        try:
            self.setAuctionId(decoded_msg['data']['auction_id'])
        except:
            error('Auction Id Missing',True)
            raise ValueError

# List bids of client Request
class List_Bids_Of_Client_Request(Message_Request):
    def __init__(self, packetId):
        super().__init__(packetId)

    def unpack(self, message):
        super().unpack(message)


# Terminate auction Request Client -> Manager
class List_Bids_Of_Client_CM_Request(List_Bids_Of_Client_Request):
    def __init__(self):
        super().__init__(packetIds['LIST_BIDS_OF_CLIENT_CM'])
        self.symmetric_key = None
        self.algorithm = None
        self.mode = None

    def getSymKey(self):
        if self.symmetric_key != None:
            return self.symmetric_key
        else:
            error(EMPTY_STRING, True)
            raise ValueError

    def setSymKey(self, key):
        if key != None:
            self.symmetric_key = key
            Message.setData(self, 'symmetric_key', self.symmetric_key)
        else:
            error(EMPTY_STRING, True)
            raise ValueError

    def getAlgorithm(self):
        if self.algorithm != None:
            return self.algorithm
        else:
            error(EMPTY_STRING, True)
            raise ValueError

    def setAlgorithm(self, algorithm):
        if algorithm != None:
            self.algorithm = algorithm
            Message.setData(self, 'algorithm', self.algorithm)
        else:
            error(EMPTY_STRING, True)
            raise ValueError

    def getMode(self):
        if self.mode != None:
            return self.mode
        else:
            error(EMPTY_STRING, True)
            raise ValueError

    def setMode(self, mode):
        if mode != None:
            self.mode = mode
            Message.setData(self, 'mode', self.mode)
        else:
            error(EMPTY_STRING, True)
            raise ValueError

    def unpack(self, message):
        super().unpack(message)
        decoded_msg = byteArrayToStr(message)

        # Read the values of message and updates packet data
        try:
            self.setCertificate(decoded_msg['certificate'])
        except:
            error('Certificate Missing', True)
            raise ValueError

        try:
            self.setSymKey(decoded_msg['data']['symmetric_key'])
        except:
            error('Symmetric Key Missing', True)
            raise ValueError
        try:
            self.setAlgorithm(decoded_msg['data']['algorithm'])
        except:
            error('Algorithm Missing', True)
            raise ValueError
        try:
            self.setMode(decoded_msg['data']['mode'])
        except:
            error('Mode Missing', True)
            raise ValueError

# List bids of client Request Manager -> Repository
class List_Bids_Of_Client_MR_Request(List_Bids_Of_Client_Request):
    def __init__(self):
        super().__init__(packetIds['LIST_BIDS_OF_CLIENT_MR'])
        self.packet = None

    def unpack(self, message):
        super().unpack(message)

# Bid on auction beginning Request
class Bid_On_Auction_Crypto_CR_Request(Message_Request):
    def __init__(self):
        super().__init__(packetIds['BID_ON_AUCTION_CRYPTO_CR'])

    # unpack message data
    def unpack(self, message):
        super().unpack(message)
        decoded_msg = byteArrayToStr(message)

        # Read the values of message and updates packet data
        try:
            self.setCertificate(decoded_msg['certificate'])
        except:
            error('Certificate Missing', True)
            raise ValueError

# Bid on auction Request
class Bid_On_Auction_Request(Message_Request):
    def __init__(self, packetId):
        super().__init__(packetId)

    def unpack(self, message, decode=True):
        super().unpack(message, decode)

# Bid on auction bid Request
class Bid_On_Auction_Bid_CR_Request(Bid_On_Auction_Request):
    def __init__(self):
        super().__init__(packetIds['BID_ON_AUCTION_BID_CR'])
        self.symmetric_key = None
        self.auction_id = None
        self.crypto_puzzle_result = None
        self.bid = None

    def getSymKey(self):
        if self.symmetric_key != None:
            return self.symmetric_key
        else:
            error(EMPTY_STRING, True)
            raise ValueError

    def setSymKey(self, key):
        if key != None:
            self.symmetric_key = key
            Message.setData(self, 'symmetric_key', self.symmetric_key)
        else:
            error(EMPTY_STRING, True)
            raise ValueError

    def getAlgorithm(self):
        if self.algorithm != None:
            return self.algorithm
        else:
            error(EMPTY_STRING, True)
            raise ValueError

    def setAlgorithm(self, algorithm):
        if algorithm != None:
            self.algorithm = algorithm
            Message.setData(self, 'algorithm', self.algorithm)
        else:
            error(EMPTY_STRING, True)
            raise ValueError

    def getMode(self):
        if self.mode != None:
            return self.mode
        else:
            error(EMPTY_STRING, True)
            raise ValueError

    def setMode(self, mode):
        if mode != None:
            self.mode = mode
            Message.setData(self, 'mode', self.mode)
        else:
            error(EMPTY_STRING, True)
            raise ValueError

    def getAuctionId(self):
        if self.auction_id != None:
            return self.auction_id
        else:
            error(EMPTY_STRING, True)
            raise ValueError

    def setAuctionId(self, auction_id):
        if auction_id != None:
            self.auction_id = auction_id
            Message.setData(self, 'auction_id', self.auction_id)
        else:
            error(EMPTY_STRING, True)
            raise ValueError

    def getBid(self):
        if self.bid != None:
            return self.bid
        else:
            error(EMPTY_STRING, True)
            raise ValueError

    def setBid(self, bid):
        if bid != None:
            self.bid = bid
            Message.setData(self, 'bid', self.bid)
        else:
            error(EMPTY_STRING, True)
            raise ValueError

    def getCryptoPuzzleResult(self):
        if self.crypto_puzzle_result != None:
            return self.crypto_puzzle_result
        else:
            error(EMPTY_STRING, True)
            raise ValueError

    def setCryptoPuzzleResult(self, crypto_puzzle_result):
        if crypto_puzzle_result != None:
            self.crypto_puzzle_result = crypto_puzzle_result
            Message.setData(self, 'crypto_puzzle_result', self.crypto_puzzle_result)
        else:
            error(EMPTY_STRING, True)
            raise ValueError

    def getHybridKey(self):
        if self.hybrid_key != None:
            return self.hybrid_key
        else:
            error(EMPTY_STRING, True)
            raise ValueError

    def setHybridKey(self, hybrid_key):
        if hybrid_key != None:
            self.hybrid_key = hybrid_key
            Message.setData(self, 'hybrid_key', self.hybrid_key)
        else:
            error(EMPTY_STRING, True)
            raise ValueError

    # unpack message data
    def unpack(self, message, decode=True):
        super().unpack(message, decode)
        if decode:
            decoded_msg = byteArrayToStr(message)
        else:
            decoded_msg = message

        # Read the values of message and updates packet data
        try:
            self.setCertificate(decoded_msg['certificate'])
        except:
            error('Certificate Missing', True)
            raise ValueError

        try:
            self.setSymKey(decoded_msg['data']['symmetric_key'])
        except:
            error('Symmetric Key Missing', True)

        try:
            self.setAuctionId(decoded_msg['data']['auction_id'])
        except:
            error('Auction Id Missing', True)

        try:
            self.setBid(decoded_msg['data']['bid'])
        except:
            error('Bid Missing', True)

        try:
            self.setCryptoPuzzleResult(decoded_msg['data']['crypto_puzzle_result'])
        except:
            error('Crypto puzzle result Missing', True)

        try:
            self.setHybridKey(decoded_msg['data']['hybrid_key'])
        except:
            error('HybridKey Missing', True)

        try:
            self.setAlgorithm(decoded_msg['data']['algorithm'])
        except:
            error('Algorithm Missing', True)
            raise ValueError
        try:
            self.setMode(decoded_msg['data']['mode'])
        except:
            error('Mode Missing', True)
            raise ValueError

# Bid on auction validation Request
class Bid_On_Auction_Validation_MR_Request(Bid_On_Auction_Request):
    def __init__(self):
        super().__init__(packetIds['BID_ON_AUCTION_VALIDATION_MR'])
        self.packet = None

    def getPacket(self):
        if self.packet != None:
            return self.packet
        else:
            error(EMPTY_STRING, True)
            raise ValueError

    def setPacket(self, packet):
        if packet != None:
            self.packet = packet
            Message.setData(self, 'packet', self.packet)
        else:
            error(EMPTY_STRING, True)
            raise ValueError

    def getLastBlock(self):
        if self.last_block != None:
            return self.last_block
        else:
            error(EMPTY_STRING, True)
            raise ValueError

    def setLastBlock(self, last_block):
        if last_block != None:
            self.last_block = last_block
            Message.setData(self, 'last_block', self.last_block)
        else:
            error(EMPTY_STRING, True)
            raise ValueError

    # unpack message data
    def unpack(self, message, decode=True):
        super().unpack(message, decode)
        if decode:
            decoded_msg = byteArrayToStr(message)
        else:
            decoded_msg = message

        # Read the values of message and updates packet data
        try:
            self.setPacket(decoded_msg['data']['packet'])
        except:
            error('Packet Missing', True)
        try:
            self.setLastBlock(decoded_msg['data']['last_block'])
        except:
            error('Packet Missing', True)

# Check english auction outcome Request
class Check_English_Auction_Outcome_CM_Request(Message_Request):
    def __init__(self):
        super().__init__(packetIds['CHECK_ENGLISH_AUCTION_OUTCOME_CM'])
        self.symmetric_key = None
        self.auction_id = None

    def getSymKey(self):
        if self.symmetric_key != None:
            return self.symmetric_key
        else:
            error(EMPTY_STRING,True)
            raise ValueError

    def setSymKey(self,key):
        if key != None:
            self.symmetric_key = key
            Message.setData(self,'symmetric_key', self.symmetric_key) 
        else:
            error(EMPTY_STRING, True)
            raise ValueError

    def getAuctionId(self):
        if self.auction_id != None:
            return self.auction_id
        else:
            error(EMPTY_STRING,True)
            raise ValueError

    def setAuctionId(self,auction_id):
        if auction_id != None:
            self.auction_id = auction_id
            Message.setData(self, 'auction_id', self.auction_id)
        else :
            error(EMPTY_STRING,True)
            raise ValueError

    def getAlgorithm(self):
        if self.algorithm != None:
            return self.algorithm
        else:
            error(EMPTY_STRING, True)
            raise ValueError

    def setAlgorithm(self, algorithm):
        if algorithm != None:
            self.algorithm = algorithm
            Message.setData(self, 'algorithm', self.algorithm)
        else:
            error(EMPTY_STRING, True)
            raise ValueError

    def getMode(self):
        if self.mode != None:
            return self.mode
        else:
            error(EMPTY_STRING, True)
            raise ValueError

    def setMode(self, mode):
        if mode != None:
            self.mode = mode
            Message.setData(self, 'mode', self.mode)
        else:
            error(EMPTY_STRING, True)
            raise ValueError


    def unpack(self, message):
        super().unpack(message)
        decoded_msg = byteArrayToStr(message)

        # Read the values of message and updates packet data
        try:
            self.setSymKey(decoded_msg['data']['symmetric_key'])
        except:
            error('Symmetric Key Missing',True)

        try:
            self.setAuctionId(decoded_msg['data']['auction_id'])
        except:
            error('Auction Id Missing',True)

        try:
            self.setCertificate(decoded_msg['certificate'])
        except:
            error('Certificate Missing', True)
            raise ValueError
        try:
            self.setAlgorithm(decoded_msg['data']['algorithm'])
        except:
            error('Algorithm Missing', True)
            raise ValueError
        try:
            self.setMode(decoded_msg['data']['mode'])
        except:
            error('Mode Missing', True)
            raise ValueError

        
# Check blind auction outcome Request
class Check_Blind_Auction_Outcome_CM_Request(Message_Request):
    def __init__(self):
        super().__init__(packetIds['CHECK_BLIND_AUCTION_OUTCOME_CM'])
        self.symmetric_key = None
        self.auction_id = None
        self.algorithm = None
        self.mode = None

    def getSymKey(self):
        if self.symmetric_key != None:
            return self.symmetric_key
        else:
            error(EMPTY_STRING,True)
            raise ValueError

    def setSymKey(self,key):
        if key != None:
            self.symmetric_key = key
            Message.setData(self, 'symmetric_key', self.symmetric_key)
        else:
            error(EMPTY_STRING, True)
            raise ValueError

    def getAuctionId(self):
        if self.auction_id != None:
            return self.auction_id
        else:
            error(EMPTY_STRING,True)
            raise ValueError

    def setAuctionId(self,auction_id):
        if auction_id != None:
            self.auction_id = auction_id
            Message.setData(self, 'auction_id', self.auction_id)
        else :
            error(EMPTY_STRING, True)
            raise ValueError

    def getAlgorithm(self):
        if self.algorithm != None:
            return self.algorithm
        else:
            error(EMPTY_STRING, True)
            raise ValueError

    def setAlgorithm(self, algorithm):
        if algorithm != None:
            self.algorithm = algorithm
            Message.setData(self, 'algorithm', self.algorithm)
        else:
            error(EMPTY_STRING, True)
            raise ValueError

    def getMode(self):
        if self.mode != None:
            return self.mode
        else:
            error(EMPTY_STRING, True)
            raise ValueError

    def setMode(self, mode):
        if mode != None:
            self.mode = mode
            Message.setData(self, 'mode', self.mode)
        else:
            error(EMPTY_STRING, True)
            raise ValueError


    def unpack(self, message):
        super().unpack(message)
        decoded_msg = byteArrayToStr(message)

        # Read the values of message and updates packet data
        try:
            self.setSymKey(decoded_msg['data']['symmetric_key'])
        except:
            error('Symmetric Key Missing', True)

        try:
            self.setAuctionId(decoded_msg['data']['auction_id'])
        except:
            error('Auction Id Missing', True)

        try:
            self.setCertificate(decoded_msg['certificate'])
        except:
            error('Certificate Missing', True)
            raise ValueError
        try:
            self.setAlgorithm(decoded_msg['data']['algorithm'])
        except:
            error('Algorithm Missing', True)
            raise ValueError
        try:
            self.setMode(decoded_msg['data']['mode'])
        except:
            error('Mode Missing', True)
            raise ValueError

        
# Check blind auction outcome unclaimed Request
class Check_Blind_Auction_Outcome_Unclaimed_CM_Request(Message_Request):
    def __init__(self):
        super().__init__(packetIds['CHECK_BLIND_AUCTION_OUTCOME_UNCLAIMED_CM'])
        self.key_blind_bid = None
        self.auction_id = None

    def getKeyBlindBid(self):
        if self.key_blind_bid != None:
            return self.key_blind_bid
        else:
            error(EMPTY_STRING, True)
            raise ValueError

    def setKeyBlindBid(self,key):
        if key != None:
            self.key_blind_bid = key
            Message.setData(self,'key_blind_bid', self.key_blind_bid) 
        else:
            error(EMPTY_STRING, True)
            raise ValueError

    def getAuctionId(self):
        if self.auction_id != None:
            return self.auction_id
        else:
            error(EMPTY_STRING,True)
            raise ValueError

    def setAuctionId(self,auction_id):
        if auction_id != None:
            self.auction_id = auction_id
            Message.setData(self, 'auction_id', self.auction_id)
        else :
            error(EMPTY_STRING, True)
            raise ValueError


    def unpack(self, message):
        super().unpack(message)
        decoded_msg = byteArrayToStr(message)

        # Read the values of message and updates packet data
        try:
            self.setKeyBlindBid(decoded_msg['data']['key_blind_bid'])
        except:
            error('Blind bid Key Missing', True)

        try:
            self.setAuctionId(decoded_msg['data']['auction_id'])
        except:
            error('Auction Id Missing', True)

        try:
            self.setCertificate(decoded_msg['certificate'])
        except:
            error('Certificate Missing', True)
            raise ValueError
        
# Check blind auction outcome claimed Request
class Check_Blind_Auction_Outcome_Claimed_CM_Request(Message_Request):
    def __init__(self):
        super().__init__(packetIds['CHECK_BLIND_AUCTION_OUTCOME_CLAIMED_CM'])
        self.symmetric_key = None
        self.auction_id = None
        self.algorithm = None
        self.mode = None

    def getSymKey(self):
        if self.symmetric_key != None:
            return self.symmetric_key
        else:
            error(EMPTY_STRING, True)
            raise ValueError

    def setSymKey(self,key):
        if key != None:
            self.symmetric_key = key
            Message.setData(self, 'symmetric_key', self.symmetric_key)
        else:
            error(EMPTY_STRING, True)
            raise ValueError

    def getAuctionId(self):
        if self.auction_id != None:
            return self.auction_id
        else:
            error(EMPTY_STRING, True)
            raise ValueError

    def setAuctionId(self,auction_id):
        if auction_id != None:
            self.auction_id = auction_id
            Message.setData(self, 'auction_id', self.auction_id)
        else :
            error(EMPTY_STRING, True)
            raise ValueError

    def getAlgorithm(self):
        if self.algorithm != None:
            return self.algorithm
        else:
            error(EMPTY_STRING, True)
            raise ValueError

    def setAlgorithm(self, algorithm):
        if algorithm != None:
            self.algorithm = algorithm
            Message.setData(self, 'algorithm', self.algorithm)
        else:
            error(EMPTY_STRING, True)
            raise ValueError

    def getMode(self):
        if self.mode != None:
            return self.mode
        else:
            error(EMPTY_STRING, True)
            raise ValueError

    def setMode(self, mode):
        if mode != None:
            self.mode = mode
            Message.setData(self, 'mode', self.mode)
        else:
            error(EMPTY_STRING, True)
            raise ValueError


    def unpack(self, message):
        super().unpack(message)
        decoded_msg = byteArrayToStr(message)

        # Read the values of message and updates packet data
        try:
            self.setSymKey(decoded_msg['data']['symmetric_key'])
        except:
            error('Symmetric Key Missing', True)

        try:
            self.setAuctionId(decoded_msg['data']['auction_id'])
        except:
            error('Auction Id Missing', True)

        try:
            self.setCertificate(decoded_msg['certificate'])
        except:
            error('Certificate Missing', True)
            raise ValueError
        try:
            self.setAlgorithm(decoded_msg['data']['algorithm'])
        except:
            error('Algorithm Missing', True)
            raise ValueError
        try:
            self.setMode(decoded_msg['data']['mode'])
        except:
            error('Mode Missing', True)
            raise ValueError

class Get_Blockchain_MR_Request(Message_Request):
    def __init__(self):
        super().__init__(packetIds['GET_BLOCKCHAIN_MR'])
        self.auctionID = None

    def getAuctionId(self):
        if self.auction_id != None:
            return self.auction_id
        else:
            error(EMPTY_STRING, True)
            raise ValueError

    def setAuctionId(self,auction_id):
        if auction_id != None:
            self.auction_id = auction_id
            Message.setData(self, 'auction_id', self.auction_id)
        else :
            error(EMPTY_STRING, True)
            raise ValueError

    def unpack(self, message, decode=True):
        super().unpack(message)
        decoded_msg = byteArrayToStr(message)

        try:
            self.setAuctionId(decoded_msg['data']['auction_id'])
        except:
            error('Auction Id Missing', True)

class Get_Blockchain_CR_Request(Message_Request):
    def __init__(self):
        super().__init__(packetIds['GET_BLOCKCHAIN_CR'])
        self.auctionID = None

    def getAuctionId(self):
        if self.auction_id != None:
            return self.auction_id
        else:
            error(EMPTY_STRING, True)
            raise ValueError

    def setAuctionId(self,auction_id):
        if auction_id != None:
            self.auction_id = auction_id
            Message.setData(self, 'auction_id', self.auction_id)
        else :
            error(EMPTY_STRING, True)
            raise ValueError

    def unpack(self, message, decode=True):
        super().unpack(message)
        decoded_msg = byteArrayToStr(message)

        try:
            self.setAuctionId(decoded_msg['data']['auction_id'])
        except:
            error('Auction Id Missing', True)


class Get_Keys_Auction_CM_Request(Message_Request):
    def __init__(self):
        super().__init__(packetIds['GET_KEYS_AUCTION_CM'])
        self.auctionID = None

    def getAuctionId(self):
        if self.auction_id != None:
            return self.auction_id
        else:
            error(EMPTY_STRING, True)
            raise ValueError

    def setAuctionId(self, auction_id):
        if auction_id != None:
            self.auction_id = auction_id
            Message.setData(self, 'auction_id', self.auction_id)
        else:
            error(EMPTY_STRING, True)
            raise ValueError

    def unpack(self, message, decode=True):
        super().unpack(message)
        decoded_msg = byteArrayToStr(message)

        try:
            self.setAuctionId(decoded_msg['data']['auction_id'])
        except:
            error('Auction Id Missing', True)

        try:
            self.setCertificate(decoded_msg['certificate'])
        except:
            error('Certificate Missing', True)
            raise ValueError



