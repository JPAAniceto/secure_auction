import sys

sys.path.append('..')
from src.utils import *
from src.const import *
from src.messageType.message import *

# Message responses super
class Message_Response(Message):
    def __init__(self,packetId):
        super().__init__(packetId, "Response")
        self.status = None

    def getStatus(self):
        if self.status is not None:
            return self.status
        else:
            error(EMPTY_STRING, True)
            raise ValueError

    def setStatus(self, status):
        if status is not None:
            self.status = status
            Message.setData(self, 'status', self.status)
        else:
            error(EMPTY_STRING, True)

    # pack message data
    def pack(self):
        return Message.strToByteArray(self)

    # unpack message data
    def unpack(self, message, decode=True):
        super().unpack(message, decode)
        if decode:
            decoded_msg = byteArrayToStr(message)
        else:
            decoded_msg = message

        # Read the values of message and updates packet data
        try:
            self.setStatus(decoded_msg['data']['status'])
        except:
            error('Status Missing', True)
            raise ValueError

# Create auction Response
class Create_Auction_Response(Message_Response):
    def __init__(self, packetId):
        super().__init__(packetId)

# Create auction Response Client -> Manager
class Create_Auction_CM_Response(Create_Auction_Response):
    def __init__(self):
        super().__init__(packetIds['CREATE_AUCTION_CM'])
        self.auctionID = None

    def getAuctionID(self):
        if self.auctionID is not None:
            return self.auctionID
        else:
            error(EMPTY_STRING, True)
            raise ValueError

    def setAuctionID(self, auctionID):
        if auctionID is not None:
            self.auctionID = auctionID
            Message.setData(self, 'auctionID', self.auctionID)
        else:
            error(EMPTY_STRING, True)
            raise ValueError

        # unpack message data

    def unpack(self, message):
        super().unpack(message)
        decoded_msg = byteArrayToStr(message)
        if 'success' in self.status:
            # Read the values of message and updates packet data
            try:
                self.setAuctionID(decoded_msg['data']['auctionID'])
            except:
                error('AuctionID Missing', True)
                raise ValueError

# Create auction Response Manager -> Repository
class Create_Auction_MR_Response(Create_Auction_Response):
    def __init__(self):
        super().__init__(packetIds['CREATE_AUCTION_MR'])
        self.auctionID = None

    def getAuctionID(self):
        if self.auctionID is not None:
            return self.auctionID
        else:
            error(EMPTY_STRING, True)
            raise ValueError

    def setAuctionID(self, auctionID):
        if auctionID is not None:
            self.auctionID = auctionID
            Message.setData(self, 'auctionID', self.auctionID)
        else :
            error(EMPTY_STRING, True)
            raise ValueError

        # unpack message data

    def unpack(self, message):
        super().unpack(message)
        decoded_msg = byteArrayToStr(message)
        if 'success' in self.status:
            # Read the values of message and updates packet data
            try:
                self.setAuctionID(decoded_msg['data']['auctionID'])
            except:
                error('AuctionID Missing', True)
                raise ValueError

# Terminate auction Response
class Terminate_Auction_Response(Message_Response):
    def __init__(self, packetId):
        super().__init__(packetId)

# Terminate auction Response Client -> Manager
class Terminate_Auction_CM_Response(Terminate_Auction_Response):
    def __init__(self):
        super().__init__(packetIds['TERMINATE_AUCTION_CM'])

# Terminate auction Response Manager -> Repository
class Terminate_Auction_MR_Response(Terminate_Auction_Response):
    def __init__(self):
        super().__init__(packetIds['TERMINATE_AUCTION_MR'])

# List auctions Response
class List_Auctions_CR_Response(Message_Response):
    def __init__(self):
        super().__init__(packetIds['LIST_AUCTIONS_CR'])
        self.auctions = None

    def getAuctions(self):
        if self.auctions is not None:
            return self.auctions
        else:
            error(EMPTY_STRING, True)
            raise ValueError

    def setAuctions(self, auctions):
        if auctions is not None:
            self.auctions = auctions
            Message.setData(self, 'auctions', self.auctions)
        else :
            error(EMPTY_STRING, True)
            raise ValueError

        # unpack message data

    def unpack(self, message):
        super().unpack(message)
        decoded_msg = byteArrayToStr(message)

        # Read the values of message and updates packet data
        if 'success' in self.status:
            try:
                self.setAuctions(decoded_msg['data']['auctions'])
            except:
                error('Auctions Missing', True)
                raise ValueError

# List bids of auction Response
class List_Bids_CR_Response(Message_Response):
    def __init__(self):
        super().__init__(packetIds['LIST_BIDS_CR'])
        self.bids = None

    def getBids(self):
        if self.bids is not None:
            return self.bids
        else:
            error(EMPTY_STRING, True)
            raise ValueError

    def setBids(self, bids):
        if bids is not None:
            self.bids = bids
            Message.setData(self, 'bids', self.bids)
        else:
            error(EMPTY_STRING, True)
            raise ValueError

    # unpack message data
    def unpack(self, message):
        super().unpack(message)
        decoded_msg = byteArrayToStr(message)

        # Read the values of message and updates packet data
        if 'success' in self.status:
            try:
                self.setBids(decoded_msg['data']['bids'])
            except:
                error('Bids Missing', True)
                raise ValueError

# List bids of client Request
class List_Bids_Of_Client_Response(Message_Response):
    def __init__(self, packetId):
        super().__init__(packetId)

    def unpack(self, message):
        super().unpack(message)

# Terminate auction Response Client -> Manager
class List_Bids_Of_Client_CM_Response(List_Bids_Of_Client_Response):
    def __init__(self):
        super().__init__(packetIds['LIST_BIDS_OF_CLIENT_CM'])
        self.bids = None

    def getBids(self):
        if self.bids is not None:
            return self.bids
        else:
            error(EMPTY_STRING, True)
            raise ValueError

    def setBids(self, bids):
        if bids is not None:
            self.bids = bids
            Message.setData(self, 'bids', self.bids)
        else:
            error(EMPTY_STRING, True)
            raise ValueError

    def unpack(self, message):
        super().unpack(message)
        decoded_msg = byteArrayToStr(message)

        # Read the values of message and updates packet data
        if 'success' in self.status:
            try:
                self.setBids(decoded_msg['data']['bids'])
            except:
                error('Bids Missing', True)
                raise ValueError

# Terminate auction Response Manager -> Repository
class List_Bids_Of_Client_MR_Response(List_Bids_Of_Client_Response):
    def __init__(self):
        super().__init__(packetIds['LIST_BIDS_OF_CLIENT_MR'])
        self.blockchains = None

    def getBlockchains(self):
        if self.blockchains is not None:
            return self.blockchains
        else:
            error(EMPTY_STRING, True)
            raise ValueError

    def setBlockchains(self, blockchains):
        if blockchains is not None:
            self.blockchains = blockchains
            Message.setData(self, 'blockchains', self.blockchains)
        else:
            error(EMPTY_STRING, True)
            raise ValueError

    def unpack(self, message):
        super().unpack(message)
        decoded_msg = byteArrayToStr(message)

        # Read the values of message and updates packet data
        if 'success' in self.status:
            try:
                self.setBlockchains(decoded_msg['data']['blockchains'])
            except:
                error('Blockchains Missing', True)
                raise ValueError


# Bid on auction beginning Response
class Bid_On_Auction_Crypto_CR_Response(Message_Response):
    def __init__(self):
        super().__init__(packetIds['BID_ON_AUCTION_CRYPTO_CR'])
        self.challenge = None

    def getChallenge(self):
        if self.challenge is not None:
            return self.challenge
        else:
            error(EMPTY_STRING, True)
            raise ValueError

    def setChallenge(self, challenge):
        if challenge is not None:
            self.challenge = challenge
            Message.setData(self, 'challenge', self.challenge)
        else:
            error(EMPTY_STRING, True)
            raise ValueError

    # unpack message data
    def unpack(self, message):
        super().unpack(message)
        decoded_msg = byteArrayToStr(message)

        # Read the values of message and updates packet data
        if 'success' in self.status:
            try:
                self.setChallenge(decoded_msg['data']['challenge'])
            except:
                error('Challenge Missing', True)
                raise ValueError

# Bid on auction bid Request
class Bid_On_Auction_Response(Message_Response):
    def __init__(self, packetId):
        super().__init__(packetId)

# Bid on auction bid Response
class Bid_On_Auction_Bid_CR_Response(Bid_On_Auction_Response):
    def __init__(self):
        super().__init__(packetIds['BID_ON_AUCTION_BID_CR'])
        self.receipt = None

    def getReceipt(self):
        if self.receipt is not None:
            return self.receipt
        else:
            error(EMPTY_STRING, True)
            raise ValueError

    def setReceipt(self, receipt):
        if receipt is not None:
            self.receipt = receipt
            Message.setData(self, 'receipt', self.receipt)
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
            self.setReceipt(decoded_msg['data']['receipt'])
        except:
            error('Receipt Missing', True)
            raise ValueError

# Bid on auction validation Response
class Bid_On_Auction_Validation_MR_Response(Bid_On_Auction_Response):
    def __init__(self):
        super().__init__(packetIds['BID_ON_AUCTION_VALIDATION_MR'])
        self.bid = None
        self.packet = None

    def getBid(self):
        if self.bid != None:
            return self.bid
        else:
            error(EMPTY_STRING, True)
            raise ValueError

    def setBid(self,bid):
        if bid != None:
            self.bid = bid
            Message.setData(self,'bid', self.bid)
        else :
            error(EMPTY_STRING, True)
            raise ValueError

    def getPacket(self):
        if self.packet != None:
            return self.packet
        else:
            error(EMPTY_STRING, True)
            raise ValueError

    def setPacket(self,packet):
        if packet != None:
            self.packet = packet
            Message.setData(self,'packet', self.packet)
        else :
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
            self.setBid(decoded_msg['data']['bid'])
        except:
            error('Bid Missing', True)
            raise ValueError
        try:
            self.setPacket(decoded_msg['data']['packet'])
        except:
            error('Packet Missing', True)
            raise ValueError

# Check english auction outcome Response
class Check_English_Auction_Outcome_CM_Response(Message_Response):
    def __init__(self):
        super().__init__(packetIds['CHECK_ENGLISH_AUCTION_OUTCOME_CM'])
        self.winnerID = None
        self.winnerValue = None

    def getWinnerID(self):
        if self.winnerID is not None:
            return self.winnerID
        else:
            error(EMPTY_STRING, True)
            raise ValueError

    def setWinnerID(self,winnerID):
        if winnerID is not None:
            self.winnerID = winnerID
            Message.setData(self, 'winnerID', self.winnerID)
        else :
            error(EMPTY_STRING, True)
            raise ValueError

    def getWinnerValue(self):
        if self.winnerValue is not None:
            return self.winnerValue
        else:
            error(EMPTY_STRING, True)
            raise ValueError

    def setWinnerValue(self, winnerValue):
        if winnerValue is not None:
            self.winnerValue = winnerValue
            Message.setData(self, 'winnerValue', self.winnerValue)
        else :
            error(EMPTY_STRING, True)
            raise ValueError

    # unpack message data
    def unpack(self, message):
        super().unpack(message)
        decoded_msg = byteArrayToStr(message)

        # Read the values of message and updates packet data
        if 'success' in self.status:
            try:
                self.setWinnerID(decoded_msg['data']['winnerID'])
            except:
                error('WinnerID Missing', True)
                raise ValueError

            try:
                self.setWinnerValue(decoded_msg['data']['winnerValue'])
            except:
                error('WinnerValue Missing', True)
                raise ValueError

# Check blind auction outcome Response
class Check_Blind_Auction_Outcome_CM_Response(Message_Response):
    def __init__(self):
        super().__init__(packetIds['CHECK_BLIND_AUCTION_OUTCOME_CM'])
        self.statusAuction = None

    def getStatusAuction(self):
        if self.statusAuction is not None:
            return self.statusAuction
        else:
            error(EMPTY_STRING, True)
            raise ValueError

    def setStatusAuction(self, statusAuction):
        if statusAuction is not None:
            self.statusAuction = statusAuction
            Message.setData(self, 'statusAuction', self.statusAuction)
        else :
            error(EMPTY_STRING, True)
            raise ValueError

    # unpack message data
    def unpack(self, message, decode=True):
        super().unpack(message)
        decoded_msg = byteArrayToStr(message)

        # Read the values of message and updates packet data
        if 'success' in self.status:
            try:
                self.setStatusAuction(decoded_msg['data']['statusAuction'])
            except:
                error('Status of Auction Missing', True)
                raise ValueError

# Check blind auction outcome unclaimed Response
class Check_Blind_Auction_Outcome_Unclaimed_CM_Response(Message_Response):
    def __init__(self):
        super().__init__(packetIds['CHECK_BLIND_AUCTION_OUTCOME_UNCLAIMED_CM'])

# Check blind auction outcome claimed Response
class Check_Blind_Auction_Outcome_Claimed_CM_Response(Message_Response):
    def __init__(self):
        super().__init__(packetIds['CHECK_BLIND_AUCTION_OUTCOME_CLAIMED_CM'])
        self.winnerID = None
        self.winnerValue = None

    def getWinnerID(self):
        if self.winnerID is not None:
            return self.winnerID
        else:
            error(EMPTY_STRING, True)


    def setWinnerID(self, winnerID):
        if winnerID is not None:
            self.winnerID = winnerID
            Message.setData(self, 'winnerID', self.winnerID)
        else:
            error(EMPTY_STRING, True)


    def getWinnerValue(self):
        if self.winnerValue is not None:
            return self.winnerValue
        else:
            error(EMPTY_STRING, True)


    def setWinnerValue(self, winnerValue):
        if winnerValue is not None:
            self.winnerValue = winnerValue
            Message.setData(self, 'winnerValue', self.winnerValue)
        else:
            error(EMPTY_STRING, True)


        # unpack message data

    def unpack(self, message, decode=True):
        super().unpack(message)
        decoded_msg = byteArrayToStr(message)

        # Read the values of message and updates packet data
        if 'success' in self.status:
            try:
                self.setWinnerID(decoded_msg['data']['winnerID'])
            except:
                error('WinnerID Missing', True)


            try:
                self.setWinnerValue(decoded_msg['data']['winnerValue'])
            except:
                error('WinnerValue Missing', True)


class Get_Blockchain_MR_Response(Message_Response):
    def __init__(self):
        super().__init__(packetIds['GET_BLOCKCHAIN_MR'])
        self.blockchain = None

    def getBlockchain(self):
        if self.blockchain is not None:
            return self.blockchain
        else:
            error(EMPTY_STRING, True)
            raise ValueError

    def setBlockchain(self, blockchain):
        if blockchain is not None:
            self.blockchain = blockchain
            Message.setData(self, 'blockchain', self.blockchain)
        else:
            error(EMPTY_STRING, True)
            raise ValueError

        # unpack message data

    def unpack(self, message, decode=True):
        super().unpack(message)
        decoded_msg = byteArrayToStr(message)

        # Read the values of message and updates packet data
        if 'success' in self.status:
            try:
                self.setBlockchain(decoded_msg['data']['blockchain'])
            except:
                error('Blockchain Missing', True)
                raise ValueError

class Get_Blockchain_CR_Response(Message_Response):
    def __init__(self):
        super().__init__(packetIds['GET_BLOCKCHAIN_CR'])
        self.blockchain = None

    def getBlockchain(self):
        if self.blockchain is not None:
            return self.blockchain
        else:
            error(EMPTY_STRING, True)
            raise ValueError

    def setBlockchain(self, blockchain):
        if blockchain is not None:
            self.blockchain = blockchain
            Message.setData(self, 'blockchain', self.blockchain)
        else:
            error(EMPTY_STRING, True)
            raise ValueError

        # unpack message data

    def unpack(self, message, decode=True):
        super().unpack(message)
        decoded_msg = byteArrayToStr(message)

        # Read the values of message and updates packet data
        if 'success' in self.status:
            try:
                self.setBlockchain(decoded_msg['data']['blockchain'])
            except:
                error('Blockchain Missing', True)
                raise ValueError

class Get_Keys_Auction_CM_Response(Message_Response):
    def __init__(self):
        super().__init__(packetIds['GET_KEYS_AUCTION_CM'])
        self.identity_keys = None
        self.blind_keys = None

    def getIdentityKeys(self):
        if self.identity_keys is not None:
            return self.identity_keys
        else:
            error(EMPTY_STRING, True)
            raise ValueError

    def setIdentityKeys(self, identity_keys):
        if identity_keys is not None:
            self.identity_keys = identity_keys
            Message.setData(self, 'identity_keys', self.identity_keys)
        else:
            error(EMPTY_STRING, True)
            raise ValueError

    def getBlindKeys(self):
        if self.blind_keys is not None:
            return self.blind_keys
        else:
            error(EMPTY_STRING, True)
            raise ValueError

    def setBlindKeys(self, blind_keys):
        if blind_keys is not None:
            self.blind_keys = blind_keys
            Message.setData(self, 'blind_keys', self.blind_keys)
        else:
            error(EMPTY_STRING, True)
            raise ValueError

        # unpack message data

    def unpack(self, message, decode=True):
        super().unpack(message)
        decoded_msg = byteArrayToStr(message)

        # Read the values of message and updates packet data
        if 'success' in self.status:
            try:
                self.setIdentityKeys(decoded_msg['data']['identity_keys'])
            except:
                error('Identity Keys Missing', True)
                raise ValueError

            try:
                self.setBlindKeys(decoded_msg['data']['blind_keys'])
            except:
                error('Blind Keys Missing', True)
                raise ValueError








