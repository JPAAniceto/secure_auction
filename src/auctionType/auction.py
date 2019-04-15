import sys
from datetime import datetime
from datetime import timedelta
from time import mktime

sys.path.append('..')

from src.utils import *
from src.const import *
from src.auctionType.bid import *
from src.modules.blockchain import *

class Auction:
    def __init__(self, auctionId, name, description, timeLimit, claimTime="None", aucType = auction_type['ENGLISH'],
                 blockchain=None, creation_date=None, bids=[], state=auction_state['OPEN']):
        
        if auctionId != None :
            self.__id = auctionId
        else :
            error("Auction id must be non empty str", True)
            raise ValueError
        
        if aucType in auction_type.values():
            self.__type = aucType
        else:
            error("Auction type not supported", True)
            raise ValueError

        if name != None:
            if isinstance(name, str):
                self.__name = name
            else :
                error("<name> must be string", True)
                raise TypeError
        else :
            error("<name> must not be empty", True)
            raise ValueError


        if description != None:
            if isinstance(description, str):
                self.__description = description
            else :
                error("<description> must be string", True)
                raise TypeError
        else :
            error("<description> must not be empty", True)
            raise ValueError
        

       
        if timeLimit != None:
            if isinstance(timeLimit, str):
                self.__time_limit = timeLimit
            else :
                error("<timeLimit> must be str", True)
                raise TypeError
        else :
            error("<timeLimit> must not be empty", True)
            raise ValueError

        if claimTime != None:
            if isinstance(claimTime, str):
                self.__claim_time = claimTime
            else :
                error("<claimTime> must be string", True)
                raise TypeError
        else :
            error("Auction id must be non empty str", True)
            raise ValueError


        if creation_date != None:
           self.__creation_date = datetime.datetime.fromtimestamp(mktime(tuple(creation_date)))
        else :
            self.__creation_date = datetime.datetime.now()

        
        if state in auction_state.values():
                self.__state = state
        else:
            error("Auction state not supported", True)
            raise ValueError
        
        self.__bids = bids

        if blockchain is not None:
            self.__block_chain = blockchain
        else:
            self.__block_chain = Blockchain(json.dumps(self.getAuction(),ensure_ascii=False,sort_keys=True))

    def getBids(self):
        return self.__bids

    def getAuctionId(self):
        if self.__id != None:
            return self.__id
        else :
            error("Auction id not set", True)
            raise ValueError

    def getAuctionType(self):
        if self.__type != None:
            return self.__type
        else :
            error("Auction type not defined", True)
            raise ValueError

    def getName(self):
        if self.__name != None:
            return self.__name
        else:
            error("Auction name not defined", True)
            raise ValueError

    def getDescription(self):
        if self.__description != None:
            return self.__description
        else :
            error("Auction description not defined", True)
            raise ValueError

    def getTimeLimit(self):
        if self.__time_limit != None:
            return self.__time_limit
        else :
            error("Time limit is not defined", True)
            raise ValueError

    def getClaimTime(self):
        if self.__claim_time != None:
            return self.__claim_time
        else :
            error("Claim time is not defined", True)
            raise ValueError

    def getCreationDate(self):
        if self.__creation_date != None:
            return self.__creation_date
        else :
            error("Creation date is not defined", True)
            raise ValueError

    def setState(self, state):
        if self.__state != auction_state['CLOSED']:
            if state in auction_state.values():
                self.__state = state
                if state == auction_state['CLOSED']:
                    self.__block_chain.close_blockchain()
            else:
                error("Auction state not supported", True)
                raise ValueError
        else :
            error("Auction has closed, cant make changes", True)
            raise RuntimeError

    def getState(self):
        if self.__state != None:
            return self.__state
        else :
            error("Auction state not defined", True)
            raise ValueError

    def terminateAuction(self):
        if self.__state == auction_state['CLOSED']:
            return
        if self.__type == auction_type['ENGLISH']:
            self.setState(auction_state['CLOSED'])
            return
        else:
            self.setState(auction_state['CLAIMING'])
            self.__creation_date = datetime.datetime.now()
            self.__time_limit = '0'

    def isClosed(self):

        if self.__type == auction_type['ENGLISH']:
            if self.__state != auction_state['CLOSED']:
                if self.getCreationDate() + timedelta(minutes=int(self.getTimeLimit())) < datetime.datetime.now():
                    self.setState(auction_state['CLOSED'])
                    self.__block_chain.close_blockchain()
                elif self.__block_chain.is_closed():
                    self.setState(auction_state['CLOSED'])
        else:
            if self.__state != auction_state['CLOSED']:
                if self.getCreationDate() + timedelta(minutes=int(self.getClaimTime())) + timedelta(minutes=int(self.getTimeLimit())) < datetime.datetime.now():
                    self.setState(auction_state['CLOSED'])
                elif self.getCreationDate() + timedelta(minutes=int(self.getTimeLimit())) < datetime.datetime.now():
                    self.setState(auction_state['CLAIMING'])
                    self.__block_chain.close_blockchain()
                elif self.__block_chain.is_closed():
                    self.setState(auction_state['CLOSED'])

        return self.__state == auction_state['CLOSED']

    # returns auction info in a dictionary, not included bids and blockchain
    def getAuction(self):
        return {
                'id'            : self.__id,
                'type'          : self.__type,
                'name'          : self.__name,
                'description'   : self.__description,
                'creation_date' : self.__creation_date.timetuple(),
                'time_limit'    : self.__time_limit,
                'claim_time'    : self.__claim_time}

    def getAuctionBlockChain(self):
        return self.__block_chain

    def addBid(self, bid):
        if self.isClosed():
            error("Auction has closed, cant add bids", True)
            return
            # raise RuntimeError

        if not isinstance(bid, type(Bid())):
            error("<bid> is of type {} but must be of type bid".format(type(bid)), True)
            return
            # raise TypeError

        if not bid.isValid():
            error("<bid> is not a valid bid", True)
            return
            # raise ValueError

        # <validate with dynamic code here>

        if bid.getBidType() != self.getAuctionType():
            error("Bid type ({}) is not compatible with auction type ({})".format(bid.getBidType(),self.getAuctionType()), True)
            return
            # raise ValueError

        if self.getAuctionType() == auction_type['ENGLISH']:
            if self.__bids != []:
                if self.__bids[-1].getValue() < bid.getValue():
                    self.__bids.append(bid)
                    self.__block_chain.add_block(json.dumps(bid.wrapBid("key_not_used"),ensure_ascii=False,sort_keys=True))
                else:
                    error("Bid value must be bigger than of the last bid)", True)
                    return
                    # raise ValueError
            else:
                self.__bids.append(bid)
                self.__block_chain.add_block(json.dumps(bid.wrapBid("key_not_used"),ensure_ascii=False,sort_keys=True))

        else:
            self.__bids.append(bid)
            self.__block_chain.add_block(json.dumps(bid.wrapBid("key_not_used"),ensure_ascii=False,sort_keys=True))

    @staticmethod
    def unwrapAuction(blockchain):
        auction_id = None
        auction_type = None
        name = None
        description = None
        creation_date = None
        time_limit = None
        claim_time = None


        data = blockchain.get_blockchain()
        auctionData = json.loads(data[0].__dict__()['data'])

        if auctionData['id'] != None :
            if isinstance(auctionData['id'], str):
                auction_id = auctionData['id']
            else :
                error("<id> must be string", True)
                raise TypeError
        else :
            error("<id> must not be empty", True)
            raise ValueError
        
        if auctionData['type'] != None :
            if isinstance(auctionData['type'], int):
                if auctionData['type'] in auction_state.values():
                    auction_type = auctionData['type']
                else:
                    error("Auction type not supported", True)
                    raise ValueError
            else :
                error("<type> must be integer", True)
                raise TypeError
        else :
            error("<type> must not be empty", True)
            raise ValueError


        if auctionData['name'] != None:
            if isinstance(auctionData['name'], str):
                name = auctionData['name']
            else :
                error("<name> must be string", True)
                raise TypeError
        else :
            error("<name> must not be empty", True)
            raise ValueError

        if auctionData['description'] != None:
            if isinstance(auctionData['description'], str):
                description = auctionData['description']
            else :
                error("<description> must be string", True)
                raise TypeError
        else :
            error("<description> must not be empty", True)
            raise ValueError

       
        if auctionData['time_limit'] != None:
            if isinstance(auctionData['time_limit'], str):
                time_limit = auctionData['time_limit']
            else :
                error("<timeLimit> must be str", True)
                raise TypeError
        else :
            error("<timeLimit> must not be empty", True)
            raise ValueError

        if auctionData['claim_time'] != None:
            if isinstance(auctionData['claim_time'], str):
                claim_time = auctionData['claim_time']
            else :
                error("<claimTime> must be string", True)
                raise TypeError
        else :
            error("<timeLimit> must not be empty", True)
            raise ValueError

        if auctionData['creation_date'] != None:
            creation_date = auctionData['creation_date']
        else :
            error("<creation_date> must not be empty", True)
            raise ValueError

        bids = []

        for block in data[1:]:
            if block.data:
                blockData = json.loads(block.__dict__()['data'])
                bids.append(Bid.unwrapBid(blockData,True))

        auction = Auction( auction_id, name, description, time_limit,
                           claimTime=claim_time, aucType =auction_type, 
                           blockchain=blockchain, creation_date=creation_date, bids = bids, 
                           state = (auction_state['CLOSED'] if blockchain.is_closed() else auction_state['OPEN']) )
        
        return auction

    def __str__(self):
        return  json.dumps(self.getAuction(),ensure_ascii=False,sort_keys=True)