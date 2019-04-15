import socket
import sys
import _thread

sys.path.append('..')
from src.utils import *
from src.const import *
from src.messageType.messageReq import *
from src.messageType.messageRsp import *
from src.modules.cyphers import *
import src.modules.cryptoPuzzle as cryptoPuzzle
from src.auctionType.auction import *

class Repository:
    def __init__(self):
        self.auctions = []
        with open(os.path.join('serverSide', 'privRepository.key'), "rb") as key_file:
            self.private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )
            self.auctions = []
            self.cryptoPuzzleDifficulty = 10
            self.cryptoPuzzleChallenges = []

        # for filename in os.listdir('auctions'):
        #     f = open(filename, 'r')
        #     b = Blockchain.load_blockchain(f)
        #     if b:
        #         self.auctions.append(Auction.unwrapAuction(b))
        #     f.close()

    def openConnection(self, socketPort):
        # Create a TCP/IP socket
        recvSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        # Bind the socket to the port
        address = ('localhost', socketPort)
        # print('starting up on %s port %s' % server_address)
        recvSocket.bind(address)
        return recvSocket

    def closeSocket(self, sock):
        info('closing recv socket')
        sock.close()

    def receiveMessage(self, socket):
        while True:
            info('\nwaiting to receive message')
            data, address = socket.recvfrom(PACKET_SIZE)

            info('received %s bytes from %s' % (len(data), address))

            dataToSend = self.runStuff(data)
            info('Status: ' + str(dataToSend.getStatus()))
            dataToSend.sign_message(self.private_key)

            info('sending response to ' + str(address))
            socket.sendto(dataToSend.strToByteArray(), address)

        socket.close()

    def runStuff(self, data):
        # Decode message
        try:
            decoded_data = byteArrayToStr(data)
            id_message = decoded_data['data']['id']
        except:
            info('Invalid packet ID: DISCARDING')
            return Message(0, 'Response')

        # Run accordingly to ID
        if id_message == packetIds['CREATE_AUCTION_MR']:
            info('Packet with ID: CREATE_AUCTION_MR')
            return self.createAuction(data)
        elif id_message == packetIds['TERMINATE_AUCTION_MR']:
            info('Packet with ID: TERMINATE_AUCTION_MR')
            return self.terminateAuction(data)
        elif id_message == packetIds['LIST_AUCTIONS_CR']:
            info('Packet with ID: LIST_AUCTIONS_CR')
            return self.listAuctions(data)
        elif id_message == packetIds['LIST_BIDS_CR']:
            info('Packet with ID: LIST_BIDS_CR')
            return self.listBids(data)
        elif id_message == packetIds['LIST_BIDS_OF_CLIENT_MR']:
            info('Packet with ID: LIST_BIDS_OF_CLIENT_MR')
            return self.listBidsOfClient(data)
        elif id_message == packetIds['BID_ON_AUCTION_CRYPTO_CR']:
            info('Packet with ID: BID_ON_AUCTION_CRYPTO_CR')
            return self.cryptoPuzzle(data)
        elif id_message == packetIds['BID_ON_AUCTION_BID_CR']:
            info('Packet with ID: BID_ON_AUCTION_BID_CR')
            return self.bidOnAuction(data)
        elif id_message == packetIds['GET_BLOCKCHAIN_MR']:
            info('Packet with ID: GET_BLOCKCHAIN_MR')
            return self.getBlockchain(data)
        elif id_message == packetIds['GET_BLOCKCHAIN_CR']:
            info('Packet with ID: GET_BLOCKCHAIN_CR')
            return self.getBlockchainClient(data)
        else:
            info('Invalid packet ID: DISCARDING')
            return Message(0, 'Response')

    def createAuction(self, data):
        messageToSend = Create_Auction_MR_Response()

        message = Create_Auction_MR_Request()

        # Check message formatting
        try:
            message.unpack(data)
        except:
            messageToSend.setStatus({'error': 'Message badly formatted'})
            return messageToSend

        # Check Signature
        if not message.verify_signature(MANAGER_PUBLIC_KEY):
            messageToSend.setStatus({'error': 'Invalid signature'})
            return messageToSend

        # Do internal Stuff
        # ....
        auction = Auction(str(len(self.auctions)+1), message.getName(), message.getDescription(), message.getTimeLimit(),
                          message.getClaimTime(), int(message.getAuctionType()))
        self.auctions.append(auction)
        id = auction.getAuctionId()
        f = open(os.path.join('auctions', id+'.bc'), 'w+')
        auction.getAuctionBlockChain().to_file(f)

        # Return Message
        messageToSend.setAuctionID(id)
        messageToSend.setStatus({'success': 'OK'})

        return messageToSend

    def terminateAuction(self, data):
        messageToSend = Terminate_Auction_MR_Response()

        message = Terminate_Auction_MR_Request()

        # Check message formatting
        try:
            message.unpack(data)
        except:
            messageToSend.setStatus({'error': 'Message badly formatted'})
            return messageToSend

        # Check Signature
        if not message.verify_signature(MANAGER_PUBLIC_KEY):
            messageToSend.setStatus({'error': 'Invalid signature'})
            return messageToSend

        # Do internal Stuff
        # ....
        info('Terminate auction with id: ' + message.getAuctionId())
        for auc in self.auctions:
            if auc.getAuctionId() == message.getAuctionId():
                auc.terminateAuction()
                messageToSend.setStatus({'success': 'OK'})
                return messageToSend

        messageToSend.setStatus({'error': 'No auction by that id'})

        return messageToSend

    def listAuctions(self, data):
        messageToSend = List_Auctions_CR_Response()

        message = List_Auctions_CR_Request()

        # Check message formatting
        try:
            message.unpack(data)
        except:
            messageToSend.setStatus({'error': 'Message badly formatted'})
            return messageToSend

        # Do internal Stuff
        # ....
        info('List auctions of type ' + message.getAuctionType())
        list = []
        if message.getAuctionType() == '0':
            # Open
            for auc in self.auctions:
                auc.isClosed()
                if auc.getState() == 0:
                    list.append(auc.getAuction())
        elif message.getAuctionType() == '1':
            # Closed
            for auc in self.auctions:
                auc.isClosed()
                if auc.getState() == 1:
                    list.append(auc.getAuction())
        elif message.getAuctionType() == '2':
            # All
            for auc in self.auctions:
                auc.isClosed()
                list.append(auc.getAuction())
        # Return Message
        messageToSend.setAuctions(list)
        messageToSend.setStatus({'success': 'OK'})

        return messageToSend

    def listBids(self, data):
        messageToSend = List_Bids_CR_Response()

        message = List_Bids_CR_Request()

        # Check message formatting
        try:
            message.unpack(data)
        except:
            messageToSend.setStatus({'error': 'Message badly formatted'})
            return messageToSend

        # Do internal Stuff
        # ....
        info('List bids of auction ' + message.getAuctionId())
        auc = self.getAuctionByID(message.getAuctionId())
        bids = []
        if auc.getAuctionType() == auction_type['ENGLISH']:
            for block in auc.getAuctionBlockChain().blocks[1:]:
                b = Bid.unwrapBid(json.loads(block.data))
                bids.append({'date': block.timestamp, 'value': b.getValue()})

        else:
            bids.append({'bids': len(auc.getBids())})

        # Return Message
        messageToSend.setBids(bids)
        messageToSend.setStatus({'success': 'OK'})

        return messageToSend

    def listBidsOfClient(self, data):
        messageToSend = List_Bids_Of_Client_MR_Response()

        message = List_Bids_Of_Client_MR_Request()

        # Check message formatting
        try:
            message.unpack(data)
        except:
            messageToSend.setStatus({'error': 'Message badly formatted'})
            return messageToSend

        # Check Signature
        if not message.verify_signature(MANAGER_PUBLIC_KEY):
            messageToSend.setStatus({'error': 'Invalid signature'})
            return messageToSend

        # Do internal Stuff
        # ....

        # Return Message
        messageToSend.setBlockchains('blockchains list')
        messageToSend.setStatus({'success': 'OK'})

        return messageToSend

    def cryptoPuzzle(self, data):
        messageToSend = Bid_On_Auction_Crypto_CR_Response()

        message = Bid_On_Auction_Crypto_CR_Request()

        # Check message formatting
        try:
            message.unpack(data)
        except:
            messageToSend.setStatus({'error': 'Message badly formatted'})
            return messageToSend
        challenge = secrets.token_urlsafe(10)
        while challenge in self.cryptoPuzzleChallenges:
            challenge = secrets.token_urlsafe(10)
        self.cryptoPuzzleChallenges.append(challenge)
        difficulty = self.cryptoPuzzleDifficulty

        messageToSend.setChallenge({'challenge': challenge, 'difficulty': difficulty})
        messageToSend.setStatus({'success': 'OK'})

        return messageToSend

    def bidOnAuction(self, data):
        messageToSend = Bid_On_Auction_Bid_CR_Response()

        message = Bid_On_Auction_Bid_CR_Request()

        # Check message formatting
        try:
            message.unpack(data)
        except:
            messageToSend.setStatus({'error': 'Message badly formatted'})
            return messageToSend

        # Check CryptoPuzzle

        challenge = message.getCryptoPuzzleResult()['challenge']
        if challenge not in self.cryptoPuzzleChallenges:
            messageToSend.setStatus({'error': 'Crypto puzzle challenge not asked for'})
            return messageToSend

        difficulty = self.cryptoPuzzleDifficulty
        token = message.getCryptoPuzzleResult()['result']

        messageToSend.setReceipt('Invalid Bid')

        if not cryptoPuzzle.checkChallenge(challenge, token, difficulty):
            messageToSend.setStatus({'error': 'Crypto puzzle not correct'})
            return messageToSend

        self.cryptoPuzzleChallenges.remove(challenge)

        # Prepare message to manager
        messageToManager = Bid_On_Auction_Validation_MR_Request()
        packet = message.toDict()
        messageToManager.setPacket(packet)

        # Get last block of auction
        last_block = ''
        type = ''

        auc = self.getAuctionByID(message.getAuctionId())
        if not auc:
            messageToSend.setStatus({'error': 'Auction with id non existant'})
            return messageToSend
        if auc.isClosed():
            messageToSend.setStatus({'error': 'Auction is closed'})
            return messageToSend
        last_block = auc.getAuctionBlockChain().get_last_block()
        type = auc.getAuctionType()



        last_block = last_block.__dict__()
        last_block['type'] = type

        messageToManager.setLastBlock(last_block)

        messageToManager.sign_message(self.private_key)

        dataFromManager = self.sendMessageManager(messageToManager.strToByteArray())

        messageFromManager = Bid_On_Auction_Validation_MR_Response()


        # Check message formatting
        try:
            messageFromManager.unpack(dataFromManager)
        except:
            messageToSend.setStatus({'error': 'Message badly formatted from manager'})
            return messageToSend


        # Check Signature
        if not messageFromManager.verify_signature(MANAGER_PUBLIC_KEY):
            messageToSend.setStatus({'error': 'Invalid signature from manager'})
            return messageToSend

        #Decrypt status
        status = json.loads(decrypt_assymetric(self.private_key, bytes.fromhex(messageFromManager.getStatus())))

        # Check Status of Message
        if 'error' in status:
            messageToSend.setStatus({'error': 'Error in Manager'})
            return messageToSend

        info('Status' + str(status))

        # INTERNAL STUFF HERE
        # ....
        #info(messageFromManager.getBid())
        bid_data = messageFromManager.getBid()
        bid = Bid.unwrapBid(bid_data)
        auc.addBid(bid)


        # Get key
        key = bytes.fromhex(decrypt_assymetric(self.private_key, bytes.fromhex(message.getSymKey())))

        #Encrypt receipt and Status
        receipt = messageFromManager.toDict()
        receipt_encrypted = encrypt_symmetric(key, json.dumps(receipt).encode('utf-8'), message.getAlgorithm(), message.getMode())
        messageToSend.setReceipt(receipt_encrypted.hex())

        status = ({'success': 'OK'})
        status_encrypted = encrypt_symmetric(key, json.dumps(status).encode('utf-8'), message.getAlgorithm(), message.getMode())
        messageToSend.setStatus(status_encrypted.hex())
        messageToSend.sign_message(self.private_key)

        return messageToSend

    def getBlockchain(self, data):
        messageToSend = Get_Blockchain_MR_Response()

        message = Get_Blockchain_MR_Request()

        # Check message formatting
        try:
            message.unpack(data)
        except:
            messageToSend.setStatus({'error': 'Message badly formatted'})
            return messageToSend

        # Check Signature
        if not message.verify_signature(MANAGER_PUBLIC_KEY):
            messageToSend.setStatus({'error': 'Invalid signature'})
            return messageToSend

        # Do internal Stuff
        # ....
        id = message.getAuctionId()
        auctionData = self.getAuctionByID(id)
        auction = ''
        if auctionData:
            auction = auctionData.getAuctionBlockChain().to_dict()
        if not auction:
            messageToSend.setStatus({'error': 'Non existent auction'})
            return messageToSend
        # Return Message
        messageToSend.setBlockchain(auction)
        messageToSend.setStatus({'success': 'OK'})

        return messageToSend

    def getBlockchainClient(self, data):
        messageToSend = Get_Blockchain_MR_Response()

        message = Get_Blockchain_MR_Request()

        # Check message formatting
        try:
            message.unpack(data)
        except:
            messageToSend.setStatus({'error': 'Message badly formatted'})
            return messageToSend

        # Do internal Stuff
        # ....
        id = message.getAuctionId()
        auctionData = self.getAuctionByID(id)
        if not auctionData.isClosed():
            messageToSend.setStatus({'error': 'Auction not yet closed'})
            return messageToSend
        auction = ''
        if auctionData:
            auction = auctionData.getAuctionBlockChain().to_dict()
        if not auction:
            messageToSend.setStatus({'error': 'Non existent auction'})
            return messageToSend
        # Return Message
        messageToSend.setBlockchain(auction)
        messageToSend.setStatus({'success': 'OK'})

        return messageToSend


    def sendMessageManager(self, data):
        # Create a UDP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        server_address = (MANAGER_CONNECTION_ADDRESS, MANAGER_CONNECTION_PORT)

        try:
            # Send data
            info('Sending to Manager')
            sent = sock.sendto(data, server_address)

            # Receive response
            info('Waiting for response')
            data, server = sock.recvfrom(PACKET_SIZE)
            info('Received response from Manager with {} bytes'.format(str(len(data))))
        finally:
            sock.close()
            return data

    def saveAuctionToFile(self, auction):
        return

    def getAuctionByID(self, id):
        for auc in self.auctions:
            if auc.getAuctionId() == id:
                return auc

