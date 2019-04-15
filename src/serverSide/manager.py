import socket
import sys
import os
import pickle
from collections import defaultdict

sys.path.append('..')
from src.utils import *
from src.const import *
from src.messageType.messageReq import *
from src.messageType.messageRsp import *
import src.modules.certificateTools as certTools
from src.modules.cyphers import *
from src.auctionType.bid import *
from src.auctionType.auction import *
from src.modules.blockchain import *

class Manager:
    def __init__(self):
        self.clients = []
        with open(os.path.join('serverSide', 'privManager.key'), "rb") as key_file:
            self.private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )
            self.auctionsKeys = []
            self.tokens = []
            self.blindKeys = defaultdict(list)
            # try:
            #     f = open('managerInternal', 'r')
            #     a = json.loads(f.read())
            #     self.auctionsKeys += a['keys']
            #     self.tokens += a['tokens']
            #     f.close()
            # except:
            #     pass
    def openConnection(self,socketPort):
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
            dataToSend.sign_message(self.private_key)
            info('Status: ' + str(dataToSend.getStatus()))

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
        if id_message == packetIds['CREATE_AUCTION_CM']:
            info('Packet with ID: CREATE_AUCTION_CM')
            return self.createAuction(data)
        elif id_message == packetIds['TERMINATE_AUCTION_CM']:
            info('Packet with ID: TERMINATE_AUCTION_CM')
            return self.terminateAuction(data)
        elif id_message == packetIds['LIST_BIDS_OF_CLIENT_CM']:
            info('Packet with ID: LIST_BIDS_OF_CLIENT_CM')
            return self.listBidsOfClient(data)
        elif id_message == packetIds['BID_ON_AUCTION_VALIDATION_MR']:
            info('Packet with ID: BID_ON_AUCTION_VALIDATION_MR')
            return self.bidOnAuction(data)
        elif id_message == packetIds['CHECK_ENGLISH_AUCTION_OUTCOME_CM']:
            info('Packet with ID: CHECK_ENGLISH_AUCTION_OUTCOME_CM')
            return self.checkEnglish(data)
        elif id_message == packetIds['CHECK_BLIND_AUCTION_OUTCOME_CM']:
            info('Packet with ID: CHECK_BLIND_AUCTION_OUTCOME_CM')
            return self.checkBlind(data)
        elif id_message == packetIds['CHECK_BLIND_AUCTION_OUTCOME_UNCLAIMED_CM']:
            info('Packet with ID: CHECK_BLIND_AUCTION_OUTCOME_UNCLAIMED_CM')
            return self.checkBlindUnclaimed(data)
        elif id_message == packetIds['CHECK_BLIND_AUCTION_OUTCOME_CLAIMED_CM']:
            info('Packet with ID: CHECK_BLIND_AUCTION_OUTCOME_CLAIMED_CM')
            return self.checkBlindClaimed(data)
        elif id_message == packetIds['GET_KEYS_AUCTION_CM']:
            info('Packet with ID: GET_KEYS_AUCTION_CM')
            return self.getKeys(data)
        else:
            info('Invalid packet ID: DISCARDING')
            return Message(0, 'Response')

    def createAuction(self, data):
        messageToSend = Create_Auction_CM_Response()

        message = Create_Auction_CM_Request()

        # Check message formatting
        try:
            message.unpack(data)
        except:
            messageToSend.setStatus({'error': 'Message badly formatted'})
            return messageToSend

        # Check Signature
        try:
            cert = certTools.load_certificate(bytes.fromhex(message.getCertificate()))
        except:
            messageToSend.setStatus({'error': 'Not a certificate in certificate field'})
            return messageToSend

        if not message.verify_signature(cert.public_key()):
            messageToSend.setStatus({'error': 'Invalid signature'})
            return messageToSend

        # Check Certificate (chain)
        if not certTools.verifyCertificateChainServerSide(cert):
            messageToSend.setStatus({'error': 'Invalid certificate'})
            return messageToSend

        # Prepare packet to send to Repository
        messageToRep = Create_Auction_MR_Request()
        messageToRep.setAuctionType(message.getAuctionType())
        messageToRep.setClaimTime(message.getClaimTime())
        messageToRep.setTimeLimit(message.getTimeLimit())
        messageToRep.setName(message.getName())
        messageToRep.setDescription(message.getDescription())
        messageToRep.sign_message(self.private_key)

        data = self.sendMessageRepository(messageToRep.strToByteArray())

        messageFromRep = Create_Auction_MR_Response()

        # Check message formatting
        try:
            messageFromRep.unpack(data)
        except:
            messageToSend.setStatus({'error': 'Message from Repository badly formatted'})
            return messageToSend

        # Check Signature
        if not messageFromRep.verify_signature(REPOSITORY_PUBLIC_KEY):
            messageToSend.setStatus({'error': 'Invalid signature from Repository'})
            return messageToSend

        # Check Status of Message
        if 'error' in messageFromRep.getStatus():
            messageToSend.setStatus({'error': 'Error in Repository'})
            return messageToSend

        keyToAdd = generateSymKey()
        self.auctionsKeys.append({'auc_id': messageFromRep.getAuctionID(), 'key': keyToAdd.hex()})
        self.tokens.append({'auc_id': messageFromRep.getAuctionID(), 'certificate': message.getCertificate()})

        if int(message.getAuctionType()) != auction_type['ENGLISH']:
            self.blindKeys[messageFromRep.getAuctionID()] = []

        messageToSend.setAuctionID(messageFromRep.getAuctionID())
        messageToSend.setStatus({'success': 'OK'})

        return messageToSend

    def terminateAuction(self, data):
        messageToSend = Terminate_Auction_CM_Response()

        message = Terminate_Auction_CM_Request()

        # Check message formatting
        try:
            message.unpack(data)
        except:
            messageToSend.setStatus({'error': 'Message badly formatted'})
            return messageToSend

        # Check Signature
        try:
            cert = certTools.load_certificate(bytes.fromhex(message.getCertificate()))
        except:
            messageToSend.setStatus({'error': 'Not a certificate in certificate field'})
            return messageToSend

        certToCompare = ''

        for entry in self.tokens:
            if entry['auc_id'] == message.getAuctionId():
                certToCompare = certTools.load_certificate(bytes.fromhex(entry['certificate']))

        if not certToCompare:
            messageToSend.setStatus({'error': 'Not a valid certificate'})
            return messageToSend

        if not message.verify_signature(certToCompare.public_key()):
            messageToSend.setStatus({'error': 'Invalid signature'})
            return messageToSend

        # Check Certificate (chain)
        if not certTools.verifyCertificateChainServerSide(cert):
            messageToSend.setStatus({'error': 'Invalid certificate'})
            return messageToSend

        # Prepare packet to send to Repository
        messageToRep = Terminate_Auction_MR_Request()
        messageToRep.setAuctionId(message.getAuctionId())
        messageToRep.sign_message(self.private_key)

        data = self.sendMessageRepository(messageToRep.strToByteArray())

        messageFromRep = Terminate_Auction_MR_Response()

        # Check message formatting
        try:
            messageFromRep.unpack(data)
        except:
            messageToSend.setStatus({'error': 'Message from Repository badly formatted'})
            return messageToSend

        # Check Signature
        if not messageFromRep.verify_signature(REPOSITORY_PUBLIC_KEY):
            messageToSend.setStatus({'error': 'Invalid signature from Repository'})
            return messageToSend

        # Check Status of Message
        if 'error' in messageFromRep.getStatus():
            messageToSend.setStatus({'error': 'Error in Repository'})
            return messageToSend

        messageToSend.setStatus({'success': 'OK'})

        return messageToSend

    def listBidsOfClient(self, data):
        messageToSend = List_Bids_Of_Client_CM_Response()

        message = List_Bids_Of_Client_CM_Request()

        # Check message formatting
        try:
            message.unpack(data)
        except:
            messageToSend.setStatus({'error': 'Message badly formatted'})
            return messageToSend

        # Check Signature
        try:
            cert = certTools.load_certificate(bytes.fromhex(message.getCertificate()))
        except:
            messageToSend.setStatus({'error': 'Not a certificate in certificate field'})
            return messageToSend

        if not message.verify_signature(cert.public_key()):
            messageToSend.setStatus({'error': 'Invalid signature'})
            return messageToSend

        # Check Certificate (chain)
        if not certTools.verifyCertificateChainServerSide(cert):
            messageToSend.setStatus({'error': 'Invalid certificate'})
            return messageToSend

        # Prepare packet to send to Repository
        messageToRep = List_Bids_Of_Client_MR_Request()

        messageToRep.sign_message(self.private_key)

        data = self.sendMessageRepository(messageToRep.strToByteArray())

        messageFromRep = List_Bids_Of_Client_MR_Response()

        # Check message formatting
        try:
            messageFromRep.unpack(data)
        except:
            messageToSend.setStatus({'error': 'Message from Repository badly formatted'})
            return messageToSend

        # Check Signature
        if not messageFromRep.verify_signature(REPOSITORY_PUBLIC_KEY):
            messageToSend.setStatus({'error': 'Invalid signature from Repository'})
            return messageToSend

        # Check Status of Message
        if 'error' in messageFromRep.getStatus():
            messageToSend.setStatus({'error': 'Error in Repository'})
            return messageToSend

        # DO STUFF Internal Code ...
        # ...
        key = bytes.fromhex(decrypt_assymetric(self.private_key, bytes.fromhex(message.getSymKey())))

        info(messageFromRep.getBlockchains())
        bids_encrypted = encrypt_symmetric(key, "bids list", message.getAlgorithm(), message.getMode())
        messageToSend.setBids(bids_encrypted.hex())
        messageToSend.setStatus({'success': 'OK'})

        return messageToSend

    def bidOnAuction(self, data):
        messageToSend = Bid_On_Auction_Validation_MR_Response()

        message = Bid_On_Auction_Validation_MR_Request()

        # Check message formatting
        try:
            message.unpack(data)
        except:
            status = {'error': 'Message badly formatted'}
            status = encrypt_assymetric(REPOSITORY_PUBLIC_KEY, json.dumps(status))
            messageToSend.setStatus(status.hex())
            return messageToSend

        # Check Signature
        if not message.verify_signature(REPOSITORY_PUBLIC_KEY):
            status = {'error': 'Invalid signature'}
            status = encrypt_assymetric(REPOSITORY_PUBLIC_KEY, json.dumps(status))
            messageToSend.setStatus(status.hex())
            return messageToSend

        # Unpack inside message
        messageInside = Bid_On_Auction_Bid_CR_Request()

        # Check inside message formatting
        try:
            messageInside.unpack(message.getPacket(), decode=False)
        except:
            status = {'error': 'Inside Message badly formatted'}
            status = encrypt_assymetric(REPOSITORY_PUBLIC_KEY, json.dumps(status))
            messageToSend.setStatus(status.hex())
            return messageToSend

        # Check inside message validation
        # Check Signature
        hybrid_key = bytes.fromhex(decrypt_assymetric(self.private_key, bytes.fromhex(messageInside.getHybridKey())))
        certData = decrypt_symmetric(hybrid_key, bytes.fromhex(messageInside.getCertificate()))

        try:
            cert = certTools.load_certificate(certData)
        except:
            status = {'error': 'Not a certificate in certificate field'}
            status = encrypt_assymetric(REPOSITORY_PUBLIC_KEY, json.dumps(status))
            messageToSend.setStatus(status.hex())
            return messageToSend

        if not messageInside.verify_signature(cert.public_key()):
            status = {'error': 'Invalid signature from client'}
            status = encrypt_assymetric(REPOSITORY_PUBLIC_KEY, json.dumps(status))
            messageToSend.setStatus(status.hex())
            return messageToSend

        # Check Certificate (chain)
        if not certTools.verifyCertificateChainServerSide(cert):
            status = {'error': 'Invalid certificate from client'}
            status = encrypt_assymetric(REPOSITORY_PUBLIC_KEY, json.dumps(status))
            messageToSend.setStatus(status.hex())
            return messageToSend

        # DO INTERNAL STUFF TO VALIDATE BID
        # ...
        last_block = message.getLastBlock()
        if not last_block['data']:
            status = {'error': 'Auction closed'}
            messageToSend.setStatus(status.hex())
            return messageToSend
        bid = Bid()
        if last_block['type'] == auction_type['ENGLISH']:
            block = json.loads(last_block['data'])
            if not 'id' in block:
                bid.unwrapBid(block)
                if bid.getValue() >= messageInside.getBid():
                    status = {'error': 'Bid lower than last bid'}
                    messageToSend.setStatus(status.hex())
                    return messageToSend

        # Dynamic code


        # Create bid
        bid_to_attach = Bid()

        bid_to_attach.setBidType(last_block['type'])
        bid_to_attach.setValue(messageInside.getBid())

        if last_block['type'] == auction_type['BLIND']:
            bid_to_attach.setIdentity(certData.hex())
        else:
            key = ''
            for keyentry in self.auctionsKeys:
                if keyentry['auc_id'] == messageInside.getAuctionId():
                    key = bytes.fromhex(keyentry['key'])
            bid_to_attach.setIdentity(encrypt_symmetric(key, certData).hex())
            bid_to_attach.setIdentityState(ENCRYPTED)

        messageToSend.setBid(bid_to_attach.wrapBid('none'))
        packet = message.toDict()
        messageToSend.setPacket(packet)
        status = {'success': 'OK'}
        #info(len(messageToSend.strToByteArray()))
        # Encrypt status
        status = encrypt_assymetric(REPOSITORY_PUBLIC_KEY, json.dumps(status))
        messageToSend.setStatus(status.hex())
        return messageToSend

    def checkEnglish(self, data):
        messageToSend = Check_English_Auction_Outcome_CM_Response()

        message = Check_English_Auction_Outcome_CM_Request()

        # Check message formatting
        try:
            message.unpack(data)
        except:
            messageToSend.setStatus({'error': 'Message badly formatted'})
            return messageToSend

        # Check Signature
        try:
            cert = certTools.load_certificate(bytes.fromhex(message.getCertificate()))
        except:
            messageToSend.setStatus({'error': 'Not a certificate in certificate field'})
            return messageToSend

        if not message.verify_signature(cert.public_key()):
            messageToSend.setStatus({'error': 'Invalid signature'})
            return messageToSend

        # Check Certificate (chain)
        if not certTools.verifyCertificateChainServerSide(cert):
            messageToSend.setStatus({'error': 'Invalid certificate'})
            return messageToSend

        # DO INTERNAL STUFF
        # GET BLOCKCHAIN
        messageToRep = Get_Blockchain_MR_Request()
        messageToRep.setAuctionId(message.getAuctionId())
        messageToRep.sign_message(self.private_key)

        res = self.sendMessageRepository(messageToRep.strToByteArray())

        messageFromRep = Get_Blockchain_MR_Response()

        # Check message formatting
        try:
            messageFromRep.unpack(res)
        except:
            messageToSend.setStatus({'error': 'Message from Repository badly formatted'})
            return messageToSend

        # Check Status of Message
        if 'error' in messageFromRep.getStatus():
            messageToSend.setStatus({'error': 'Auction non existent'})
            return messageToSend

        # Load Blockchain into auction
        blockchain = Blockchain.load_dict_blockchain(messageFromRep.getBlockchain())
        if not blockchain.verify_integrity():
            messageToSend.setStatus({'error': 'Blockchain is invalid'})
            return messageToSend
        auction = Auction.unwrapAuction(blockchain)

        if not auction.isClosed():
            messageToSend.setStatus({'error': 'Auction is not closed'})
            return messageToSend

        if auction.getAuctionType() != auction_type['ENGLISH']:
            messageToSend.setStatus({'error': 'Auction is not english'})
            return messageToSend

        identity = ''
        value = 0
        me = False
        for bid in auction.getBids():
            if int(bid.getValue()) > value:
                value = int(bid.getValue())
                identity = bid.getIdentity()

        if identity:
            identity = decrypt_symmetric(self.getKeyOfAuction(auction.getAuctionId()), bytes.fromhex(identity))
            certToCompare = certTools.load_certificate(identity)
            if certToCompare.fingerprint(hashes.SHA256()) == cert.fingerprint(hashes.SHA256()):
                me = True
            identity = certTools.getNameInCert(cert)

        # Return
        # Get key
        key = bytes.fromhex(decrypt_assymetric(self.private_key, bytes.fromhex(message.getSymKey())))

        # Encrypt winnerID and winnervalue
        winnerID = {'me': me, 'ID': identity}
        winnerID_encrypted = encrypt_symmetric(key, json.dumps(winnerID).encode('utf-8'), message.getAlgorithm(), message.getMode())
        messageToSend.setWinnerID(winnerID_encrypted.hex())
        winnerValue = {'value': value}
        winnerValue_encrypted = encrypt_symmetric(key, json.dumps(winnerValue).encode('utf-8'), message.getAlgorithm(), message.getMode())
        messageToSend.setWinnerValue(winnerValue_encrypted.hex())
        messageToSend.setStatus({'success': 'OK'})

        return messageToSend

    def checkBlind(self, data):
        messageToSend = Check_Blind_Auction_Outcome_CM_Response()

        message = Check_Blind_Auction_Outcome_CM_Request()
        # Check message formatting
        try:
            message.unpack(data)
        except:
            messageToSend.setStatus({'error': 'Message badly formatted'})
            return messageToSend

        # Check Signature
        try:
            cert = certTools.load_certificate(bytes.fromhex(message.getCertificate()))
        except:
            messageToSend.setStatus({'error': 'Not a certificate in certificate field'})
            return messageToSend

        if not message.verify_signature(cert.public_key()):
            messageToSend.setStatus({'error': 'Invalid signature'})
            return messageToSend

        # Check Certificate (chain)
        if not certTools.verifyCertificateChainServerSide(cert):
            messageToSend.setStatus({'error': 'Invalid certificate'})
            return messageToSend

        # DO INTERNAL STUFF
        # GET BLOCKCHAIN
        messageToRep = Get_Blockchain_MR_Request()
        messageToRep.setAuctionId(message.getAuctionId())
        messageToRep.sign_message(self.private_key)

        res = self.sendMessageRepository(messageToRep.strToByteArray())

        messageFromRep = Get_Blockchain_MR_Response()

        # Check message formatting
        try:
            messageFromRep.unpack(res)
        except:
            messageToSend.setStatus({'error': 'Message from Repository badly formatted'})
            return messageToSend

        # Check Status of Message
        if 'error' in messageFromRep.getStatus():
            messageToSend.setStatus({'error': 'Auction non existent'})
            return messageToSend

        # Load Blockchain into auction
        blockchain = Blockchain.load_dict_blockchain(messageFromRep.getBlockchain())
        if not blockchain.verify_integrity():
            messageToSend.setStatus({'error': 'Blockchain is invalid'})
            return messageToSend
        auction = Auction.unwrapAuction(blockchain)
        auction.isClosed()

        if auction.getState() == auction_state['OPEN']:
            messageToSend.setStatus({'error': 'Auction is still open'})
            return messageToSend

        if auction.getAuctionType() == auction_type['ENGLISH']:
            messageToSend.setStatus({'error': 'Auction is english'})
            return messageToSend

        closed = False
        if auction.getState() == auction_state['CLOSED']:
            closed = True


        # Return
        # Get key
        key = bytes.fromhex(decrypt_assymetric(self.private_key, bytes.fromhex(message.getSymKey())))
        if closed:
            auctionState = {'closed': True}
        else:
            auctionState = {'closed': False}
        auctionState_encrypted = encrypt_symmetric(key, json.dumps(auctionState).encode('utf-8'), message.getAlgorithm(),
                                                  message.getMode())
        messageToSend.setStatusAuction(auctionState_encrypted.hex())
        messageToSend.setStatus({'success': 'OK'})

        return messageToSend

    def checkBlindUnclaimed(self, data):
        messageToSend = Check_Blind_Auction_Outcome_Unclaimed_CM_Response()

        message = Check_Blind_Auction_Outcome_Unclaimed_CM_Request()

        # Check message formatting
        try:
            message.unpack(data)
        except:
            messageToSend.setStatus({'error': 'Message badly formatted'})
            return messageToSend

        # Check Signature
        try:
            cert = certTools.load_certificate(bytes.fromhex(message.getCertificate()))
        except:
            messageToSend.setStatus({'error': 'Not a certificate in certificate field'})
            return messageToSend

        if not message.verify_signature(cert.public_key()):
            messageToSend.setStatus({'error': 'Invalid signature'})
            return messageToSend

        # Check Certificate (chain)
        if not certTools.verifyCertificateChainServerSide(cert):
            messageToSend.setStatus({'error': 'Invalid certificate'})
            return messageToSend

        # Get Key Blind Bid
        keyBlindBid = bytes.fromhex(decrypt_assymetric(self.private_key, bytes.fromhex(message.getKeyBlindBid())))
        info(keyBlindBid)

        # GET BLOCKCHAIN
        messageToRep = Get_Blockchain_MR_Request()
        messageToRep.setAuctionId(message.getAuctionId())
        messageToRep.sign_message(self.private_key)

        res = self.sendMessageRepository(messageToRep.strToByteArray())

        messageFromRep = Get_Blockchain_MR_Response()

        # Check message formatting
        try:
            messageFromRep.unpack(res)
        except:
            messageToSend.setStatus({'error': 'Message from Repository badly formatted'})
            return messageToSend

        # Check Status of Message
        if 'error' in messageFromRep.getStatus():
            messageToSend.setStatus({'error': 'Auction non existent'})
            return messageToSend

        # Load Blockchain into auction
        blockchain = Blockchain.load_dict_blockchain(messageFromRep.getBlockchain())
        if not blockchain.verify_integrity():
            messageToSend.setStatus({'error': 'Blockchain is invalid'})
            return messageToSend
        auction = Auction.unwrapAuction(blockchain)
        auction.isClosed()

        if auction.getAuctionType() == auction_type['ENGLISH']:
            messageToSend.setStatus({'error': 'Auction is english'})
            return messageToSend

        for bid in auction.getBids():
            value = ''
            identity = bid.getIdentity()
            if auction.getAuctionType() == auction_type['BLIND']:
                identity = bytes.fromhex(identity)
            else:
                identity = decrypt_symmetric(self.getKeyOfAuction(auction.getAuctionId()), bytes.fromhex(identity))
            certToCompare = certTools.load_certificate(identity)

            if certToCompare.fingerprint(hashes.SHA256()) == cert.fingerprint(hashes.SHA256()):
                valueData = decrypt_symmetric(keyBlindBid, bytes.fromhex(bid.getValue())).decode('utf-8')
                try:
                    value = int(valueData)
                    self.blindKeys[auction.getAuctionId()].append(
                        {'identity': identity, 'value': value, 'keyBlindBid': keyBlindBid})
                    break
                except:
                    pass

        if not value:
            messageToSend.setStatus({'error': 'Key is not valid'})
            return messageToSend

        info(self.blindKeys)
        messageToSend.setStatus({'success': 'OK'})

        return messageToSend

    def checkBlindClaimed(self, data):
        messageToSend = Check_Blind_Auction_Outcome_Claimed_CM_Response()

        message = Check_Blind_Auction_Outcome_Claimed_CM_Request()

        # Check message formatting
        try:
            message.unpack(data)
        except:
            messageToSend.setStatus({'error': 'Message badly formatted'})
            return messageToSend

        # Check Signature
        try:
            cert = certTools.load_certificate(bytes.fromhex(message.getCertificate()))
        except:
            messageToSend.setStatus({'error': 'Not a certificate in certificate field'})
            return messageToSend

        if not message.verify_signature(cert.public_key()):
            messageToSend.setStatus({'error': 'Invalid signature'})
            return messageToSend

        # Check Certificate (chain)
        if not certTools.verifyCertificateChainServerSide(cert):
            messageToSend.setStatus({'error': 'Invalid certificate'})
            return messageToSend

        # DO INTERNAL STUFF
        if not self.blindKeys[message.getAuctionId()]:
            messageToSend.setStatus({'error': 'No one claimed this auction :('})
            return messageToSend

        # GET BLOCKCHAIN
        messageToRep = Get_Blockchain_MR_Request()
        messageToRep.setAuctionId(message.getAuctionId())
        messageToRep.sign_message(self.private_key)

        res = self.sendMessageRepository(messageToRep.strToByteArray())

        messageFromRep = Get_Blockchain_MR_Response()

        # Check message formatting
        try:
            messageFromRep.unpack(res)
        except:
            messageToSend.setStatus({'error': 'Message from Repository badly formatted'})
            return messageToSend

        # Check Status of Message
        if 'error' in messageFromRep.getStatus():
            messageToSend.setStatus({'error': 'Auction non existent'})
            return messageToSend

        # Load Blockchain into auction
        blockchain = Blockchain.load_dict_blockchain(messageFromRep.getBlockchain())
        if not blockchain.verify_integrity():
            messageToSend.setStatus({'error': 'Blockchain is invalid'})
            return messageToSend
        auction = Auction.unwrapAuction(blockchain)
        auction.isClosed()

        if auction.getAuctionType() == auction_type['ENGLISH']:
            messageToSend.setStatus({'error': 'Auction is english'})
            return messageToSend

        highest_value = 0
        winner_id = ''
        me = False
        for bid in auction.getBids():
            # Get identity and decode
            identity = bid.getIdentity()
            if auction.getAuctionType() == auction_type['BLIND']:
                identity = bytes.fromhex(identity)
            else:
                identity = decrypt_symmetric(self.getKeyOfAuction(auction.getAuctionId()), bytes.fromhex(identity))
            certInBid = certTools.load_certificate(identity)
            # Search for entry saved in manager for the key to decrypt value by comparing cert
            entryBlind = ''
            for entry in self.blindKeys[message.getAuctionId()]:
                certTemp = certTools.load_certificate(entry['identity'])
                if certTemp.fingerprint(hashes.SHA256()) == certInBid.fingerprint(hashes.SHA256()):
                    entryBlind = entry
                    break
            if entryBlind:
                valueData = decrypt_symmetric(entryBlind['keyBlindBid'], bytes.fromhex(bid.getValue())).decode('utf-8')
                try:
                    value = int(valueData)
                    if value > highest_value:
                        highest_value = value
                        winner_id = certInBid
                except:
                    pass

        if cert.fingerprint(hashes.SHA256()) == winner_id.fingerprint(hashes.SHA256()):
            me = True
        # Encrypt winnerID and winnervalue
        # Get key
        key = bytes.fromhex(decrypt_assymetric(self.private_key, bytes.fromhex(message.getSymKey())))
        winnerID = {'me': me, 'ID': certTools.getNameInCert(winner_id)}
        winnerID_encrypted = encrypt_symmetric(key, json.dumps(winnerID).encode('utf-8'), message.getAlgorithm(), message.getMode())
        messageToSend.setWinnerID(winnerID_encrypted.hex())
        winnerValue = {'value': highest_value}
        winnerValue_encrypted = encrypt_symmetric(key, json.dumps(winnerValue).encode('utf-8'), message.getAlgorithm(),
                                                  message.getMode())
        messageToSend.setWinnerValue(winnerValue_encrypted.hex())
        messageToSend.setStatus({'success': 'OK'})

        return messageToSend

    def getKeys(self, data):
        messageToSend = Get_Keys_Auction_CM_Response()

        message = Get_Keys_Auction_CM_Request()

        # Check message formatting
        try:
            message.unpack(data)
        except:
            messageToSend.setStatus({'error': 'Message badly formatted'})
            return messageToSend

        # Check Signature
        try:
            cert = certTools.load_certificate(bytes.fromhex(message.getCertificate()))
        except:
            messageToSend.setStatus({'error': 'Not a certificate in certificate field'})
            return messageToSend

        if not message.verify_signature(cert.public_key()):
            messageToSend.setStatus({'error': 'Invalid signature'})
            return messageToSend

        # Check Certificate (chain)
        if not certTools.verifyCertificateChainServerSide(cert):
            messageToSend.setStatus({'error': 'Invalid certificate'})
            return messageToSend

        # GET BLOCKCHAIN
        messageToRep = Get_Blockchain_MR_Request()
        messageToRep.setAuctionId(message.getAuctionId())
        messageToRep.sign_message(self.private_key)

        res = self.sendMessageRepository(messageToRep.strToByteArray())

        messageFromRep = Get_Blockchain_MR_Response()

        # Check message formatting
        try:
            messageFromRep.unpack(res)
        except:
            messageToSend.setStatus({'error': 'Message from Repository badly formatted'})
            return messageToSend

        # Check Status of Message
        if 'error' in messageFromRep.getStatus():
            messageToSend.setStatus({'error': 'Auction non existent'})
            return messageToSend

        # Load Blockchain into auction
        blockchain = Blockchain.load_dict_blockchain(messageFromRep.getBlockchain())
        if not blockchain.verify_integrity():
            messageToSend.setStatus({'error': 'Blockchain is invalid'})
            return messageToSend
        auction = Auction.unwrapAuction(blockchain)

        if not auction.isClosed():
            messageToSend.setStatus({'error': 'Auction is not closed'})
            return messageToSend

        if auction.getAuctionType() == auction_type['BLIND']:
            messageToSend.setIdentityKeys("Is a blind auction")
        else:
            identityKey = self.getKeyOfAuction(auction.getAuctionId())
            messageToSend.setIdentityKeys(identityKey.hex())

        if auction.getAuctionType() != auction_type['ENGLISH']:
            keyList = self.blindKeys[auction.getAuctionId()]
            messageToSend.setBlindKeys(pickle.dumps(keyList).hex())
        else:
            messageToSend.setBlindKeys('Not a blind auction')

        messageToSend.setStatus({'success': 'OK'})
        return messageToSend

    def sendMessageRepository(self, data):
        # Create a UDP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        server_address = (REPOSITORY_CONNECTION_ADDRESS, REPOSITORY_CONNECTION_PORT)

        try:
            # Send data
            info('Sending to Repository')
            sent = sock.sendto(data, server_address)

            # Receive response
            info('Waiting for response')
            data, server = sock.recvfrom(PACKET_SIZE)
            info('Received response from Repository with size ' + str(len(data)))
        finally:
            sock.close()
            return data

    def getKeyOfAuction(self, id):
        for auc in self.auctionsKeys:
            if auc['auc_id'] == id:
                return bytes.fromhex(auc['key'])
        return None




