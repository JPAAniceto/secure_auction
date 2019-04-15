import socket
import sys
import os
import pickle

sys.path.append('..')
from src.utils import *
from src.const import *
from src.messageType.messageReq import *
from src.messageType.messageRsp import *
from src.modules.cyphers import *
import src.modules.cryptoPuzzle as cryptoPuzzle
from src.modules.blockchain import *
from src.auctionType.auction import *
from src.auctionType.bid import *
import src.modules.certificateTools as certTools



class Client:
    def __init__(self, name, userId):
        self.name = name
        self.id = userId
        self.keys = []
        if not os.path.exists('receipts'):
            os.makedirs('receipts')

    def printMenu(self):
        print('\n***MENU***')
        print('1 - Create auction')
        print('2 - Terminate auction')
        print('3 - List auctions')
        print('4 - List bids of a auction')
        print('5 - List my bids')
        print('6 - Bid on auction')
        print('7 - Check outcome of a auction/bid')
        print('8 - Validate a receipt')
        print('9 - Verify and see all info about closed auction')
        print('0 - Exit Program')
        print()

    def runOption(self, option):
        if option is 1:
            return self.createAuction()
        elif option is 2:
            return self.terminateAuction()
        elif option is 3:
            return self.listAuctions()
        elif option is 4:
            return self.listBidsofAuction()
        elif option is 5:
            return self.listMyBids()
        elif option is 6:
            return self.bidOnAuction()
        elif option is 7:
            return self.checkOutcome()
        elif option is 8:
            return self.validateReceipt()
        elif option is 9:
            return self.verifyAuction()

    def createAuction(self):
        # Get all parameters
        messageToSend = self.createAuction_args()
        if not messageToSend:
            return

        slot = self.getCard()
        if not slot:
            return

        # Sign Message
        messageToSend.sign_message_CC(int(slot))

        # Send to manager
        res = self.sendMessageManager(messageToSend.strToByteArray())

        response = Create_Auction_CM_Response()

        # Unpack Response
        try:
            response.unpack(res)
        except:
            print('Malformed response from server')
            return

        if not response.verify_signature(MANAGER_PUBLIC_KEY):
            print('Oops, manager signature failed. Someone modified the packet')
            return

        # Check Status of Message
        if 'error' in response.getStatus():
            print('Error creating auction: ' + response.getStatus()['error'])
            return

        # Print Status
        print('Created Auction with ID: ' + response.getAuctionID())

        return

    def createAuction_args(self):
        # Create Request
        messageToSend = Create_Auction_CM_Request()

        # Get Auction Type
        print('Choose type of auction:\n1- English\n2- Blind\n3- Full Blind')
        auctionType = input()
        try:
            a = int(auctionType)
            assert a > 0 and a < 4
        except:
            print('Invalid type of auction')
            return
        messageToSend.setAuctionType(str(a-1))

        # Get Claim Time
        if int(auctionType) > 1:
            print('How much claim time? (min)')
            claimTime = input()
            try:
                assert int(claimTime) > 0
            except:
                print('Invalid Claim Time')
                return
            messageToSend.setClaimTime(claimTime)
        else:
            messageToSend.setClaimTime('0')

        # Get Time Limit
        print('How much time limit? (min)')
        timeLimit = input()
        try:
            assert int(timeLimit) > 0
        except:
            print('Invalid Time Limit')
            return
        messageToSend.setTimeLimit(timeLimit)

        # Get Name
        print('Name?')
        name = input()
        messageToSend.setName(name)

        # Get Description
        print('Description?')
        description = input()
        messageToSend.setDescription(description)

        return messageToSend

    def terminateAuction(self):
        # Get all parameters
        messageToSend = self.terminateAuction_args()
        if not messageToSend:
            return

        slot = self.getCard()
        if not slot:
            return

        # Sign Message
        messageToSend.sign_message_CC(int(slot))

        # Send to manager
        res = self.sendMessageManager(messageToSend.strToByteArray())

        response = Terminate_Auction_CM_Response()

        # Unpack Response
        try:
            response.unpack(res)
        except:
            print('Malformed response from server')
            return

        if not response.verify_signature(MANAGER_PUBLIC_KEY):
            print('Oops, manager signature failed. Someone modified the packet')
            return

        # Check Status of Message
        if 'error' in response.getStatus():
            print('Error terminating auction: ' + response.getStatus()['error'])
            return

        # Print Status
        print('Terminated Auction with ID: ' + messageToSend.getAuctionId())

        return

    def terminateAuction_args(self):
        # Create Request
        messageToSend = Terminate_Auction_CM_Request()

        # Get Auction Type
        print('Enter the auction ID: ')
        auc_id = input()
        try:
            a = int(auc_id)
        except:
            print('Invalid auction id')
            return
        messageToSend.setAuctionId(auc_id)

        return messageToSend

    def listAuctions(self):
        # Get all parameters
        messageToSend = self.listAuctions_args()
        if not messageToSend:
            return

        # Send to repository
        res = self.sendMessageRepository(messageToSend.strToByteArray())

        response = List_Auctions_CR_Response()

        # Unpack Response
        try:
            response.unpack(res)
        except:
            print('Malformed response from server')
            return

        # Verify message signature
        if not response.verify_signature(REPOSITORY_PUBLIC_KEY):
            print('Oops, repository signature failed. Someone modified the packet')
            return

        # Check Status of Message
        if 'error' in response.getStatus():
            print('Error listing auctions: ' + response.getStatus()['error'])
            return

        #Print Result
        print('Auctions')
        for auc in response.getAuctions():
            print(auc)

        return
    def listAuctions_args(self):
        messageToSend = List_Auctions_CR_Request()
        # Get Auction Type
        print('What auctions to show:\n1- Open\n2- Closed\n3- All')
        type = input()
        try:
            a = int(type)
            assert a > 0 and a < 4
        except:
            print('Invalid type of auction')
            return
        messageToSend.setAuctionType(str(a-1))
        return messageToSend


    def listBidsofAuction(self):
        messageToSend = self.listBidsofAuction_args()
        if not messageToSend:
            return

        # Send to repository
        res = self.sendMessageRepository(messageToSend.strToByteArray())

        response = List_Bids_CR_Response()

        # Unpack Response
        try:
            response.unpack(res)
        except:
            print('Malformed response from server')
            return

        # Verify message signature
        if not response.verify_signature(REPOSITORY_PUBLIC_KEY):
            print('Oops, repository signature failed. Someone modified the packet')
            return

        # Check Status of Message
        if 'error' in response.getStatus():
            print('Error listing bids of auction: ' + response.getStatus()['error'])
            return

        # Print Result
        print('Bids of auction ' + messageToSend.getAuctionId())
        print(response.getBids())

        return

    def listBidsofAuction_args(self):
        messageToSend = List_Bids_CR_Request()

        # Get Auction Type
        print('Enter the auction ID: ')
        auc_id = input()
        try:
            a = int(auc_id)
        except:
            print('Invalid type of auction')
            return
        messageToSend.setAuctionId(auc_id)

        return messageToSend

    def listMyBids(self):
        bids = []

        # Get client cert
        slot = self.getCard()
        if not slot:
            return

        cert = ccTools.extractCert('CITIZEN AUTHENTICATION CERTIFICATE', int(slot))

        # Go to receipt folder
        for filename in os.listdir('receipts'):
            f = open(os.path.join('receipts', filename), 'r')
            # Get relevant bid information
            bid = self.getBidFromReceipt(f.read(), cert)
            if bid:
                bids.append(bid)
            f.close()

        # Print Result
        print('My bids')
        for bid in bids:
            print(bid)

        return

    def bidOnAuction(self):
        # Get and solve CryptoPuzzle
        print('Asking for cryptoPuzzle')
        crypto_ask = Bid_On_Auction_Crypto_CR_Request()

        res = self.sendMessageRepository(crypto_ask.strToByteArray())

        crypto_response = Bid_On_Auction_Crypto_CR_Response()

        # Unpack Response
        try:
            crypto_response.unpack(res)
        except:
            print('Malformed response from server')
            return

        if not crypto_response.verify_signature(REPOSITORY_PUBLIC_KEY):
            print('Oops, repository signature failed. Someone modified the packet')
            return

        # Check Status of Message
        if 'error' in crypto_response.getStatus():
            print('Error asking for cryptopuzzle: ' + crypto_response.getStatus()['error'])
            return

        challenge = crypto_response.getChallenge()['challenge']
        difficulty = crypto_response.getChallenge()['difficulty']

        print('Solving cryptopuzzle')
        result = cryptoPuzzle.solveChallenge(challenge, int(difficulty))

        print('Cryptopuzzle is solved? ' + str(cryptoPuzzle.checkChallenge(challenge, result, int(difficulty))))

        # Prepare Bid Message

        # Get Type
        encrypt_value = False
        typeV = input('Is the auction english? Y/n')
        if typeV == 'n' or typeV == 'N':
            encrypt_value = True

        messageToSend = self.bidOnAuction_args()
        if not messageToSend:
            return
        messageToSend.setCryptoPuzzleResult({'challenge': challenge, 'difficulty': difficulty, 'result': result})

        slot = self.getCard()
        if not slot:
            return

        # Encrypt symmetric key with repository public key
        if messageToSend.getAlgorithm() == 'tripledes' or messageToSend.getAlgorithm() == 'cast5' or messageToSend.getAlgorithm() == 'seed':
            keyToSend = generateSymKey(16)
        else:
            keyToSend = generateSymKey(32)

        key_encrypted = encrypt_assymetric(REPOSITORY_PUBLIC_KEY, keyToSend.hex())
        messageToSend.setSymKey(key_encrypted.hex())

        # Encrypt Value if blind
        if encrypt_value:
            key_blind_bid = generateSymKey()
            value_encrypted = encrypt_symmetric(key_blind_bid, messageToSend.getBid().encode('utf-8'))
            messageToSend.setBid(value_encrypted.hex())


        # Encrypt certificate with hybrid key with Manager public key
        key = generateSymKey()
        key_encrypted = encrypt_assymetric(MANAGER_PUBLIC_KEY, key.hex())
        messageToSend.setHybridKey(key_encrypted.hex())

        # Sign Message
        messageToSend.sign_message_CC(int(slot))

        cert = messageToSend.getCertificate()
        cert_encrypted = encrypt_symmetric(key, bytes.fromhex(cert))
        messageToSend.setCertificate(cert_encrypted.hex())

        # Send to Repository
        res = self.sendMessageRepository(messageToSend.strToByteArray())

        # Receive Response
        response = Bid_On_Auction_Bid_CR_Response()

        # Unpack Response
        try:
            response.unpack(res)
        except:
            print('Malformed response from server')
            return

        if not response.verify_signature(REPOSITORY_PUBLIC_KEY):
            print('Oops, repository signature failed. Someone modified the packet')
            return

        # Check Status of Message
        if 'error' in response.getStatus():
            print('Error bidding: ' + response.getStatus()['error'])
            return

        # Decrypt status
        status = json.loads(decrypt_symmetric(keyToSend, bytes.fromhex(response.getStatus()), messageToSend.algorithm, messageToSend.mode).decode('utf-8'))

        # Check Status of Message
        if 'error' in status:
            print('Error bidding: ' + status['error'])
            return

        receipt = json.loads(decrypt_symmetric(keyToSend, bytes.fromhex(response.getReceipt()), messageToSend.algorithm, messageToSend.mode).decode('utf-8'))

        if encrypt_value:
            self.keys.append({'auc_id': messageToSend.getAuctionId(), 'key': key_blind_bid})

        #info(receipt)

        # Deal with receipt
        filename = input('Name for the receipt?')
        with open(os.path.join('receipts',filename), 'w+') as file:
            toWrite = response.toDict()
            toWrite['keySentForEncryption'] = keyToSend.hex()
            toWrite['algorithm'] = messageToSend.algorithm
            toWrite['mode'] = messageToSend.mode
            file.write(json.dumps(toWrite))

        return

    def bidOnAuction_args(self):
        messageToSend = Bid_On_Auction_Bid_CR_Request()

        # Get Algorithm type and hash
        # Get algorithm
        print('Enter the algorithm to encrypt response: ')
        algorithm = input()
        if algorithm:
            algorithm = algorithm.replace(' ', '').lower()
            if algorithm not in sym_algorithms:
                print('Invalid Algorithm')
                return
        else:
            algorithm = 'aes'
            print('Defaulting to AES')
        messageToSend.setAlgorithm(algorithm)

        # Get mode
        print('Enter the algorithm to encrypt response: ')
        mode = input()
        if mode:
            mode = mode.replace(' ', '').lower()
            if mode not in sym_algorithms:
                print('Invalid Algorithm')
                return
        else:
            mode = 'cbc'
            print('Defaulting to CBC')
        messageToSend.setMode(mode)

        # Get Auction Type
        print('Enter the auction ID: ')
        auc_id = input()
        try:
            a = int(auc_id)
        except:
            print('Invalid auction id')
            return
        messageToSend.setAuctionId(auc_id)

        # Get Bid Value
        print('Enter value: ')
        value = input()
        try:
            a = int(value)
            assert a > 0
        except:
            print('Invalid value')
            return
        messageToSend.setBid(value)

        return messageToSend

    def checkOutcome(self):
        firstMessage = self.checkOutcome_args()

        slot = self.getCard()
        if not slot:
            return

        # Encrypt symmetric key with repository public key
        if firstMessage.getAlgorithm() == 'tripledes' or firstMessage.getAlgorithm() == 'cast5' or firstMessage.getAlgorithm() == 'seed':
            keyToSend = generateSymKey(16)
        else:
            keyToSend = generateSymKey(32)

        key_encrypted = encrypt_assymetric(MANAGER_PUBLIC_KEY, keyToSend.hex())
        firstMessage.setSymKey(key_encrypted.hex())

        firstMessage.sign_message_CC(int(slot))

        firstMessageResponseData = self.sendMessageManager(firstMessage.strToByteArray())

        if firstMessage.id == packetIds['CHECK_ENGLISH_AUCTION_OUTCOME_CM']:
            firstMessageResponse = Check_English_Auction_Outcome_CM_Response()
            # Unpack Response
            try:
                firstMessageResponse.unpack(firstMessageResponseData)
            except:
                print('Malformed response from server')
                return

            if not firstMessageResponse.verify_signature(MANAGER_PUBLIC_KEY):
                print('Oops, manager signature failed. Someone modified the packet')
                return

            # Check Status of Message
            if 'error' in firstMessageResponse.getStatus():
                print('Error checking outcome: ' + firstMessageResponse.getStatus()['error'])
                return

            winnerID = json.loads(decrypt_symmetric(keyToSend, bytes.fromhex(firstMessageResponse.getWinnerID()), firstMessage.algorithm, firstMessage.mode).decode('utf-8'))
            winnerValue = json.loads(decrypt_symmetric(keyToSend, bytes.fromhex(firstMessageResponse.getWinnerValue()), firstMessage.algorithm, firstMessage.mode).decode('utf-8'))
            print(winnerID)
            print(winnerValue)
            return

        firstMessageResponse = Check_Blind_Auction_Outcome_CM_Response()
        try:
            firstMessageResponse.unpack(firstMessageResponseData)
        except:
            print('Malformed response from server')
            return

        if not firstMessageResponse.verify_signature(MANAGER_PUBLIC_KEY):
            print('Oops, manager signature failed. Someone modified the packet')
            return

        # Check Status of Message
        if 'error' in firstMessageResponse.getStatus():
            print('Error checking outcome: ' + firstMessageResponse.getStatus()['error'])
            return

        statusAuction = json.loads(decrypt_symmetric(keyToSend, bytes.fromhex(firstMessageResponse.getStatusAuction()), firstMessage.algorithm, firstMessage.mode).decode('utf-8'))



        # Deal with Status
        if 'closed' in statusAuction:
            claiming = not statusAuction['closed']
        else:
            print('Bad auction status by manager. Aborting check outcome')
            return

        info(claiming)

        # Claming or not mode

        if claiming:
            print('Auction in claiming mode')
            messageToSend = Check_Blind_Auction_Outcome_Unclaimed_CM_Request()
            messageToSend.setAuctionId(firstMessage.getAuctionId())
            keyBlindBid = None
            for entry in self.keys:
                if messageToSend.getAuctionId() == entry['auc_id']:
                    keyBlindBid = entry['key']
                    break
            if not keyBlindBid:
                print('Key to claim has been lost')
                #keyBlindBid = generateSymKey()
                return

            key_encrypted = encrypt_assymetric(MANAGER_PUBLIC_KEY, keyBlindBid.hex())
            messageToSend.setKeyBlindBid(key_encrypted.hex())
            messageToSend.sign_message_CC(int(slot))

            res = self.sendMessageManager(messageToSend.strToByteArray())

            response = Check_Blind_Auction_Outcome_Unclaimed_CM_Response()

            # Unpack Response
            try:
                response.unpack(res)
            except:
                print('Malformed response from server')
                return

            if not response.verify_signature(MANAGER_PUBLIC_KEY):
                print('Oops, manager signature failed. Someone modified the packet')
                return

            print(response.getStatus())


        else:
            print('Auction has ended')
            messageToSend = Check_Blind_Auction_Outcome_Claimed_CM_Request()
            messageToSend.setAuctionId(firstMessage.getAuctionId())
            messageToSend.setAlgorithm(firstMessage.getAlgorithm())
            messageToSend.setMode(firstMessage.getMode())
            # Encrypt symmetric key with repository public key
            if messageToSend.getAlgorithm() == 'tripledes' or messageToSend.getAlgorithm() == 'cast5' or messageToSend.getAlgorithm() == 'seed':
                keyToSend = generateSymKey(16)
            else:
                keyToSend = generateSymKey(32)

            key_encrypted = encrypt_assymetric(MANAGER_PUBLIC_KEY, keyToSend.hex())
            messageToSend.setSymKey(key_encrypted.hex())
            messageToSend.sign_message_CC(int(slot))

            res = self.sendMessageManager(messageToSend.strToByteArray())

            response = Check_Blind_Auction_Outcome_Claimed_CM_Response()

            # Unpack Response
            try:
                response.unpack(res)
            except:
                print('Malformed response from server')
                return

            if not response.verify_signature(MANAGER_PUBLIC_KEY):
                print('Oops, manager signature failed. Someone modified the packet')
                return

            winnerID = json.loads(
                decrypt_symmetric(keyToSend, bytes.fromhex(response.getWinnerID()), messageToSend.algorithm,
                                  messageToSend.mode).decode('utf-8'))
            winnerValue = json.loads(decrypt_symmetric(keyToSend, bytes.fromhex(response.getWinnerValue()),
                                                       messageToSend.algorithm, messageToSend.mode).decode('utf-8'))
            print(winnerID)
            print(winnerValue)

        return

    def checkOutcome_args(self):
        # Get Type
        english = True
        typeV = input('Is the auction english? Y/n')
        if typeV == 'n' or typeV == 'N':
            english = False
        if english:
            messageToSend = Check_English_Auction_Outcome_CM_Request()
        else:
            messageToSend = Check_Blind_Auction_Outcome_CM_Request()

        # Get Algorithm type and hash
        # Get algorithm
        print('Enter the algorithm to encrypt response: ')
        algorithm = input()
        if algorithm:
            algorithm = algorithm.replace(' ', '').lower()
            if algorithm not in sym_algorithms:
                print('Invalid Algorithm')
                return
        else:
            algorithm = 'aes'
            print('Defaulting to AES')
        messageToSend.setAlgorithm(algorithm)

        # Get mode
        print('Enter the algorithm to encrypt response: ')
        mode = input()
        if mode:
            mode = mode.replace(' ', '').lower()
            if mode not in sym_algorithms:
                print('Invalid Algorithm')
                return
        else:
            mode = 'cbc'
            print('Defaulting to CBC')
        messageToSend.setMode(mode)

        # Get Auction Type
        print('Enter the auction ID: ')
        auc_id = input()
        try:
            a = int(auc_id)
        except:
            print('Invalid auction id')
            return
        messageToSend.setAuctionId(auc_id)

        return messageToSend

    def validateReceipt(self):
        filename = input('Receipt File?')
        try:
            f = open(os.path.join('receipts',filename) , 'r')
        except:
            print('Can\'t open file')
            return

        data = json.loads(f.read())

        keyForReceipt = data['keySentForEncryption']
        algorithm = data['algorithm']
        mode = data['mode']

        # Decode first packet
        response1 = Bid_On_Auction_Bid_CR_Response()
        # Unpack Response
        try:
            response1.unpack(data, decode=False)
        except:
            print('Malformed data')
            return

        if not response1.verify_signature(REPOSITORY_PUBLIC_KEY):
            print('Oops, repository signature failed. Someone modified this')
            return

        print('Repository top signature verified')

        receipt = json.loads(decrypt_symmetric(bytes.fromhex(keyForReceipt), bytes.fromhex(response1.getReceipt()), algorithm, mode).decode('utf-8'))

        response2 = Bid_On_Auction_Validation_MR_Response()
        try:
            response2.unpack(receipt, decode=False)
        except:
            print('Malformed data')
            return

        if not response2.verify_signature(MANAGER_PUBLIC_KEY):
            print('Oops, Manager signature failed. Someone modified this')
            return

        print('Manager second signature verified')

        #info('Block inside blockchain')
        #print(response2.getBid())

        response3 = Bid_On_Auction_Validation_MR_Request()
        try:
            response3.unpack(response2.getPacket(), decode=False)
        except:
            print('Malformed data')
            return

        if not response3.verify_signature(REPOSITORY_PUBLIC_KEY):
            print('Oops, repository signature failed. Someone modified this')
            return

        print('Repository third signature verified')

        response4 = Bid_On_Auction_Bid_CR_Request()
        try:
            response4.unpack(response3.getPacket(), decode=False)
        except:
            print('Malformed data')
            return

        print('Verifiyng own signature')

        slot = self.getCard()
        if not slot:
            return

        cert = ccTools.extractCert('CITIZEN AUTHENTICATION CERTIFICATE', int(slot))

        if not response4.verify_signature(cert.public_key()):
            print('Own signature is wrong')
            return

        print('Own Signature is Correct')

        print('BID for auction ' + response4.getAuctionId() + ' with value ' + response4.getBid())


        return

    def verifyAuction(self):
        # Ask repository for blockchain
        messageToRep = Get_Blockchain_CR_Request()

        # Get Auction Type
        print('Enter the auction ID: ')
        auc_id = input()
        try:
            a = int(auc_id)
        except:
            print('Invalid auction id')
            return
        messageToRep.setAuctionId(auc_id)

        # Send to repository
        res = self.sendMessageRepository(messageToRep.strToByteArray())

        messageFromRep = Get_Blockchain_CR_Response()

        # Unpack Response
        try:
            messageFromRep.unpack(res)
        except:
            print('Malformed message from Repository')
            return

        # Verify message signature
        if not messageFromRep.verify_signature(REPOSITORY_PUBLIC_KEY):
            print('Oops, repository signature failed. Someone modified the packet')
            return

        # Check Status of Message
        if 'error' in messageFromRep.getStatus():
            print('Error listing auctions: ' + messageFromRep.getStatus()['error'])
            return

        # Verify blockchain
        print('Received blockchain of auction from repository')
        blockchain = Blockchain.load_dict_blockchain(messageFromRep.getBlockchain())

        if not blockchain.verify_integrity():
            print("Blockchain is not correct BIG OOPS")
            print("Contact the police")

        print('Blockchain is indeed correct')

        # Ask Manager for keys
        messageToManager = Get_Keys_Auction_CM_Request()
        messageToManager.setAuctionId(messageToRep.getAuctionId())
        slot = self.getCard()
        if not slot:
            return
        messageToManager.sign_message_CC(int(slot))

        # Send to manager
        res = self.sendMessageManager(messageToManager.strToByteArray())

        messageFromManager = Get_Keys_Auction_CM_Response()

        # Unpack Response
        try:
            messageFromManager.unpack(res)
        except:
            print('Malformed message from Manager')
            return

        # Verify message signature
        if not messageFromManager.verify_signature(MANAGER_PUBLIC_KEY):
            print('Oops, manager signature failed. Someone modified the packet')
            return

        # Check Status of Message
        if 'error' in messageFromManager.getStatus():
            print('Error listing auctions: ' + messageFromManager.getStatus()['error'])
            return

        # Decrypt all auction information
        auction = Auction.unwrapAuction(blockchain)
        auction.isClosed()

        # Get Keys
        if auction.getAuctionType() != auction_type['BLIND']:
            identityKey = bytes.fromhex(messageFromManager.getIdentityKeys())
        if auction.getAuctionType() != auction_type['ENGLISH']:
            blindKeys = pickle.loads(bytes.fromhex(messageFromManager.getBlindKeys()))

        # Print it
        print('Auction Info')
        print(auction.getAuction())

        print('Bids Decrypted')
        for bid in auction.getBids():
            # Get identity and decode
            identity = bid.getIdentity()
            if auction.getAuctionType() == auction_type['BLIND']:
                identity = bytes.fromhex(identity)
            else:
                identity = decrypt_symmetric(identityKey, bytes.fromhex(identity))
            certInBid = certTools.load_certificate(identity)
            # Search for entry saved in manager for the key to decrypt value by comparing cert
            if auction.getAuctionType() != auction_type['ENGLISH']:
                entryBlind = ''
                for entry in blindKeys:
                    certTemp = certTools.load_certificate(entry['identity'])
                    if certTemp.fingerprint(hashes.SHA256()) == certInBid.fingerprint(hashes.SHA256()):
                        entryBlind = entry
                        valueData = decrypt_symmetric(entryBlind['keyBlindBid'], bytes.fromhex(bid.getValue())).decode('utf-8')
                        try:
                            value = int(valueData)
                            if value == entryBlind['value']:
                                print('BID made by ' + certTools.getNameInCert(certInBid) + ' with value ' + str(value))
                        except:
                            pass
            else:
                print('BID made by ' + certTools.getNameInCert(certInBid) + ' with value ' + bid.getValue())

        return

    def sendMessageRepository(self, data):
        # Create a UDP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        server_address = (REPOSITORY_CONNECTION_ADDRESS, REPOSITORY_CONNECTION_PORT)

        try:
            # Send data
            info('Sending to repository')
            sent = sock.sendto(data, server_address)

            # Receive response
            info('Waiting for response')
            data, server = sock.recvfrom(PACKET_SIZE)

        finally:
            sock.close()
            return data

    def sendMessageManager(self, data):
        # Create a UDP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        server_address = (MANAGER_CONNECTION_ADDRESS, MANAGER_CONNECTION_PORT)

        try:
            # Send data
            info('Sending to manager')
            sent = sock.sendto(data, server_address)

            # Receive response
            info('Waiting for response')
            data, server = sock.recvfrom(PACKET_SIZE)

        finally:
            sock.close()
            return data

    def getBidFromReceipt(self, data, cert):
        data = json.loads(data)

        keyForReceipt = data['keySentForEncryption']
        algorithm = data['algorithm']
        mode = data['mode']

        # Decode first packet
        response1 = Bid_On_Auction_Bid_CR_Response()
        # Unpack Response
        try:
            response1.unpack(data, decode=False)
        except:
            #print('Malformed data')
            return

        receipt = json.loads(
            decrypt_symmetric(bytes.fromhex(keyForReceipt), bytes.fromhex(response1.getReceipt()), algorithm,
                              mode).decode('utf-8'))

        response2 = Bid_On_Auction_Validation_MR_Response()
        try:
            response2.unpack(receipt, decode=False)
        except:
            #print('Malformed data')
            return

        response3 = Bid_On_Auction_Validation_MR_Request()
        try:
            response3.unpack(response2.getPacket(), decode=False)
        except:
            #print('Malformed data')
            return

        response4 = Bid_On_Auction_Bid_CR_Request()
        try:
            response4.unpack(response3.getPacket(), decode=False)
        except:
            #print('Malformed data')
            return


        if not response4.verify_signature(cert.public_key()):
            return

        value = response4.getBid()
        for entry in self.keys:
            if response4.getAuctionId() == entry['auc_id']:
                key = entry['key']
                value = decrypt_symmetric(key, bytes.fromhex(value)).decode('utf-8')

        return {'auction': response4.getAuctionId(), 'value': value}

    def getCard(self):
        # Select Card
        cards = ccTools.getCards()
        while not cards:
            a = input('Insert Card (Enter to try again or enter 0 to exit)')
            if a is '0':
                return None
            cards = ccTools.getCards()
        print('Choose card: ')
        for card in cards:
            print('{} - {} - {}'.format(card['slot'], card['name'], card['BI']))
        slot = input()
        try:
            a = int(slot)
            assert a >= 0 and a < len(cards)
        except:
            print('Invalid slot')
            return None
        return slot

