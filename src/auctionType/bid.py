import sys

sys.path.append('..')
from src.utils import *
from src.const import *
from src.modules.cyphers import *


class Bid:
    def __init__(self, identity=None, value=None, bidType=bid_type['ENGLISH'], encryptionAlg = 'aes', encryptionMode = 'cbc'):
        self.__type = bidType
        self.__encryption_algorithm = encryptionAlg
        self.__encryption_mode = encryptionMode
        self.__identity = identity
        self.__identity_state = DECRYPTED
        self.__value = value

    def setBidType(self, BidType):
        if BidType != None and int(BidType) in bid_type.values():
            self.__type = BidType
        else :
            error(EMPTY_STRING, True)
            raise ValueError

    def getBidType(self):
        if self.__type != None and int(self.__type) in bid_type.values():
            return self.__type
        else:
            error(EMPTY_STRING,True)
            raise ValueError

    def setEncryptionAlgorithm(self, EncryptionAlg):
        if EncryptionAlg != None and EncryptionAlg in sym_algorithms:
            self.__encryption_algorithm = EncryptionAlg
        else :
            error(EMPTY_STRING, True)
            raise ValueError

    def getEncryptionAlgorithm(self):
        if self.__encryption_algorithm != None and self.__encryption_algorithm in sym_algorithms:
            return self.__encryption_algorithm
        else :
            error(EMPTY_STRING, True)
            raise ValueError

    def setEncryptionMode(self, EncryptionMode):
        if EncryptionMode != None and EncryptionMode  in sym_modes:
            self.__encryption_mode = EncryptionMode
        else :
            error(EMPTY_STRING, True)
            raise ValueError

    def getEncryptionMode(self):
        if self.__encryption_algorithm != None and self.__encryption_mode in sym_modes:
            return self.__encryption_mode
        else :
            error(EMPTY_STRING, True)
            raise ValueError

    def setValue(self, Value):
        if Value != None:
            self.__value = Value
        else :
            error(EMPTY_STRING, True)
            raise ValueError
    
    def getValue(self):
        if self.__value != None:
            return self.__value
        else :
            error(EMPTY_STRING, True)
            raise ValueError

    def setIdentity(self, Identity):
        if Identity != None:
            self.__identity = Identity
        else :
            error(EMPTY_STRING, True)
            raise ValueError
    
    def getIdentity(self):
        if self.__identity != None: 
            return self.__identity
        else :
            error(EMPTY_STRING, True)
            raise ValueError

    def setIdentityState(self, identityState):
        if identityState == DECRYPTED or identityState == ENCRYPTED:
            self.__identity_state = identityState
        else:
            error('Wrong identity state!',True)
            raise ValueError

    def getIdentityState(self):
        if self.__identity_state == DECRYPTED or self.__identity_state == ENCRYPTED:
            return self.__identity_state
        else:
            error('Wrong identity state!',True)
            raise ValueError

    def encriptBid(self, key):
        # English bid, identity must be hidden
        if self.__type == bid_type['ENGLISH']:
            if self.__identity_state == DECRYPTED:
                # Encrypt function
                self.__identity = encrypt_symmetric(key, self.__identity, self.getEncryptionAlgorithm(), self.getEncryptionMode())
                self.__identity_state = ENCRYPTED

        # Blind bid
        elif self.__type == bid_type['BLIND']:
            pass

        # Full Blind bid identity must be hidden
        elif self.__type == bid_type['FULL_BLIND']:
            if self.__identity_state == DECRYPTED:
                # Encrypt function
                self.__identity = encrypt_symmetric(key, self.__identity, self.getEncryptionAlgorithm(), self.getEncryptionMode())
                self.__identity_state = ENCRYPTED
        
        else:
            error('Bid type not defined',True)
            raise ValueError

    def decriptBid(self, key):
        # English bid, identity must be hidden
        if self.__type == bid_type['ENGLISH']:
            if self.__identity_state == ENCRYPTED:
                # decrypt function
                self.__identity = decrypt_symmetric(key, self.__identity, self.getEncryptionAlgorithm(), self.getEncryptionMode())
                self.__identity_state = DECRYPTED

        # Blind bid, value must be hidden
        elif self.__type == bid_type['BLIND']:
            pass

        # Full Blind bid, value and identity must be hidden
        elif self.__type == bid_type['FULL_BLIND']:
            if self.__identity_state == ENCRYPTED:
                # decrypt function
                self.__identity = decrypt_symmetric(key, self.__identity, self.getEncryptionAlgorithm(), self.getEncryptionMode())
                self.__identity_state = DECRYPTED

        else:
            error('Bid type not defined',True)
            raise ValueError

    # wraps necessary fields of bid in a dictionary
    def wrapBid(self, key, encriptBoolean=False):
        if encriptBoolean:
            self.encriptBid(key)

        bid = { 'bid_type' : self.__type,
                'encryption_algorithm' : self.__encryption_algorithm,
                'encryption_mode' : self.__encryption_mode,
                'identity' : self.__identity,
                'value' : self.__value }

        return bid

    # unwraps bid from a dictionary to a class
    def unwrapBid(bid, isEncriptedBoolean=False):
        bidType = 0
        encryption_algorithm = ''
        encryption_mode = ''
        identity = ''
        value = ''

        try:
            bidType = bid['bid_type']
        except:
            error('Bid type not defined!',True)
            raise ValueError

        try:
            encryption_algorithm = bid['encryption_algorithm']
        except:
            error('Bid algorithm not defined!',True)
            raise ValueError

        try:
            encryption_mode = bid['encryption_mode']
        except:
            error('Bid algorithm not defined!',True)
            raise ValueError

        try:
            identity = bid['identity']
        except:
            error('Bid identity not defined',True)
            raise ValueError

        try:
            value = bid['value']
        except:
            error('Bid value not defined',True)
            raise ValueError

        newBid = Bid(identity , value,bidType,encryption_algorithm,encryption_mode)

        if isEncriptedBoolean:
            try:
                # English bid, identity must be hidden
                if bidType == bid_type['ENGLISH']:
                    newBid.setIdentityState(ENCRYPTED)

                # Blind bid, value must be hidden
                elif bidType == bid_type['BLIND']:
                    pass

                # Full Blind bid, value and identity must be hidden
                elif bidType == bid_type['FULL_BLIND']:
                    newBid.setIdentityState(ENCRYPTED)

            except Exception as e:
                error("Wrong bid type!\n" + e,True)
                raise ValueError

        return newBid

    def isValid(self):
        if (self.getIdentity() != None and self.getIdentityState() != None and
            self.getValue() != None and
            self.getEncryptionAlgorithm() != None and self.getEncryptionMode() != None and
            self.getBidType() != None ):
            return True
        else :
            return False

    def __str__(self):

        return  Fore.CYAN + "Bid type: " + Fore.RESET + "{}".format([k for k,v in bid_type.items() if v==self.__type][0]) + " \n" +\
                Fore.CYAN + "Encryption Algorithm: " + Fore.RESET + "{}".format(self.__encryption_algorithm) + " \n" +\
                Fore.CYAN + "Encryption Mode: " + Fore.RESET + "{}".format(self.__encryption_mode) + " \n" +\
                Fore.CYAN + "Identity: " + Fore.RESET + "{}".format(self.__identity) + " \n" +\
                Fore.CYAN + "Identity State: " + Fore.RESET + "{}".format(("Encrypted" if self.__identity_state == ENCRYPTED else "Decrypted") ) + " \n" +\
                Fore.CYAN + "Value: " + Fore.RESET + "{}".format(self.__value) + " \n"