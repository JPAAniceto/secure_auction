import sys, os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

sys.path.append('..')

# UDP Connection constants
MANAGER_CONNECTION_ADDRESS = 'localhost'
REPOSITORY_CONNECTION_ADDRESS = 'localhost'
REPOSITORY_CONNECTION_PORT = 10000
MANAGER_CONNECTION_PORT = 10001
PACKET_SIZE = 1000000

# Global Constants
EMPTY_STRING = ""
UNDEFINED_INTEGER = sys.maxsize

ENCRYPTED = 0
DECRYPTED = 1

# CM : client <-> manager
# CR : client <-> repository
# MR : manager <-> repository
packetIds = {
    'CREATE_AUCTION_CM'                         :  1,
    'CREATE_AUCTION_MR'                         :  2,
    'TERMINATE_AUCTION_CM'                      :  3,
    'TERMINATE_AUCTION_MR'                      :  4,
    'LIST_AUCTIONS_CR'                          :  5,
    'LIST_BIDS_CR'                              :  6,
    'LIST_BIDS_OF_CLIENT_CM'                    :  7,
    'LIST_BIDS_OF_CLIENT_MR'                    :  8,
    'BID_ON_AUCTION_CRYPTO_CR'                  :  9,
    'BID_ON_AUCTION_BID_CR'                     : 10,
    'BID_ON_AUCTION_VALIDATION_MR'              : 11,
    'CHECK_ENGLISH_AUCTION_OUTCOME_CM'          : 12,
    'CHECK_BLIND_AUCTION_OUTCOME_CM'            : 13,
    'CHECK_BLIND_AUCTION_OUTCOME_UNCLAIMED_CM'  : 14,
    'CHECK_BLIND_AUCTION_OUTCOME_CLAIMED_CM'    : 15,
    'GET_BLOCKCHAIN_MR'                         : 16,
    'GET_BLOCKCHAIN_CR'                         : 17,
    'GET_KEYS_AUCTION_CM'                       : 18,
}

bid_type = {
    'ENGLISH'   : 0,
    'BLIND'     : 1,
    'FULL_BLIND': 2,
}

auction_type = {
    'ENGLISH'   : 0,
    'BLIND'     : 1,
    'FULL_BLIND': 2,
}

auction_state = {
    'OPEN'      : 0,
    'CLOSED'    : 1,
    'CLAIMING'  : 2,
}

auction_all_states = {
    'OPEN'      : 0,
    'CLOSED'    : 1,
    'ALL'       : 2,
}

# Servers public keys

with open(os.path.join('keys', 'publicManager.key'), "rb") as key_file:
    MANAGER_PUBLIC_KEY = serialization.load_pem_public_key(
        key_file.read(),
        backend=default_backend()
    )

with open(os.path.join('keys', 'publicRepository.key'), "rb") as key_file:
    REPOSITORY_PUBLIC_KEY = serialization.load_pem_public_key(
        key_file.read(),
        backend=default_backend()
    )