import sys

sys.path.append('..')

from src.utils import *
from src.const import *
from src.auctionType.bid import *


def bid_test(identity, value, key, bidType=bid_type['ENGLISH'], encryptionAlg = 'aes', encryptionMode = 'cbc'):
    bid = Bid(identity, value, bidType, encryptionAlg, encryptionMode)
    bidTested = Bid(identity, value, bidType, encryptionAlg, encryptionMode)
    
    debug("***************** Start Bid Test *****************")
    print(bid)

    info("Is valid: {}".format(bid.isValid()))
    
    info("Key : {}".format(key))
    
    bid.encriptBid(key)
    info("Encrypted : ")
    print(bid)
    
    bid.decriptBid(key)
    info("Decrypted : ")
    print(bid)

    wrappedBid = bid.wrapBid(key,True)
    info("Bid wrapped : ")
    print(wrappedBid)

    info("Bid unWrapped is valid: {}".format(bid.isValid()))
    unwrappedBid = Bid.unwrapBid(wrappedBid,True)
    info("Bid unWrapped : ")
    print(unwrappedBid)
    
    info("Bid is same after unWrap : {}".format(str(unwrappedBid)==str(bid)))

    debug("***************** End Bid Test *****************")
    print("\n\n")

    return bidTested


if __name__ == '__main__':
    key = generateSymKey(32)
    bid_test("joao", "5", key)
    key = generateSymKey(16)
    bid_test("pedro", "5", key, bidType=bid_type['BLIND'], encryptionAlg = 'seed')
    bid_test("davide", "56666", key, bidType=bid_type['FULL_BLIND'], encryptionAlg = 'seed')

