import sys
from datetime import datetime

sys.path.append('..')

from src.utils import *
from src.const import *
from src.auctionType.bid import *
from src.auctionType.auction import *
from tests.bid_test import *

def auction(auctionId, name, description, timeLimit, claimTime="None", typeAuction=auction_type["ENGLISH"]):
    key  = generateSymKey(32)

    bid1 = Bid("joao", "1", bid_type['ENGLISH'])
    bid2 = Bid("joao", "2", bid_type['ENGLISH'])
    bid3 = Bid("davide", "3", bid_type['ENGLISH'])
    bid4 = Bid("davide", "4", bid_type['ENGLISH'])
    bid5 = Bid("davide", "5", bid_type['ENGLISH'])
    bid6 = Bid("rodrigo", "7", bid_type['ENGLISH'])
    bid7 = Bid("rodrigo", "7", bid_type['ENGLISH'])
    bid8 = Bid("davide", "8", bid_type['BLIND'])
    bid9 = Bid("davide", "9", bid_type['FULL_BLIND'])


    debug("***************** Start Auction Test *****************")

    try:
        sys.stdout = open(os.devnull, "w")
        bid_test(bid1.getIdentity(), bid1.getValue(), key, bid1.getBidType(), bid1.getEncryptionAlgorithm(), bid1.getEncryptionMode())
        sys.stdout = sys.__stdout__
    except Exception:
        error("Bid 1 error")
        raise ValueError

    try:
        sys.stdout = open(os.devnull, "w")
        bid_test(bid2.getIdentity(), bid2.getValue(), key, bid2.getBidType(), bid2.getEncryptionAlgorithm(), bid2.getEncryptionMode())
        sys.stdout = sys.__stdout__
    except Exception:
        error("Bid 2 error")
        raise ValueError

    try:
        sys.stdout = open(os.devnull, "w")
        bid_test(bid3.getIdentity(), bid3.getValue(), key, bid3.getBidType(), bid3.getEncryptionAlgorithm(), bid3.getEncryptionMode())
        sys.stdout = sys.__stdout__
    except Exception:
        error("Bid 3 error")
        raise ValueError

    try:
        sys.stdout = open(os.devnull, "w")
        bid_test(bid4.getIdentity(), bid4.getValue(), key, bid4.getBidType(), bid4.getEncryptionAlgorithm(), bid4.getEncryptionMode())
        sys.stdout = sys.__stdout__
    except Exception:
        error("Bid 4 error")
        raise ValueError

    try:
        sys.stdout = open(os.devnull, "w")
        bid_test(bid5.getIdentity(), bid5.getValue(), key, bid5.getBidType(), bid5.getEncryptionAlgorithm(), bid5.getEncryptionMode())
        sys.stdout = sys.__stdout__
    except Exception:
        error("Bid 5 error")
        raise ValueError

    try:
        sys.stdout = open(os.devnull, "w")
        bid_test(bid6.getIdentity(), bid6.getValue(), key, bid6.getBidType(), bid6.getEncryptionAlgorithm(), bid6.getEncryptionMode())
        sys.stdout = sys.__stdout__
    except Exception:
        error("Bid 6 error")
        raise ValueError

    try:
        sys.stdout = open(os.devnull, "w")
        bid_test(bid7.getIdentity(), bid7.getValue(), key, bid7.getBidType(), bid7.getEncryptionAlgorithm(), bid7.getEncryptionMode())
        sys.stdout = sys.__stdout__
    except Exception:
        error("Bid 7 error")
        raise ValueError

    try:
        sys.stdout = open(os.devnull, "w")
        bid_test(bid8.getIdentity(), bid8.getValue(), key, bid8.getBidType(), bid8.getEncryptionAlgorithm(), bid8.getEncryptionMode())
        sys.stdout = sys.__stdout__
    except Exception:
        error("Bid 8 error")
        raise ValueError

    try:
        sys.stdout = open(os.devnull, "w")
        bid_test(bid9.getIdentity(), bid9.getValue(), key, bid9.getBidType(), bid9.getEncryptionAlgorithm(), bid9.getEncryptionMode())
        sys.stdout = sys.__stdout__
    except Exception:
        error("Bid 9 error")
        raise ValueError

    info("All bids are valid")

    auction = Auction(auctionId, name, description, timeLimit, claimTime, typeAuction)

    info(auction)
    info("Blockchain :\n")
    for block in auction.getAuctionBlockChain().get_blockchain():
        print(block)
   
    info(auction.getState())
    auction.addBid(bid1)
    info("Blockchain after adding bid 1 :")
    for block in auction.getAuctionBlockChain().get_blockchain():
        print(block)

    print("\n\n")
    info(auction.getState())
    auction.addBid(bid2)
    info("Blockchain after adding bid 2 :")
    for block in auction.getAuctionBlockChain().get_blockchain():
        print(block)

    print("\n\n")
    info(auction.getState())
    auction.addBid(bid3)
    info("Blockchain after adding bid 3 :")
    for block in auction.getAuctionBlockChain().get_blockchain():
        print(block)

    print("\n\n")
    info(auction.getState())
    auction.addBid(bid4)
    info("Blockchain after adding bid 4 :")
    for block in auction.getAuctionBlockChain().get_blockchain():
        print(block)

    print("\n\n")
    info(auction.getState())
    auction.addBid(bid5)
    info("Blockchain after adding bid 5 :")
    for block in auction.getAuctionBlockChain().get_blockchain():
        print(block)

    print("\n\n")
    info(auction.getState())
    auction.addBid(bid6)
    info("Blockchain after adding bid 6 :")
    for block in auction.getAuctionBlockChain().get_blockchain():
        print(block)

    print("\n\n")
    info(auction.getState())
    auction.addBid(bid7)
    info("Blockchain after adding bid 7 :")
    for block in auction.getAuctionBlockChain().get_blockchain():
        print(block)

    print("\n\n")
    info(auction.getState())
    auction.addBid(bid8)
    info("Blockchain after adding bid 8 :")
    for block in auction.getAuctionBlockChain().get_blockchain():
        print(block)

    print("\n\n")
    info(auction.getState())
    auction.addBid(bid9)
    info("Blockchain after adding bid 9 :")
    for block in auction.getAuctionBlockChain().get_blockchain():
        print(block)

    print("\n\n")
    info(auction.getState())
    auction.setState(auction_state['CLOSED'])
    info("Auction after close: \n{}".format(str(auction)))
    info("Blockchain closed after auction close : {}".format( auction.getAuctionBlockChain().is_closed()))
    info("Blockchain after auction close:")
    for block in auction.getAuctionBlockChain().get_blockchain():
        print(block)

    print("\n\n")
    auction.addBid(bid1)
    info("Blockchain after adding bid 1 again :")
    for block in auction.getAuctionBlockChain().get_blockchain():
        print(block)

    newAuction = Auction.unwrapAuction(auction.getAuctionBlockChain())

    info("Blockchain after unwrap :")
    for block in newAuction.getAuctionBlockChain().get_blockchain():
        print(block)

    info("Are they equal after unwrap: {}".format(str(auction)==str(newAuction)))
    info("Are their blockchain equal after unwrap: {}".format(str(auction.getAuctionBlockChain())==str(newAuction.getAuctionBlockChain())))

    debug("***************** End Auction Test *****************")

    return True


if __name__ == '__main__':
    auction('1', 'carro', 'carro 1000€', '1000')
    # auction('1', 'carro', 'carro 1000€', '1000','5000')
    # auction('1', 'carro', 'carro 1000€', '1000',typeAuction=auction_type['BLIND'])