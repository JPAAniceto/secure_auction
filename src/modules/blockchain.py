import datetime
import hashlib
import json


class Blockchain:
    def __init__(self, initialValue='', createFirst=True):
        self.blocks = []
        # Create initial block and append to list
        if createFirst:
            self.blocks.append(self.create_initial_block(initialValue))

    def __eq__(self, other):
        if self.blocks == other.blocks:
            return True
        return False

    def add_block(self, data):
        last_block = self.get_last_block()
        if not last_block.data:
            return False
        last_hash = self.hash_blockchain(self.blocks)
        b = Block(data, last_hash)
        self.blocks.append(b)
        return True

    def _add_block(self, block):
        self.blocks.append(block)

    def get_last_block(self):
        return self.blocks[-1]

    def get_blockchain(self):
        return self.blocks

    def close_blockchain(self):
        self.add_block('')
        return True

    def is_closed(self):
        return not self.get_last_block().data 

    def get_block(self, index):
        try:
            return self.blocks[index]
        except:
            return None

    def create_initial_block(self, data):
        return Block(data, '0')

    def verify_integrity(self):
        for i in range(0, len(self.blocks)-1):
            if not self.hash_blockchain(self.blocks[:i+1]) == self.blocks[i+1].hash:
                return False
        return True

    def to_file(self, file):
        dict = {}
        for index, block in enumerate(self.blocks):
            dict[str(index)] = block.__dict__()
        try:
            json.dump(dict, file, default=str)
        except:
            return None

    def to_dict(self):
        dict = {}
        for index, block in enumerate(self.blocks):
            dict[str(index)] = block.__dict__()
        return dict

    def __str__(self):
        dict = {}
        for index, block in enumerate(self.blocks):
            dict[str(index)] = block.__dict__()
        try:
            return str(dict)
        except:
            return None

    @staticmethod
    def hash_blockchain(blocks):
        to_hash = ''
        for block in blocks:
            to_hash = to_hash + str(block)
        last_hash = hashlib.sha256(to_hash.encode('utf-8')).hexdigest()
        return last_hash

    @staticmethod
    def load_dict_blockchain(dict):
        bc = Blockchain(createFirst=False)
        for key in sorted(list(dict.keys())):
            dictBlk = dict[key]
            block = Block(dictBlk['data'], dictBlk['hash'], timeStamp=dictBlk['timestamp'])
            bc._add_block(block)
        return bc


    @staticmethod
    def load_blockchain(file):
        bc = Blockchain(createFirst=False)
        try:
            data = json.load(file)
            for key in sorted(list(data.keys())):
                dataBlk = data[key]
                block = Block(dataBlk['data'], dataBlk['hash'], timeStamp=dataBlk['timestamp'])
                bc._add_block(block)
            return bc
        except:
            return None


class Block:
    def __init__(self, data, hash, timeStamp=None):
        if timeStamp:
            self.timestamp = timeStamp
        else:
            self.timestamp = str(datetime.datetime.now())
        self.data = data
        self.hash = hash

    def __str__(self):
        return str(self.__dict__())

    def __repr__(self):
        return str(self.__dict__())

    def __dict__(self):
        return {'timestamp': self.timestamp, 'data': self.data, 'hash': self.hash}

    def __eq__(self, other):
        if self.timestamp != other.timestamp:
            return False

        if self.data != other.data:
            return False

        if self.hash != other.hash:
            return False

        return True

if __name__ == '__main__':
    # Create blockchain
    b = Blockchain('Block Initial')
    b.add_block('Block 1')
    b.add_block('Block 2')
    b.close_blockchain()

    # Test blockchain
    print("Blockchain 1")
    print('Integrity: ' + str(b.verify_integrity()))

    # Write Blockchain
    file = open('test.bc', 'w+')
    b.to_file(file)
    file.close

    # Test Blockchain read
    file = open('test.bc', 'r')
    bc = Blockchain.load_blockchain(file)
    file.close
    print()
    print("Blockchain 2")
    print('Integrity: ' + str(bc.verify_integrity()))

    print("\nAre the blockchains equal: " + str(b == bc))




