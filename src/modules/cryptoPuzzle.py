"""
CryptoPuzzle based on HashCash
"""

import hashlib, itertools


def solveChallenge(keyword, nZeros=5):
    keywordHash = hashlib.sha1(keyword.encode('utf-8')).digest()
    for token in generateRandomString():
        tempHash = hash(str(keywordHash) + token)
        #print('Tentativa com token {} e hash {} com {} zeros'.format(token, tempHash, countZeros(tempHash)))
        if countZeros(tempHash) >= nZeros:
            return token


def checkChallenge(keyword, token, nZeros=5):
    keywordHash = hashlib.sha1(keyword.encode('utf-8')).digest()
    finalHash = hash(str(keywordHash) + token)
    if countZeros(finalHash) >= nZeros:
        return True
    else:
        return False


def hash(s):
    return int(hashlib.sha1(s.encode('utf-8')).hexdigest(), 16)


def countZeros(n):
    if n == 0:
        return 0
    binN = bin(n)[2:]
    while len(binN) < 160:
        binN = '0' + binN
    for i in range(0, len(binN)):
        if binN[i] is not '0':
            return i-2


def generateRandomString():
    charset="0123456789ABCDEF"
    m = len(charset)
    for n in itertools.count(0):
        for i in range(m ** n):
            yield ''.join([charset[(i // (m ** j)) % m] for j in range(n)])

