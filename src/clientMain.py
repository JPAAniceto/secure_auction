import socket
import sys
import time


from clientSide.client import *
from utils import *
from const import *

def main():
    client = Client("joao", 1)
    exit = False
    while not exit:
        inputKey = 99
        while inputKey < 0 or inputKey > 9:
            client.printMenu()
            inputKey = input()
            try:
                inputKey = int(inputKey)
            except:
                inputKey = 99
        if inputKey is 0:
            exit = True
        else:
            client.runOption(inputKey)

if __name__ == '__main__':
    main()