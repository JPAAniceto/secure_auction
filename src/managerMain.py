import socket
import sys


from serverSide.manager import *
from utils import *
from const import *


def main():
    manager = Manager()
    recvSocket = manager.openConnection(MANAGER_CONNECTION_PORT)
    manager.receiveMessage(recvSocket)
    recvSocket.close()


if __name__ == '__main__':
    main()