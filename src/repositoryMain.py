import socket
import sys

from serverSide.repository import *
from utils import *
from const import *

def main():
    repo = Repository()
    recvSocket = repo.openConnection(REPOSITORY_CONNECTION_PORT)
    repo.receiveMessage(recvSocket)
    recvSocket.close()


if __name__ == '__main__':
    main()
