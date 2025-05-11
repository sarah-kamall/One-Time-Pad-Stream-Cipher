import el_gammal
import socket
import config

SENDER_PORT = config.SERVER_PORT
RECEIEVER_PORT = config.RECEIVER_PORT


class Party:

    def __init__(self, host, port):
        self.encryption_algorithm = el_gammal.ElGammal()
        self.encryption_algorithm.generate_keys()
        self.lcg = None
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.seed = None
