import config


class LCG:
    """
        This LCG class is made for the project requirement of transmitting ASCII 
        characters of length 1 byte 
    """

    def __init__(self, seed, HMAC_key,  a=16843009, c=826366247, m=2**32):
        self.HMAC_key = HMAC_key
        self.state = seed
        self.a = config.a or a
        self.c = config.c or c
        self.m = config.m or m

    def next_byte(self):
        """
            next state is based on previous state 

        """
        self.state = (self.a * self.state + self.c) % self.m
        return self.state & 0xFF  # 1 byte

    def keystream(self, length):
        return bytes([self.next_byte() for _ in range(length)])
