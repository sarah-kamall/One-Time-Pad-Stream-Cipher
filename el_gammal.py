import sympy
import random
from common import power
from common import mod_inverse

import config
"""
This is implementation of ElGammal encryption scheme.
It is a public key encryption scheme based on the Diffie-Hellman problem.
It is used for secure key exchange and digital signatures.

I will be choosing q = 2^31 -1 and alpha = 7 as a primitive root of q.
"""


class ElGammal:
    def __init__(self, q=2 ** 31 - 1, alpha=7):
        """
        Initialize the ElGammal encryption scheme with the given parameters.
        q is a prime number and alpha is a primitive root of q.
        """
        if not self.valid_paramters(q, alpha):
            raise ValueError(f"Invalid parameters: q={q}, alpha={alpha}")

        self.q = config.q or q

        self.alpha = config.alpha or alpha
        self._private_key = None
        self.public_key = None
        # this is a dictionary of name: public_key
        self.parties = {}

    def valid_paramters(self, q, alpha):
        """
        Check if q is prime and alpha is a primitive root of q.
        """
        if not sympy.isprime(q):
            raise ValueError(f"{q} is not prime")
        if not sympy.is_primitive_root(alpha, q):
            raise ValueError(f"{alpha} is not a primitive root of {q}")
        return True

    def generate_keys(self):
        """
        Generate public and private keys.
        Private key is a random number between 1 and q-1.
        """

        self._private_key = random.randint(1, self.q - 1)
        self.public_key = power(self.alpha, self._private_key, self.q)

    def encrypt(self, message, recipient):
        """
        Encrypt the message using the public key.
        The message should be a number between 1 and q-1.
        """
        if message >= self.q:
            raise ValueError(
                f"Message {message} is not in the range [1, {self.q-1}]")
        if recipient not in self.parties:
            raise ValueError(f"Recipient {recipient} not found")
        public_key = self.parties[recipient]
        k = random.randint(1, self.q - 1)
        K = power(public_key, k, self.q)
        c1 = power(self.alpha, k, self.q)
        c2 = power(K*message, 1, self.q)
        return c1, c2

    def decrypt(self, c1, c2):
        """
        Decrypt the message using the private key.
        c1 and c2 are the ciphertext.
        """
        K = power(c1, self._private_key, self.q)
        K_inv = mod_inverse(K, self.q)
        message = (c2 * K_inv) % self.q
        return message

    def add_party(self, name, public_key):
        """
        Add a party to the list of parties.
        The party should be a tuple of (name, public_key).
        """
        if name in self.parties:
            raise ValueError(f"Party {name} already exists")
        self.parties[name] = public_key
    if __name__ == "__main__":
        check = valid_paramters(2**31 - 1, 7)
