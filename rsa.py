from Crypto.Util import number
from Crypto import Random
import Crypto
import math
import random


# Padding in PKCS1 (in total_bytes): 0x00 02 | non-zero padding | 00 HASH(msg)
def PKCS1_pad(msg, total_bytes):
    # 3 constant bytes + at least 8 bytes of padding -> 11
    if len(msg) > total_bytes - 11:
        raise Exception("Message is too big!")

    pad_len = total_bytes - 3 - len(msg)
    # non-zeros padding bytes
    padding = bytes(random.sample(range(1, 256), pad_len))

    return b"\x00\x02" + padding + b"\x00" + msg


def PKCS1_unpad(padded_msg):
    i = padded_msg.find(b"\x00", 2)

    return padded_msg[i + 1:]


class RsaCipher:
    def __init__(self, e, modulus_length):
        self.modulus_length = modulus_length
        self.e = e
        [N, d] = self.generate_keys()
        self.private_keys = [N, d]
        self.public_keys = [N, e]

    # Generate a key of RSA key
    def generate_keys(self):
        length = self.modulus_length // 2 + 128
        p = number.getPrime(length, randfunc=Crypto.Random.get_random_bytes)
        # e and p - 1 must be co-prime
        while math.gcd(self.e, p - 1) != 1:
            p = number.getPrime(length, randfunc=Crypto.Random.get_random_bytes)

        # p and q should not be too close to avoid Fermat factorization. | p - q | >= 2 n ^ 1 / 4.
        # FIPS 186-4 recommends | p - q | >= 2 ^ {n / 2 - 100}.
        k = self.modulus_length // 4 + 1
        q = number.getPrime(p.bit_length() - k, randfunc=Crypto.Random.get_random_bytes)
        # e and q - 1 must be co-prime
        while math.gcd(self.e, q - 1) != 1:
            q = number.getPrime(p.bit_length() - k, randfunc=Crypto.Random.get_random_bytes)

        N = p * q
        phi = (p - 1) * (q - 1)
        # Generate the private key d
        d = pow(self.e, -1, phi)
        private_keys = [N, d]

        return private_keys

    def encrypt(self, msg):
        # Encrypt using public key e
        # or verify the signature using the public key e
        k = self.modulus_length // 8
        msg_padded = PKCS1_pad(msg, k)

        m = number.bytes_to_long(msg_padded)

        [N, e] = self.public_keys

        if m > N:
            raise ValueError("Message is too big for this RSA!")

        return number.long_to_bytes(pow(m, e, N))

    def decrypt(self, cipher):
        # Decrypt using private key d
        # or generate the signature using the private key d
        c = number.bytes_to_long(cipher)
        [N, d] = self.private_keys

        return number.long_to_bytes(pow(c, d, N))

    def encrypt_int(self, m: int):
        [N, e] = self.public_keys
        if m > N:
            raise ValueError("Message is too big for this RSA!")

        return pow(m, e, N)

    def decrypt_int(self, c: int):
        [N, d] = self.private_keys
        return pow(c, d, N)


if __name__ == '__main__':
    # Testing
    e = 0x10001
    modulus_length = 1024
    M = b"Hello RSA!"
    rsa = RsaCipher(e, modulus_length)
    mpadded = PKCS1_pad(M, modulus_length // 8)

    # Test #1, padding scheme
    print("1. (un)pad:", PKCS1_unpad(mpadded) == M)

    # Test #2 , RSA without padding
    M1 = rsa.decrypt_int(rsa.encrypt_int(number.bytes_to_long(M)))
    print("2. RSA cipher without padding:", M == number.long_to_bytes(M1))

    # Test #3 , RSA with padding
    M2 = PKCS1_unpad(rsa.decrypt(rsa.encrypt(M)))
    print("3. RSA with PKCS#1 v1.5 padding:", M == M2)
