import time
from rsa import *
from Crypto.Util import number
import intervals as I

# Global variable counting the number of queries to the decryption oracle
global n_queries
n_queries = 0
start_time = time.process_time()


def ceil(a, b):
    return a // b + (a % b > 0)


def floor(a, b):
    return a // b


def oracle(ciphertext, rsa_cipher):
    # The oracle decrypts the ciphertext and check if it conforms the PKCS#1 format
    k = rsa_cipher.modulus_length // 8
    msg_padded = rsa.decrypt(ciphertext)

    if len(msg_padded) < k:
        zero_pad = b"\x00" * (k - len(msg_padded))
        msg_padded = zero_pad + msg_padded

    return msg_padded[0:2] == b"\x00\x02"


def find_smallest_s(lower, upper, c, rsa_cipher):
    # Find the smallest s >= lower_bound s.t. c * s^e mod n conforms to PKCS format
    s = lower
    [n, e] = rsa_cipher.public_keys
    global n_queries

    while s <= upper:
        c_i = (c * pow(s, e, n)) % n
        c_i = number.long_to_bytes(c_i)

        n_queries += 1
        t = time.process_time()
        if n_queries % 1000 == 0:
            print("Query #{} times to oracle in {} seconds".format(n_queries, round(t - start_time, 3)))

        if oracle(c_i, rsa_cipher):
            return s

        s += 1

    return 0


def bleichenbacher(ciphertext, rsa_cipher):
    print("Bleichenbacher Attack on RSA PKCS v1.5\n")

    n, e = rsa_cipher.public_keys

    # Compute constant variable B and initial interval M = [2B, 3B - 1]
    k = rsa_cipher.modulus_length // 8
    B = pow(2, (8 * (k - 2)))
    M_i_1 = I.closed(2 * B, 3 * B - 1)

    # Step 1: calculate c and s
    print("Step 1!")
    c = number.bytes_to_long(ciphertext)
    s = 1

    # Step 2a: Calculate s_i, the smallest int >= n/3B that conforms
    print("Step 2a!")
    s = find_smallest_s(ceil(n, 3 * B), n - 1, c, rsa_cipher)

    # Repeat until two bound of M is equal
    while M_i_1.lower != M_i_1.upper: #True:
        # Step 2b: If M_i-1 has multiple disjoint intervals, calculate smallest s_i > s_(i-1) that conforms
        print("Step 2b!")
        if len(M_i_1) > 1:
            # Find smallest s_i > s_(i-1) such that plaintext corresponding to c(s_i^e) mod n conforms
            s = find_smallest_s(s + 1, n - 1, c, rsa_cipher)

        # Step 2c. Number of intervals = 1 -> find s_i
        elif len(M_i_1) == 1:
            # Given the interval [a, b], reduce the search only to relevant regions
            # and stop when a value s that is a PKCS1 conforming string is found
            # by varying integer r_i and s_i until find s_i such that plaintext corresponding to c(s_i^e) mod n conforms
            print("\nStep 2c!")
            (a, b) = (M_i_1.lower, M_i_1.upper) # M[0]

            # Step 4
            # print("Step 4!")
            if a == b:
                return number.long_to_bytes(a % n)

            r_i = ceil(2 * (b * s - 2 * B), n)
            s = 0

            while s == 0:
                lower = ceil(2 * B + r_i * n, b)
                upper = ceil(3 * B + r_i * n, a)
                s = find_smallest_s(lower, upper, c, rsa_cipher)
                r_i += 1

        # Step 3. After s_i found, reduce set M_(i-1) to M_i
        M_i = I.empty()
        # For each disjoint interval [a,b] in M_(i-1)
        for interval in M_i_1:
            a, b = interval.lower, interval.upper
            low_r = ceil(a * s - 3 * B + 1, n)
            high_r = ceil(b * s - 2 * B, n)
            for r in range(low_r, high_r):
                i_low = max(a, ceil(2 * B + r * n, s))
                i_high = min(b, floor(3 * B - 1 + r * n, s))
                M_new = I.closed(i_low, i_high)
                M_i = M_i | M_new

        # Reset variables for next round
        M_i_1 = M_i

    # Step 4. M_i.lower = M_i.higher = m, the message in integer form
    print("Step 4!")
    elapsed_time = time.process_time() - start_time
    print("Successful attack in {} seconds!".format(round(elapsed_time, 3)))
    return number.long_to_bytes(M_i_1.lower % n)


if __name__ == '__main__':

    modulus_length = 1024  # a toy modulus length
    e = 0x10001  # public key 2^16 + 1

    rsa = RsaCipher(e, modulus_length)

    msg: bytes = b"Demo of Bleichenbacher attack!"

    cipher = rsa.encrypt(msg)
    decrypted = bleichenbacher(cipher, rsa)
    decrypted = PKCS1_unpad(decrypted)

    assert decrypted == msg

    print("Number of queries: {}".format(n_queries))
    print("Decrypted message recovered: {}".format(decrypted))

