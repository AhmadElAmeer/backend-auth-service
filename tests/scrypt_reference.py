"""scrypt (RFC 7914) in plain Python, written from the RFC, as an independent
oracle for the OpenSSL implementation behind hashlib.scrypt.

Far too slow for real use; fine for the small parameters in the tests.
"""

import hashlib
import struct


def _rotl(x: int, n: int) -> int:
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def salsa20_8(block: bytes) -> bytes:
    """RFC 7914 §3: the Salsa20/8 core on a 64-byte block."""
    b = list(struct.unpack("<16I", block))
    x = b[:]
    for _ in range(4):  # 8 rounds = 4 double rounds
        for a, c, d, s in ((4, 0, 12, 7), (8, 4, 0, 9), (12, 8, 4, 13), (0, 12, 8, 18),
                           (9, 5, 1, 7), (13, 9, 5, 9), (1, 13, 9, 13), (5, 1, 13, 18),
                           (14, 10, 6, 7), (2, 14, 10, 9), (6, 2, 14, 13), (10, 6, 2, 18),
                           (3, 15, 11, 7), (7, 3, 15, 9), (11, 7, 3, 13), (15, 11, 7, 18)):
            x[a] ^= _rotl((x[c] + x[d]) & 0xFFFFFFFF, s)
        for a, c, d, s in ((1, 0, 3, 7), (2, 1, 0, 9), (3, 2, 1, 13), (0, 3, 2, 18),
                           (6, 5, 4, 7), (7, 6, 5, 9), (4, 7, 6, 13), (5, 4, 7, 18),
                           (11, 10, 9, 7), (8, 11, 10, 9), (9, 8, 11, 13), (10, 9, 8, 18),
                           (12, 15, 14, 7), (13, 12, 15, 9), (14, 13, 12, 13), (15, 14, 13, 18)):
            x[a] ^= _rotl((x[c] + x[d]) & 0xFFFFFFFF, s)
    return struct.pack("<16I", *((x[i] + b[i]) & 0xFFFFFFFF for i in range(16)))


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(i ^ j for i, j in zip(a, b))


def block_mix(B: bytes, r: int) -> bytes:
    """RFC 7914 §4: scryptBlockMix."""
    X = B[(2 * r - 1) * 64:]
    Y = []
    for i in range(2 * r):
        X = salsa20_8(_xor(X, B[i * 64:(i + 1) * 64]))
        Y.append(X)
    return b"".join(Y[0::2] + Y[1::2])  # even blocks first, then odd


def ro_mix(B: bytes, N: int, r: int) -> bytes:
    """RFC 7914 §5: scryptROMix, the memory-hard part."""
    X = B
    V = []
    for _ in range(N):
        V.append(X)
        X = block_mix(X, r)
    for _ in range(N):
        j = int.from_bytes(X[(2 * r - 1) * 64:(2 * r - 1) * 64 + 8], "little") % N  # Integerify
        X = block_mix(_xor(X, V[j]), r)
    return X


def scrypt(password: bytes, salt: bytes, N: int, r: int, p: int, dklen: int) -> bytes:
    """RFC 7914 §6."""
    B = hashlib.pbkdf2_hmac("sha256", password, salt, 1, p * 128 * r)
    B = b"".join(ro_mix(B[i * 128 * r:(i + 1) * 128 * r], N, r) for i in range(p))
    return hashlib.pbkdf2_hmac("sha256", password, B, 1, dklen)
