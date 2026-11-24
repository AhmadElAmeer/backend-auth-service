import hashlib
import random

import pytest

from authsvc import passwords
from authsvc.passwords import ScryptParams, check_policy, hash_password, needs_rehash, verify_password
from conftest import FAST
from scrypt_reference import scrypt as reference_scrypt

# RFC 7914 §12 test vectors (password, salt, N, r, p, derived key).
RFC7914 = [
    (b"", b"", 16, 1, 1,
     "77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442"
     "fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906"),
    (b"password", b"NaCl", 1024, 8, 16,
     "fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b373162"
     "2eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640"),
    (b"pleaseletmein", b"SodiumChloride", 16384, 8, 1,
     "7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2"
     "d5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887"),
]


@pytest.mark.parametrize("pw, salt, n, r, p, expected", RFC7914)
def test_hashlib_scrypt_matches_rfc7914(pw, salt, n, r, p, expected):
    assert hashlib.scrypt(pw, salt=salt, n=n, r=r, p=p, dklen=64, maxmem=64 * 1024 * 1024).hex() == expected


def test_reference_scrypt_matches_rfc7914_vector_1():
    # The pure-Python oracle is independent of OpenSSL; vector 1 is small enough for it.
    assert reference_scrypt(b"", b"", 16, 1, 1, 64).hex() == RFC7914[0][5]


def test_reference_and_openssl_agree_on_random_inputs():
    rng = random.Random(15)
    for _ in range(25):
        pw = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 40)))
        salt = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 24)))
        n, r, p, dk = 2 ** rng.randrange(1, 6), rng.randrange(1, 4), rng.randrange(1, 3), rng.randrange(1, 80)
        assert reference_scrypt(pw, salt, n, r, p, dk) == hashlib.scrypt(pw, salt=salt, n=n, r=r, p=p, dklen=dk)


def test_our_hash_is_scrypt_of_the_normalised_password():
    encoded = hash_password("Café crème brûlée", FAST)
    ln, r, p, salt, digest = passwords.parse(encoded)
    assert (ln, r, p, len(salt), len(digest)) == (10, 8, 1, 16, 32)
    assert digest == reference_scrypt("Café crème brûlée".encode(), salt, 2 ** 10, 8, 1, 32)


def test_format_verify_and_salt():
    a = hash_password("correct horse", FAST)
    b = hash_password("correct horse", FAST)
    assert a.startswith("$scrypt$ln=10,r=8,p=1$")
    assert a != b, "each hash has its own random salt"
    assert verify_password("correct horse", a) and verify_password("correct horse", b)
    assert not verify_password("correct horsf", a)
    assert not verify_password("", a)
    assert not verify_password("Correct horse", a)


def test_composed_and_decomposed_accents_are_the_same_password():
    composed = "café au lait 99"
    decomposed = "café au lait 99"
    assert composed != decomposed
    assert verify_password(decomposed, hash_password(composed, FAST))


@pytest.mark.parametrize("bad", ["", "$scrypt$ln=10,r=8$abc$def", "$2b$12$abcdefghijklmnopqrstuv",
                                 "$scrypt$ln=99,r=8,p=1$AAAA$AAAA", "$scrypt$ln=10,r=8,p=1$!!$AAAA"])
def test_malformed_hashes_are_rejected(bad):
    with pytest.raises(ValueError):
        verify_password("x", bad)


def test_needs_rehash_when_the_parameters_go_up():
    old = hash_password("pw", ScryptParams(ln=10))
    assert needs_rehash(old, ScryptParams(ln=11))
    assert needs_rehash(old, ScryptParams(ln=10, r=9))
    assert not needs_rehash(old, ScryptParams(ln=10))
    assert not needs_rehash(hash_password("pw", ScryptParams(ln=12)), ScryptParams(ln=10))


def test_default_parameters_follow_owasp():
    d = passwords.DEFAULT
    assert (d.ln, d.r, d.p) == (17, 8, 1)
    assert d.memory == 128 * 1024 * 1024


# ---- policy (NIST SP 800-63B)

@pytest.mark.parametrize("pw", [
    "plum tractor violet 1987",          # passphrase with spaces
    "ñandú-pingüino-cóndor",            # any Unicode is allowed
    "x7#Qm2!vLp9$",                     # short but random, 12 characters
    "🐧🐧 penguins march at dawn 🐧🐧",
])
def test_good_passwords_pass(pw):
    assert check_policy(pw, username="ahmad", email="ahmad@example.com") == []


@pytest.mark.parametrize("pw, problem", [
    ("short1!", "at least 12"),
    ("kiwi-bonsai", "at least 12"),             # 11 characters: one short
    ("a" * 129, "at most 128"),
    ("password1234", "commonly used"),
    ("Password-2024!", "commonly used"),        # punctuation and trailing digits don't help
    ("QWERTYUIOP!!!", "commonly used"),
    ("ababababababab", "repetitive"),
    ("ahmad-the-great-2026", "username"),
    ("AhmadElAmeer-rocks-1", "username"),        # e-mail local part
    ("my authsvc password!", "service name"),
    ("tab\tin the middle", "control characters"),
])
def test_bad_passwords_are_rejected_with_a_reason(pw, problem):
    problems = check_policy(pw, username="ahmad", email="ahmadelameer@example.com", service="authsvc")
    assert any(problem in p for p in problems), problems


def test_no_composition_rules():
    # All lower-case letters and spaces is fine if it's long and not common.
    assert check_policy("the river bends twice near the old mill") == []
