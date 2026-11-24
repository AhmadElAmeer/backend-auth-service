from urllib.parse import parse_qs, urlparse

import pytest

from authsvc import totp

KEY = b"12345678901234567890"


def test_hotp_rfc4226_appendix_d():
    expected = ["755224", "287082", "359152", "969429", "338314",
                "254676", "287922", "162583", "399871", "520489"]
    assert [totp.hotp(KEY, c) for c in range(10)] == expected


# RFC 6238 Appendix B: (time, SHA1, SHA256, SHA512), 8 digits. The RFC uses a
# key of the hash's length: the ASCII digits repeated.
RFC6238 = [
    (59, "94287082", "46119246", "90693936"),
    (1111111109, "07081804", "68084774", "25091201"),
    (1111111111, "14050471", "67062674", "99943326"),
    (1234567890, "89005924", "91819424", "93441116"),
    (2000000000, "69279037", "90698825", "38618901"),
    (20000000000, "65353130", "77737706", "47863826"),
]


@pytest.mark.parametrize("t, sha1, sha256, sha512", RFC6238)
def test_totp_rfc6238_appendix_b(t, sha1, sha256, sha512):
    assert totp.totp(KEY, t, digits=8) == sha1
    assert totp.totp(b"12345678901234567890123456789012", t, digits=8, algorithm="sha256") == sha256
    assert totp.totp(b"1234567890" * 6 + b"1234", t, digits=8, algorithm="sha512") == sha512


def test_base32_round_trip_and_tolerant_input():
    key = totp.new_secret()
    assert len(key) == 20
    text = totp.to_base32(key)
    assert "=" not in text and len(text) == 32
    assert totp.from_base32(text) == key
    spaced = " ".join(text[i:i + 4] for i in range(0, 32, 4)).lower()
    assert totp.from_base32(spaced) == key


def test_provisioning_uri():
    uri = totp.provisioning_uri(KEY, "ahmad@example.com", "authsvc")
    u = urlparse(uri)
    assert (u.scheme, u.netloc, u.path) == ("otpauth", "totp", "/authsvc:ahmad@example.com")
    q = parse_qs(u.query)
    assert q["secret"] == [totp.to_base32(KEY)]
    assert q["issuer"] == ["authsvc"] and q["digits"] == ["6"] and q["period"] == ["30"]


def test_match_step_window():
    t = 1_700_000_000
    now = t // 30
    for offset, expected in [(-2, None), (-1, now - 1), (0, now), (1, now + 1), (2, None)]:
        code = totp.hotp(KEY, now + offset)
        assert totp.match_step(KEY, code, t) == expected, offset
    assert totp.match_step(KEY, totp.hotp(KEY, now), t, window=0) == now
    assert totp.match_step(KEY, totp.hotp(KEY, now - 1), t, window=0) is None


@pytest.mark.parametrize("code", ["", "12345", "1234567", "abcdef", "12 34 5x", "１２３４５６"])
def test_malformed_codes_never_match(code):
    assert totp.match_step(KEY, code, 1_700_000_000) is None


def test_spaces_in_codes_are_ignored():
    t = 1_700_000_000
    code = totp.totp(KEY, t)
    assert totp.match_step(KEY, f"{code[:3]} {code[3:]}", t) == t // 30
