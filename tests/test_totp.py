"""The TOTP implementation against the vectors published in the RFCs."""

import base64

import pytest

from mcprack import totp

# RFC 4226 / 6238 use the ASCII secret "12345678901234567890"
RFC_SECRET = base64.b32encode(b"12345678901234567890").decode().rstrip("=")


@pytest.mark.parametrize(
    "counter,expected",
    list(enumerate(["755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"])),
)
def test_hotp_rfc4226_appendix_d(counter, expected):
    assert totp.hotp(RFC_SECRET, counter) == expected


@pytest.mark.parametrize(
    "when,expected",
    [
        (59, "94287082"),
        (1111111109, "07081804"),
        (1111111111, "14050471"),
        (1234567890, "89005924"),
        (2000000000, "69279037"),
        (20000000000, "65353130"),
    ],
)
def test_totp_rfc6238_appendix_b_sha1(when, expected):
    """The RFC lists 8-digit codes; the same HMAC truncated to 8 digits."""
    assert totp.hotp(RFC_SECRET, totp.current_step(when), digits=8) == expected


def test_six_digit_codes_are_the_last_six_of_the_eight():
    assert totp.hotp(RFC_SECRET, totp.current_step(59)) == "287082"


def test_a_generated_secret_is_160_bits_of_base32_without_padding():
    secret = totp.generate_secret()

    assert len(secret) == 32 and "=" not in secret
    assert len(base64.b32decode(secret)) == 20
    assert totp.generate_secret() != secret


def test_match_accepts_the_current_step_and_one_either_side():
    now = 1_700_000_000
    step = totp.current_step(now)
    for offset in (-1, 0, 1):
        assert totp.match(RFC_SECRET, totp.hotp(RFC_SECRET, step + offset), now=now) == step + offset


def test_match_rejects_codes_further_away_and_wrong_codes():
    now = 1_700_000_000
    step = totp.current_step(now)

    assert totp.match(RFC_SECRET, totp.hotp(RFC_SECRET, step + 2), now=now) is None
    assert totp.match(RFC_SECRET, totp.hotp(RFC_SECRET, step - 2), now=now) is None
    assert totp.match(RFC_SECRET, "000000", now=now) in (None, step - 1, step, step + 1)  # only by coincidence
    assert totp.match(RFC_SECRET, "12345", now=now) is None  # too short


def test_a_used_step_cannot_be_used_again():
    now = 1_700_000_000
    step = totp.current_step(now)
    code = totp.hotp(RFC_SECRET, step)

    first = totp.match(RFC_SECRET, code, now=now)
    again = totp.match(RFC_SECRET, code, now=now, after_step=first)

    assert first == step and again is None


def test_an_older_code_than_the_last_accepted_one_is_refused():
    now = 1_700_000_000
    step = totp.current_step(now)

    assert totp.match(RFC_SECRET, totp.hotp(RFC_SECRET, step - 1), now=now, after_step=step) is None


@pytest.mark.parametrize("typed", ["123 456", " 123456 ", "123-456", "123456"])
def test_codes_are_normalised_the_way_apps_display_them(typed):
    assert totp.normalise_code(typed) == "123456"


@pytest.mark.parametrize("typed", ["", None, "12345", "1234567", "abcdef", "12 34 5a", "١٢٣٤٥٦", "123456\x00"])
def test_things_that_cannot_be_a_code_are_not_one(typed):
    assert totp.normalise_code(typed) is None
    assert totp.match(RFC_SECRET, typed, now=1_700_000_000) is None


def test_the_provisioning_uri_is_what_authenticator_apps_import():
    uri = totp.provisioning_uri("ABCDEFGH", "ann@example.com", "mcprack (prod)")

    assert uri.startswith("otpauth://totp/mcprack%20%28prod%29%3Aann%40example.com?")
    assert "secret=ABCDEFGH" in uri and "algorithm=SHA1" in uri and "digits=6" in uri and "period=30" in uri
    assert "issuer=mcprack%20%28prod%29" in uri


def test_a_secret_is_shown_in_groups():
    assert totp.group("ABCDEFGHIJKL") == "ABCD EFGH IJKL"


def test_recovery_codes_are_60_bits_without_ambiguous_characters():
    code = totp.generate_recovery_code()
    raw = code.replace("-", "")

    assert len(raw) == 12 and code.count("-") == 2
    assert not set(raw) & set("IO01")
    assert totp.normalise_recovery_code(code) == raw
    assert len({totp.generate_recovery_code() for _ in range(200)}) == 200


@pytest.mark.parametrize("typed", ["abcd-efgh-jklm", "ABCD EFGH JKLM", "abcdefghjklm"])
def test_recovery_codes_are_typed_in_any_case_and_spacing(typed):
    assert totp.normalise_recovery_code(typed) == "ABCDEFGHJKLM"


@pytest.mark.parametrize("typed", ["", None, "ABCD-EFGH", "ABCD-EFGH-JKLM-NPQR", "ABCD-EFGH-JKL0", "ABCD-EFGH-JKLI"])
def test_malformed_recovery_codes_are_rejected(typed):
    assert totp.normalise_recovery_code(typed) is None
