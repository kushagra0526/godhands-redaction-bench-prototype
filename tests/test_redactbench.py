import numpy as np

from redactbench import detect, gen


def ev(text, **kw):
    return {"kind": "text", "text": text, **kw}


def test_generated_checksums_are_valid():
    rng = np.random.default_rng(1)
    assert gen.luhn_ok(gen.luhn_complete("4", 16, rng))
    assert detect.mod97_ok(gen.iban_complete(rng))
    assert gen.verhoeff_ok(gen.verhoeff_complete("234567890123"[:11]))


def test_card_needs_luhn_so_tracking_numbers_survive():
    card = gen.luhn_complete("4", 16, np.random.default_rng(2))
    assert card not in detect.layered(ev(f"card {card}"))
    track = "1234567890123456"                                    # fails Luhn
    assert track in detect.layered(ev(f"tracking {track}"))
    assert track not in detect.naive(ev(f"tracking {track}"))     # the plain pattern removes it


def test_password_field_is_removed_whole_even_without_a_pattern():
    assert detect.layered({"kind": "typed", "field": "password", "text": "hunter22!"}) == detect.MARK
    assert detect.naive({"kind": "typed", "field": "password", "text": "hunter22!"}) == "hunter22!"


def test_business_numbers_survive():
    t = "Refund approved for ticket 4830, amount $120.00, order 556677"
    assert detect.layered(ev(t)) == t


def test_scorer_counts_a_leak_on_the_same_planted_secret():
    ses = gen.make_session(3)
    clean = "\n".join(detect.layered(e) for e in ses["events"])
    raw = "\n".join(e["text"] for e in ses["events"])
    assert any(v in raw for _, v in ses["secrets"])
    assert not any(v in clean for _, v in ses["secrets"] if len(v) > 8)
