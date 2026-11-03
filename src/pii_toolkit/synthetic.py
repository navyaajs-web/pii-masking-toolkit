"""Synthetic customer records for demos and tests.

Everything here is invented. Emails use the reserved example.com/example.org domains, phone
numbers sit in the UK range set aside for fiction, and card numbers use a test-style prefix
with a valid Luhn check digit so the detector has something realistic to find.
"""

from __future__ import annotations

import random
from datetime import date, timedelta

FIRST = [
    "Asha",
    "Ben",
    "Chloe",
    "Dev",
    "Elif",
    "Farah",
    "Gus",
    "Hana",
    "Ivan",
    "Jade",
    "Kofi",
    "Lena",
    "Mateo",
    "Nia",
    "Omar",
    "Priya",
    "Quinn",
    "Rosa",
    "Sami",
    "Tara",
]
LAST = [
    "Okafor",
    "Lindqvist",
    "Moreau",
    "Tanaka",
    "Reyes",
    "Novak",
    "Haddad",
    "Kowalski",
    "Brennan",
    "Iyer",
    "Duarte",
    "Fischer",
    "Mensah",
    "Petrov",
    "Sato",
    "Walsh",
]
CITIES = ["Northbridge", "Easthaven", "Millbrook", "Westmere", "Southport", "Kingsford"]
SEGMENTS = ["retail", "premier", "student", "small_business"]


def luhn_check_digit(partial: str) -> str:
    total = 0
    for i, ch in enumerate(reversed(partial)):
        n = int(ch)
        if i % 2 == 0:
            n = n * 2 - 9 if n > 4 else n * 2
        total += n
    return str((10 - total % 10) % 10)


def _card(rng: random.Random) -> str:
    partial = "400000" + "".join(str(rng.randint(0, 9)) for _ in range(9))
    return partial + luhn_check_digit(partial)


def generate_customers(n: int = 200, seed: int = 7) -> list[dict]:
    rng = random.Random(seed)
    rows = []
    for i in range(1, n + 1):
        first, last = rng.choice(FIRST), rng.choice(LAST)
        dob = date(1950, 1, 1) + timedelta(days=rng.randint(0, 365 * 55))
        rows.append(
            {
                "customer_id": f"C{i:06d}",
                "first_name": first,
                "last_name": last,
                "email": f"{first}.{last}{i}@example.com".lower(),
                "phone": f"+44 7700 9{rng.randint(0, 99999):05d}",
                "ssn": f"9{rng.randint(10, 99)}-{rng.randint(10, 99)}-{rng.randint(1000, 9999)}",
                "date_of_birth": dob.isoformat(),
                "card_number": _card(rng),
                "city": rng.choice(CITIES),
                "segment": rng.choice(SEGMENTS),
                # Not in the example policy on purpose: the detector should flag it.
                "contact_alt": f"{last}.{i}@example.org".lower(),
                "notes": rng.choice(["", "prefers email", "called branch", "address change"]),
            }
        )
    return rows
