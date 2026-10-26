# redactbench: how many secrets survive on-laptop redaction?

GodHands says that "passwords, keys, tokens, card, bank and ID numbers are removed on the laptop, before anything is sent" (https://godhands.ai). That claim is checkable. This prototype generates synthetic work sessions with planted secrets, whose true values are known, and look-alikes that a playbook needs to keep (tracking numbers, git SHAs, UUIDs, invoice numbers, amounts), then scores any redactor on leaks and on wrongly removed look-alikes. It is not GodHands' system and sees none of their data.

## The setup
`redactbench/gen.py`: sessions of 5-8 business events (tickets, refunds, invoices) plus 1-3 planted secrets and 1-3 look-alikes. Dev types: card (Luhn-valid, spaced/dashed/plain), US SSN, IBAN (mod 97), AWS key, GitHub token, JWT, password typed in a password field, database URL with password, bearer token, "password: ..." text, PEM private key. Held-out types: Slack token, Stripe key, Aadhaar (Verhoeff), card and IBAN cut by a line break, a password given in a sentence, a one-time code typed in an OTP field, a private key inside a JSON file.
`redactbench/detect.py`, three redactors: plain patterns; entropy only (long high-entropy tokens); layered (fixed token formats, Luhn / mod-97 / Verhoeff / SSN-rule checks, password-field context). A secret counts as leaked if its first or last 8 letters and digits survive in the output; a look-alike counts as wrongly removed if its value does not survive.

## Results (held-out: 300 sessions, 575 planted secrets, 570 look-alikes; fixed in git before the first run)
| | dev leaked | dev look-alikes wrongly removed | held-out leaked | held-out look-alikes wrongly removed |
|---|---|---|---|---|
| plain patterns | 10.2% (38/372) | 29% (120/408) | 51.7% (297/575) | 28% (157/570) |
| entropy only | 48.7% (181/372) | 34% (138/408) | 54.8% (315/575) | 41% (234/570) |
| layered, **first held-out run** | 0% (0/372) | 0.2% (1/408) | **45.4% (261/575)** | 0.4% (2/570) |
| layered, after adding the held-out formats | 0% | 0.2% | 0.7% (4/575) | 0.4% (2/570) |

- Plain patterns remove many look-alikes (any 16-digit number looks like a card) and cannot see a password typed in a password field. Entropy alone removes SHAs and UUIDs and misses short secrets (card, SSN, passwords).
- The layered detector was perfect on the formats I built it for, and on the held-out run it leaked 45% because 7 of the 15 types were formats it had never been given (Slack, Stripe, Aadhaar, OTP field, prose password, wrapped card and IBAN). I then added rules for those and reran on the same held-out set, so the 0.7% is near-circular: it only shows the rules work on the formats I wrote. The 4 remaining leaks are IBANs wrapped across lines where an uneven group broke the join.
- What carries over: checksums keep the look-alikes (Luhn rejects tracking numbers, mod 97 rejects cost-centre codes) and field context catches what no pattern can. What does not: any format without a rule leaks, and I did not build an entropy-near-keyword fallback.
- Side effect: joining a number cut by a line break turns the break into a space in the output.

## Read this before believing the table
All data is generated; real screens carry OCR errors, tables, and secrets in images. Look-alike types are the ones I thought of. No claim about GodHands' actual detectors; I have not seen them.

## Run it (3 commands)
```
pip install numpy pytest
python -m pytest -q tests
python -m redactbench.run
```
numpy only. 5 tests; the run takes a few seconds.

Unofficial prototype by Kushagra Pratap Singh. Not affiliated with GodHands.
