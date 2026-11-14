# QuantumShield on ShorList v0.3.0

[ShorList](https://github.com/shorlist/shorlist) is an open, versioned catalogue of the forms in which
public-key cryptography appears in code and configuration, with decoys and a primary source on each row.

## Read this first

- **Unofficial.** These numbers come from `score.py` in this folder, a small re-implementation of the
  line-exact rules described in ShorList's README ("Scoring"). They were not produced by ShorList's own
  generator and are not published by the ShorList maintainers.
- **Not a blind test.** The v0.4 rules were written after reading these rows. The v0.4 figure is a
  score on the material the rules were tuned on. Expect lower numbers on code you write.
- Defect rows (CWE axis) are not scored: QuantumShield reports no CWE.

Catalogue: ShorList 0.3.0, commit `65377e2c9ba6362316aa586a1506d7f18088dd8a`.

## Results

| | v0.3 (before) | v0.4 |
|---|---|---|
| Quantum axis, positive rows hit (line-exact, right family) | 529 / 1465 (36.1%) | 1194 / 1465 (81.5%) |
| Quantum axis, decoys flagged by mistake | 66 / 174 | 41 / 174 |
| Weak axis, positive rows hit | 21 / 244 (8.6%) | 179 / 244 (73.4%) |
| Weak axis, decoys flagged by mistake | 2 / 29 | 7 / 29 |
| PEM rows SL-3637 to SL-3647 (generic labels) | 0 / 10 hit, decoy flagged | 10 / 10 hit, decoy ok |

## What changed

- New rules for TLS cipher suites, signature schemes, groups, key types, OIDs and curve names (QS012-QS017, QS101).
- PEM blocks with generic labels (`PRIVATE KEY`, `PUBLIC KEY`, `CERTIFICATE`) are decoded and the algorithm
  OID inside is reported (QS018). Certificates report their signature algorithm.
- Lines that mention an algorithm without using it are not reported: comments, removal or rejection
  messages, disabled entries (`"X": False`) and removals in algorithm lists (`-X25519MLKEM768`, `!kRSA`).
  Committed private keys are always reported.

## Known gaps

Largest remaining misses: RSA forms named only through library objects, EC curves with uncommon names,
and stateful hash-based signature names. Decoys still flagged are mostly mentions without a negation word.

## Reproduce

```sh
git clone https://github.com/shorlist/shorlist.git
pip install pyyaml
python -I bench/shorlist/score.py shorlist . results.json
```
