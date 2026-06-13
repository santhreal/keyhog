#!/usr/bin/env python3
"""Generate the English bigram log-probability model used by the generic-bridge
randomness discriminator (KH-L-0413): distinguishes RANDOM credential values
(`gjbubxsu`, a real password) from DICTIONARY identifiers (`getUserName`, a code
reference) so the keyword bridge can recover the former without surfacing the
latter. Emits a flat little-endian f32[26*26] table = mean-bigram-logprob inputs.

Source: a standard English wordlist (default /usr/share/dict/words). The OUTPUT
.bin is committed as the source of truth so the model is reproducible and
host-independent; re-run only to refresh. Laplace-smoothed over the 26x26 space."""
import math, collections, struct, sys, pathlib
WORDS = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "/usr/share/dict/words")
OUT = pathlib.Path(__file__).resolve().parents[1] / "crates/scanner/data/english_bigram_logprob.bin"
counts = collections.Counter(); tot = 0
for w in WORDS.read_text(encoding="latin-1").splitlines():
    w = w.strip().lower()
    if not w.isalpha() or len(w) < 3:
        continue
    for i in range(len(w) - 1):
        a, b = w[i], w[i + 1]
        if "a" <= a <= "z" and "a" <= b <= "z":
            counts[(ord(a) - 97, ord(b) - 97)] += 1; tot += 1
V = 26 * 26
table = []
for a in range(26):
    for b in range(26):
        table.append(math.log((counts.get((a, b), 0) + 1) / (tot + V)))
OUT.write_bytes(b"".join(struct.pack("<f", v) for v in table))
print(f"wrote {OUT} ({OUT.stat().st_size} bytes) from {tot} bigrams over {WORDS}")
print(f"logprob range [{min(table):.3f}, {max(table):.3f}]")
