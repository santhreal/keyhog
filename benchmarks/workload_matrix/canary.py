"""The planted credential every workload regime carries.

One canary, one detector, one shape. Every regime in the matrix hides this
exact byte string somewhere in its input. If a regime scans clean, the canary
tells you which of the two clean results you got:

  findings >= 1   the regime reached the bytes and the scan is real
  findings == 0   the regime never reached the bytes, so "clean" is a lie

Do not swap this for a different provider without re-checking two things:
the detector must fire at confidence 1.0 with no verification, and it must
not be on the bundled test-fixture suppression list (otherwise the default
scan drops it and every regime looks silently broken).
"""

import base64

# stripe-secret-key, severity critical, confidence 1.0, verification skipped.
CANARY = "sk_live_51H8xQ2eZvKYlo2CkVvNbHqRt9pXwZmA3dLfGyUcTiOnEsRaBvQwXyZ12"  # keyhog:ignore detector=stripe-secret-key -- deliberate workload-matrix canary; the harness needs it found in the generated corpora, not in this source literal

# The detector that must own the finding. Used to tell the canary apart from
# whatever else a regime's filler bytes happen to trip.
CANARY_DETECTOR = "stripe-secret-key"

# Assignment shape, so the keyword-adjacency path has something to anchor on
# and the canary looks like a real leak rather than a loose token.

# How the canary appears once keyhog redacts it, in report output and in the
# `--dogfood` suppression trace: first four bytes, ellipsis, last four.
CANARY_REDACTED = f"{CANARY[:4]}...{CANARY[-4:]}"
CANARY_LINE = f"STRIPE_SECRET_KEY={CANARY}"


def canary_bytes() -> bytes:
    return (CANARY_LINE + "\n").encode()


def canary_base64_bytes() -> bytes:
    """The canary behind one layer of Base64, in an assignment.

    Recovering this needs decode-through, so it exercises a path a plain literal
    never reaches. That matters because the decode-through size cap is applied
    per CHUNK, not per file, and a chunk larger than the cap is scanned raw with
    nothing encoded inside it recovered. A literal canary is found regardless and
    tells you nothing about that.
    """
    encoded = base64.b64encode(CANARY_LINE.encode()).decode()
    return f"payload={encoded}\n".encode()
