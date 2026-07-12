"""Small text statistics shared across the bench + generators.

ONE home for the Shannon-entropy formula so the mirror generator's manifest
metadata and the CredData miss-analysis bucketing can never disagree on how a
value's entropy is computed.
"""

from __future__ import annotations

import math
from collections import Counter


def shannon_entropy(s: str) -> float:
    """Shannon entropy (bits/char) of ``s``; 0.0 for the empty string."""
    if not s:
        return 0.0
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in Counter(s).values())
