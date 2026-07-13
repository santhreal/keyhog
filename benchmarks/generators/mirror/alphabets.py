"""Canonical character alphabets for the mirror generator.

ONE home for every alphabet so providers.py and negatives.py can never
disagree. Note: ``string.hexdigits`` is ``0-9a-fA-F0-9``, its lower/upper
folds double every hex letter (a-f twice), skewing sampled hex toward a-f.
HEX here is the correct uniform 16-symbol set.
"""

from __future__ import annotations

import string

B62 = string.ascii_letters + string.digits
B64 = B62 + "+/"
B64URL = B62 + "-_"
HEX = "0123456789abcdef"
