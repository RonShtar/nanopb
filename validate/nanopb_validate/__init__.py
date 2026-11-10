"""nanopb_validate: validation, packet filters and Wireshark tools for nanopb.

The modules import each other by plain name (they also run as scripts and as
protoc plugins), so importing the package puts its folder on sys.path.
"""

import os as _os
import sys as _sys

_here = _os.path.dirname(_os.path.abspath(__file__))
if _here not in _sys.path:
    _sys.path.insert(0, _here)
