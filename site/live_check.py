"""Command-line entry for the post-deploy live check. Owner: ATACE Working Group.

Run from the repository root: `python site/live_check.py <base-url> [--dist DIR]`.
The code lives in site/cxsite/live_check.py.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from cxsite.live_check import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
