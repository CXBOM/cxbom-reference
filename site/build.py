"""Command-line entry for the cxbom.org build. Owner: ATACE Working Group.

Run from the repository root: `python site/build.py [--out DIR] [--lock]`.
The code lives in site/cxsite/. See site/cxsite/build.py for the options.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from cxsite.build import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
