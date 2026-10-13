"""Streamlit entry point for the SentinelSOC dashboard.

Run from the project root with::

    streamlit run app.py

This thin launcher makes the project root importable and then hands off to the
dashboard defined in ``sentinelsoc/app.py``.
"""

import sys
from pathlib import Path

# Make the project root importable so ``sentinelsoc.*`` resolves no matter the
# working directory Streamlit was started from.
ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from sentinelsoc.app import main  # noqa: E402

main()
