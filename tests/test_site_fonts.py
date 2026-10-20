"""Self-hosted fonts keep their exact bytes and their license travels with them.

Owner: ATACE Working Group.

The woff2 files come unmodified from the npm packages @fontsource/source-serif-4
5.3.0 (integrity sha512-yQz8xmIgMzks8zQbpuca3UYtjxK798XCyQAGdDXmzBgvV7sdoK6d0YvE9F9kiYxORCEMRBgGZDZsSYcXj5KvwA==)
and @fontsource/source-code-pro 5.3.0 (integrity
sha512-JxaCODU69HDS3mVra9u96nyBF911La6IvtGLgpQD+PZLxJ1i9IxooNfLR6Y37kx06IFjVGkvoUmg3WPwh/8gBg==).
Both are SIL OFL 1.1. OFL.txt carries the copyright lines read from each font's
name table, followed by the license text shipped in the packages.
"""
import hashlib
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FONTS = ROOT / "site/fonts"
PINNED = {
    "source-serif-4-latin-400-normal.woff2": "02194deb92d3975dd30e11a3824a1f1db32b48c93654e60560cb81ce8e7b5f95",
    "source-serif-4-latin-400-italic.woff2": "882b7c150c29f29d4f8daae6b8dcae8662aac7f28ca34b34615305154136ecfd",
    "source-serif-4-latin-600-normal.woff2": "f2b7e1cf1d277b7608231868135648f8ad8e2b58d8e97ca088bee15dc357bee7",
    "source-code-pro-latin-400-normal.woff2": "75aa8cacfd459d58d7c093f3ff0ab8745cc878dfc93c5d4cda052791aeace878",
    "source-code-pro-latin-600-normal.woff2": "0d1ec7219990cad29c487df2e1fc6651671fd5224daec191cae5f649824cb7bd",
    "OFL.txt": "684ff6d6541d242242181ee66f3f6e68ca2267711af80e5c8a8292123c26c274",
}


def test_font_directory_holds_exactly_the_pinned_files():
    assert sorted(p.name for p in FONTS.iterdir()) == sorted(PINNED)


def test_every_font_file_matches_its_pin():
    for name, sha in PINNED.items():
        assert hashlib.sha256((FONTS / name).read_bytes()).hexdigest() == sha, name


def test_license_names_both_families_and_the_ofl():
    text = (FONTS / "OFL.txt").read_text(encoding="utf-8")
    assert text.startswith("Source Serif 4: Copyright 2014 - 2021 Adobe")
    assert "Source Code Pro: Copyright 2023 Adobe" in text
    assert "SIL OPEN FONT LICENSE Version 1.1" in text


def test_stylesheet_references_every_woff2_and_nothing_else():
    css = (ROOT / "site/templates/site.css").read_text(encoding="utf-8")
    urls = re.findall(r'url\("([^"]+)"\)', css)
    assert sorted(urls) == sorted(f"/fonts/{n}" for n in PINNED if n.endswith(".woff2"))
