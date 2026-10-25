"""
PhishLens — Font Downloader (Optional Utility)

Downloads standalone WOFF2 variable font binaries for Manrope and JetBrains Mono
so PhishLens can operate 100% offline without CDN dependencies.
"""

import os
import urllib.request

FONTS = {
    "static/fonts/manrope/Manrope-Variable.woff2": (
        "https://raw.githubusercontent.com/sharanda/manrope/master/fonts/variable/Manrope%5Bwght%5D.woff2"
    ),
    "static/fonts/jetbrains-mono/JetBrainsMono-Variable.woff2": (
        "https://raw.githubusercontent.com/JetBrains/JetBrainsMono/master/fonts/variable/JetBrainsMono%5Bwght%5D.woff2"
    ),
}

def download():
    print("[*] Downloading self-hosted font assets for offline support...")
    for local_path, url in FONTS.items():
        os.makedirs(os.path.dirname(local_path), exist_ok=True)
        if os.path.exists(local_path) and os.path.getsize(local_path) > 0:
            print(f"  [✓] Exists: {local_path}")
            continue
        try:
            print(f"  [>] Fetching {url} ...")
            req = urllib.request.Request(url, headers={"User-Agent": "PhishLens-FontDownloader/1.0"})
            with urllib.request.urlopen(req, timeout=15) as resp, open(local_path, "wb") as out:
                out.write(resp.read())
            print(f"  [✓] Saved: {local_path} ({os.path.getsize(local_path):,} bytes)")
        except Exception as exc:
            print(f"  [!] Notice: Could not download {local_path} ({exc}). System font fallbacks are active.")

if __name__ == "__main__":
    download()
