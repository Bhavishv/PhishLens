"""
PhishLens — Vendor Assets Downloader (Optional Utility)

Vendors Leaflet 1.9.4 JS and CSS locally under static/vendor/leaflet/
so the map operates without third-party trackers or external runtime scripts.
"""

import os
import urllib.request

ASSETS = {
    "static/vendor/leaflet/leaflet.js": (
        "https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"
    ),
    "static/vendor/leaflet/leaflet.css": (
        "https://unpkg.com/leaflet@1.9.4/dist/leaflet.css"
    ),
}

def download():
    print("[*] Downloading Leaflet assets for local vendoring...")
    for local_path, url in ASSETS.items():
        os.makedirs(os.path.dirname(local_path), exist_ok=True)
        if os.path.exists(local_path) and os.path.getsize(local_path) > 1000:
            print(f"  [✓] Exists: {local_path} ({os.path.getsize(local_path):,} bytes)")
            continue
        try:
            print(f"  [>] Fetching {url} ...")
            req = urllib.request.Request(url, headers={"User-Agent": "PhishLens-VendorDownloader/1.0"})
            with urllib.request.urlopen(req, timeout=15) as resp, open(local_path, "wb") as out:
                out.write(resp.read())
            print(f"  [✓] Saved: {local_path} ({os.path.getsize(local_path):,} bytes)")
        except Exception as exc:
            print(f"  [!] Notice: Could not download {local_path} ({exc}). Fallback structured hop table will be used.")

if __name__ == "__main__":
    download()
