import os
import hashlib
import base64
from bs4 import BeautifulSoup
from typing import Tuple, List
from app.utils import log_detail

def generate_csp_header(scan_path: str) -> Tuple[str, List[str]]:
    # if not os.path.isdir(scan_path):
    #     raise ValueError(f"Provided path '{scan_path}' is not a valid directory.")

    script_hashes = set()
    details = []

    for root, _, files in os.walk(scan_path):
        for filename in files:
            if filename.endswith(".html"):
                filepath = os.path.join(root, filename)
                with open(filepath, "r", encoding="utf-8") as file:
                    soup = BeautifulSoup(file, "html.parser")
                    for script_tag in soup.find_all("script"):
                        if not script_tag.has_attr("src"):
                            script_content = script_tag.decode_contents().strip()
                            if script_content:
                                hash_digest = hashlib.sha256(script_content.encode("utf-8")).digest()
                                hash_b64 = base64.b64encode(hash_digest).decode("utf-8")
                                full_hash = f"'sha256-{hash_b64}'"
                                if full_hash not in script_hashes:
                                    script_hashes.add(full_hash)
                                    details.append(log_detail(full_hash, filepath, len(script_content)))
                            else:
                                print(f"⚠️  Skipped empty inline script in: {filepath}")
    
    sorted_hashes = sorted(script_hashes)
    csp = (
        "Content-Security-Policy: default-src 'none'; "
        "script-src 'self' " + " ".join(sorted_hashes) + "; "
        "style-src 'self'; img-src 'self' data:; font-src 'self'; "
        "frame-ancestors 'none'; base-uri 'self'; form-action 'none'"
    )

    header_content = f"""
{csp}
X-XSS-Protection: 0
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
Referrer-Policy: strict-origin-when-cross-origin
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Permissions-Policy: geolocation=(), microphone=(), camera=(), interest-cohort=()
Expect-CT: max-age=86400, enforce
""".strip()

    return header_content, details
