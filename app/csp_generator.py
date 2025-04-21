import os
import re
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

def validate_csp_header(scan_path: str, header_file: str) -> Tuple[bool, List[str]]:
    """
    Compare inline-script hashes in HTML files under scan_path
    against those listed in the existing CSP header_file.

    Returns (is_valid, report_lines).
    """

    # same generate_csp_header logic to get current hashes
    current_hashes = set()
    for root, _, files in os.walk(scan_path):
        for fname in files:
            if fname.endswith('.html'):
                full_path = os.path.join(root, fname)
                with open(full_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                # find inline scripts and hash them
                soup = BeautifulSoup(content, 'html.parser')
                for tag in soup.find_all('script'):
                    if not tag.has_attr('src'):
                        script = tag.decode_contents().strip()
                        if script:
                            digest = hashlib.sha256(script.encode()).digest()
                            b64 = base64.b64encode(digest).decode()
                            current_hashes.add(f"'sha256-{b64}'")

    # Extract hashes from the existing header file
    with open(header_file, 'r', encoding='utf-8') as f:
        header_text = f.read()
    # regex to capture everything between script-src and the next semicolon
    match = re.search(r"script-src[^;]*", header_text)
    if not match:
        raise ValueError("No script-src directive found in header.")
    header_directive = match.group(0)
    # extract individual 'sha256-...' tokens
    header_hashes = set(re.findall(r"'sha256-[A-Za-z0-9+/=]+'", header_directive))

    missing = current_hashes - header_hashes
    extra = header_hashes - current_hashes

    report: List[str] = []
    if missing:
        for h in sorted(missing):
            report.append(f"Missing hash: {h}")
    if extra:
        for h in sorted(extra):
            report.append(f"Extraneous hash: {h}")

    is_valid = not report
    return is_valid, report
