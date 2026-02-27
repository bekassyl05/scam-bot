# bot/checker.py
import os
import re
import json
import socket
import unicodedata
from urllib.parse import urlparse, urljoin
from typing import List, Dict, Optional, Tuple, Any

import requests
import validators
import tldextract
from bs4 import BeautifulSoup

try:
    from services.renderer import render_from_html, render_url
except Exception:
    render_from_html = None
    render_url = None

try:
    import pytesseract
    from PIL import Image
except Exception:
    pytesseract = None
    Image = None

try:
    from pyzbar.pyzbar import decode as zbar_decode
except Exception:
    zbar_decode = None

try:
    import fitz
except Exception:
    fitz = None

try:
    import docx
except Exception:
    docx = None

try:
    from rapidfuzz import fuzz
except Exception:
    fuzz = None

# OPTIONAL heavy libs for file analysis
try:
    import magic as python_magic
except Exception:
    python_magic = None

try:
    import pefile
except Exception:
    pefile = None

try:
    import yara
except Exception:
    yara = None

try:
    from androguard.core.bytecodes.apk import APK as AndroAPK
except Exception:
    AndroAPK = None

# CONFIG
REQUEST_TIMEOUT = 6
MAX_CONTENT_BYTES = 200 * 1024
MAX_REDIRECTS = 6
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

# VirusTotal API key (optional)
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "").strip() or None
VT_HEADERS = {"x-apikey": VIRUSTOTAL_API_KEY} if VIRUSTOTAL_API_KEY else None
VT_FILE_LOOKUP_URL = "https://www.virustotal.com/api/v3/files/{}"

# blocklist sources (free feeds)
URLHAUS_CSV = "https://urlhaus.abuse.ch/downloads/csv_online/"
OPENPHISH_TXT = "https://openphish.com/feed.txt"

BLOCKLIST_CACHE = {
    "urlhaus": set(),
    "openphish": set(),
    "loaded": False
}

# Blocklists & shorteners
def load_blocklists(force: bool = False) -> None:
    if BLOCKLIST_CACHE["loaded"] and not force:
        return
    BLOCKLIST_CACHE["urlhaus"].clear()
    BLOCKLIST_CACHE["openphish"].clear()
    url_pattern = re.compile(r"https?://[^\s,]+", re.I)
    try:
        r = requests.get(URLHAUS_CSV, timeout=8)
        if r.ok:
            for m in url_pattern.finditer(r.text):
                BLOCKLIST_CACHE["urlhaus"].add(m.group(0).strip().lower())
    except Exception:
        pass
    try:
        r = requests.get(OPENPHISH_TXT, timeout=8)
        if r.ok:
            for line in r.text.splitlines():
                line = line.strip()
                if line and url_pattern.match(line):
                    BLOCKLIST_CACHE["openphish"].add(line.lower())
    except Exception:
        pass
    BLOCKLIST_CACHE["loaded"] = True

def is_blocklisted(url: str) -> Optional[str]:
    try:
        load_blocklists()
        u = url.strip().lower()
        if u in BLOCKLIST_CACHE["urlhaus"]:
            return "urlhaus"
        if u in BLOCKLIST_CACHE["openphish"]:
            return "openphish"
        for b in BLOCKLIST_CACHE["urlhaus"]:
            if b and b in u:
                return "urlhaus"
        for b in BLOCKLIST_CACHE["openphish"]:
            if b and b in u:
                return "openphish"
    except Exception:
        pass
    return None

def load_shorteners(path: Optional[str] = None) -> set:
    default = [
        "bit.ly", "t.co", "tinyurl.com", "goo.gl", "ow.ly",
        "is.gd", "buff.ly", "adf.ly", "shorturl.at", "tiny.one", "rb.gy"
    ]
    if not path:
        path = os.path.join(BASE_DIR, "shorteners.json")
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            arr = data.get("shorteners", default)
            return set([d.lower() for d in arr])
    except Exception:
        return set([d.lower() for d in default])

SHORTENERS = load_shorteners()

FILE_EXTENSIONS = {
    "apk", "exe", "zip", "rar", "scr", "js", "msi", "bat", "cmd",
    "docm", "xlsm", "php", "jar", "dmg", "run"
}

FILE_NAME_RE = re.compile(
    r"\b[A-Za-z0-9_\-\.\[\]\(\)\s]{3,200}\.(?:apk|exe|zip|rar|scr|js|msi|bat|cmd|docm|xlsm|php|jar|dmg|run)\b",
    re.IGNORECASE
)

OBFUSCATED_FILE_RE = re.compile(
    r"([A-Za-z0-9_\-]{2,200})\s*(?:\[dot\]|\(dot\)|\sdot\s|\.)\s*(apk|exe|zip|rar|scr|js|msi|bat|cmd|docm|xlsm|php|jar|dmg|run)",
    re.IGNORECASE
)

OBFUSCATION_PATTERNS = [
    (re.compile(r'\[dot\]|\(dot\)|\sdot\s|\[.\]', re.IGNORECASE), '.'),
    (re.compile(r'\[slash\]|\(slash\)|\sslash\s', re.IGNORECASE), '/'),
    (re.compile(r'hxxp', re.IGNORECASE), 'http'),
    (re.compile(r'\[at\]|\(at\)|\sat\s', re.IGNORECASE), '@'),
    (re.compile(r'[\u200B-\u200D\uFEFF]'), ''),  # zero-width chars
]

URL_RE = re.compile(r'(?:(?:https?://)|(?:http://))?(?:www\.)?[A-Za-z0-9\-\_]{1,63}(?:\.[A-Za-z0-9\-\_]{1,63})+\b', re.IGNORECASE)
DOMAIN_RE = re.compile(r"\b(?:[A-Za-z0-9\-]+\.)+[A-Za-z]{2,}\b", re.IGNORECASE)

# Utilities
def preprocess_obfuscation(text: str) -> str:
    if not text:
        return ""
    s = unicodedata.normalize("NFKC", text)
    for patt, repl in OBFUSCATION_PATTERNS:
        s = patt.sub(repl, s)
    s = re.sub(r'\s*\.\s*', '.', s)
    s = re.sub(r'\s+', ' ', s)
    return s.strip()

def extract_candidates_from_text(text: str) -> List[str]:
    text = preprocess_obfuscation(text)
    found = []
    for m in URL_RE.finditer(text):
        s = m.group(0).strip(".,;:()[]<>\"'")
        if s and s not in found:
            found.append(s)
    for m in DOMAIN_RE.finditer(text):
        s = m.group(0).strip(".,;:()[]<>\"'")
        if s and s not in found:
            found.append(s)
    for m in FILE_NAME_RE.finditer(text):
        s = m.group(0).strip()
        if s not in found:
            found.append(s)
    for m in OBFUSCATED_FILE_RE.finditer(text):
        name = re.sub(r'[^\w\.\-]', '', m.group(1))
        ext = m.group(2)
        cand = f"{name}.{ext}"
        if cand not in found:
            found.append(cand)
    return found

def normalize_candidate(s: str) -> Optional[str]:
    if not s:
        return None
    s = s.strip()
    if FILE_NAME_RE.search(s) or OBFUSCATED_FILE_RE.search(s):
        s2 = preprocess_obfuscation(s)
        s2 = re.sub(r'[^\w\.\-]', '', s2)
        return "file://" + s2
    if s.lower().startswith("http://") or s.lower().startswith("https://"):
        url = s
    else:
        if DOMAIN_RE.fullmatch(s):
            url = "https://" + s
        else:
            url = "https://" + s
    url = url.rstrip(".,;:)")
    if validators.url(url):
        return url
    try:
        parsed = urlparse(url)
        host = parsed.netloc
        host_idna = host.encode('idna').decode('ascii')
        rebuilt = parsed._replace(netloc=host_idna).geturl()
        if validators.url(rebuilt):
            return rebuilt
    except Exception:
        pass
    return None

def is_shortener_domain(domain: str) -> bool:
    return domain and domain.lower() in SHORTENERS

def safe_follow_redirects(url: str) -> List[str]:
    chain = [url]
    current = url
    for _ in range(MAX_REDIRECTS):
        try:
            r = requests.head(current, allow_redirects=False, timeout=REQUEST_TIMEOUT)
            loc = r.headers.get("Location")
            if loc:
                loc = urljoin(current, loc)
                if loc in chain:
                    break
                chain.append(loc)
                current = loc
                continue
            r2 = requests.get(current, allow_redirects=False, timeout=REQUEST_TIMEOUT, stream=True)
            loc2 = r2.headers.get("Location")
            if loc2:
                loc2 = urljoin(current, loc2)
                if loc2 in chain:
                    break
                chain.append(loc2)
                current = loc2
                continue
            break
        except Exception:
            break
    return chain

def resolve_ips(domain: str) -> List[str]:
    try:
        return socket.gethostbyname_ex(domain)[2]
    except Exception:
        return []

def is_private_ip(ip_str: str) -> bool:
    try:
        parts = [int(x) for x in ip_str.split(".")]
        if parts[0] == 10 or parts[0] == 127:
            return True
        if parts[0] == 192 and parts[1] == 168:
            return True
        if parts[0] == 172 and 16 <= parts[1] <= 31:
            return True
        return False
    except Exception:
        return False

def fetch_content_safe(url: str) -> Tuple[Optional[int], str]:
    try:
        with requests.get(url, timeout=REQUEST_TIMEOUT, stream=True, allow_redirects=False) as r:
            content = b""
            for chunk in r.iter_content(2048):
                if not chunk:
                    break
                content += chunk
                if len(content) > MAX_CONTENT_BYTES:
                    break
            try:
                text = content.decode("utf-8", errors="ignore")
            except Exception:
                text = ""
            return r.status_code, text
    except Exception:
        return None, ""

# File / image extraction
def extract_text_from_pdf(path: str) -> str:
    if not fitz:
        return ""
    try:
        doc = fitz.open(path)
        txt = []
        for page in doc:
            txt.append(page.get_text())
        return "\n".join(txt)
    except Exception:
        return ""

def extract_text_from_docx(path: str) -> str:
    if not docx:
        return ""
    try:
        d = docx.Document(path)
        paragraphs = [p.text for p in d.paragraphs]
        return "\n".join(paragraphs)
    except Exception:
        return ""

def ocr_image_file(path: str) -> str:
    if not pytesseract or not Image:
        return ""
    try:
        img = Image.open(path)
        txt = pytesseract.image_to_string(img)
        return txt
    except Exception:
        return ""

def scan_qr_from_image(path: str) -> List[str]:
    if not zbar_decode or not Image:
        return []
    try:
        img = Image.open(path)
        codes = zbar_decode(img)
        found = []
        for c in codes:
            try:
                found.append(c.data.decode())
            except Exception:
                pass
        return found
    except Exception:
        return []

# File-analysis helpers (static)
import hashlib
import mimetypes
import zipfile

APK_SUSPICIOUS_PERMS = {
    "SEND_SMS","RECEIVE_SMS","READ_SMS","WRITE_SMS","RECEIVE_MMS",
    "RECORD_AUDIO","READ_CONTACTS","WRITE_CONTACTS",
    "REQUEST_INSTALL_PACKAGES","SYSTEM_ALERT_WINDOW","WRITE_EXTERNAL_STORAGE",
    "READ_PHONE_STATE","CALL_PHONE","PROCESS_OUTGOING_CALLS"
}
PE_SUSPICIOUS_IMPORTS = {
    "URLDownloadToFileA","URLDownloadToFileW","WinExec","CreateProcessA","CreateProcessW",
    "ShellExecuteA","ShellExecuteW","InternetOpenA","InternetOpenW","InternetConnectA","InternetConnectW",
    "HttpSendRequestA","HttpSendRequestW"
}

def compute_file_sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

def detect_mime(path: str) -> str:
    try:
        if python_magic:
            m = python_magic.Magic(mime=True)
            return m.from_file(path)
    except Exception:
        pass
    t, _ = mimetypes.guess_type(path)
    return t or "application/octet-stream"

def vt_lookup_by_hash(sha256_hex: str) -> dict:
    if not VIRUSTOTAL_API_KEY:
        return {}
    try:
        url = VT_FILE_LOOKUP_URL.format(sha256_hex)
        r = requests.get(url, headers=VT_HEADERS, timeout=10)
        if r.status_code == 200:
            data = r.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats")
            verdict = data.get("data", {}).get("attributes", {}).get("last_analysis_results")
            return {"vt_stats": stats, "vt_results": verdict}
        else:
            return {"error": f"vt_status_{r.status_code}", "text": r.text[:200]}
    except Exception as e:
        return {"error": "vt_exception", "text": str(e)}

def yara_scan_file(path: str, rules_path: str = "yara_rules.yar") -> list:
    if yara is None:
        return []
    if not os.path.exists(rules_path):
        return []
    try:
        rules = yara.compile(filepath=rules_path)
        matches = rules.match(path)
        return [{"rule": m.rule, "ns": m.namespace} for m in matches]
    except Exception:
        return []

def analyze_apk_file(path: str) -> dict:
    out = {"apk": {}}
    if AndroAPK is None:
        out["apk"]["error"] = "androguard_missing"
        return out
    try:
        a = AndroAPK(path)
        out["apk"]["package"] = a.get_package()
        out["apk"]["version_name"] = a.get_androidversion_name()
        out["apk"]["requested_permissions"] = a.get_permissions() or []
        perms = set([p.split(".")[-1].upper() for p in (a.get_permissions() or [])])
        suspicious = [p for p in perms if p in APK_SUSPICIOUS_PERMS]
        out["apk"]["suspicious_permissions"] = suspicious
        out["apk"]["activities"] = a.get_activities() or []
        out["apk"]["services"] = a.get_services() or []
        out["apk"]["receivers"] = a.get_receivers() or []
    except Exception as e:
        out["apk"]["error"] = str(e)
    return out

def analyze_pe_file(path: str) -> dict:
    out = {"pe": {}}
    if pefile is None:
        out["pe"]["error"] = "pefile_missing"
        return out
    try:
        pe = pefile.PE(path, fast_load=True)
        imports = []
        try:
            for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
                dll = entry.dll.decode(errors="ignore") if isinstance(entry.dll, bytes) else str(entry.dll)
                for imp in entry.imports or []:
                    name = (imp.name.decode(errors="ignore") if imp.name else None)
                    if name:
                        imports.append(name)
        except Exception:
            pass
        out["pe"]["imports"] = imports
        suspicious = [i for i in imports if i in PE_SUSPICIOUS_IMPORTS]
        out["pe"]["suspicious_imports"] = suspicious
    except Exception as e:
        out["pe"]["error"] = str(e)
    return out

def analyze_archive_file(path: str) -> dict:
    out = {"archive": {}}
    try:
        if zipfile.is_zipfile(path):
            with zipfile.ZipFile(path, "r") as z:
                names = z.namelist()
            out["archive"]["type"] = "zip"
            out["archive"]["members"] = names[:200]
            execs = [n for n in names if os.path.splitext(n)[1].lower() in (".exe", ".msi", ".apk", ".bat", ".cmd")]
            out["archive"]["embedded_executables"] = execs
        else:
            out["archive"]["note"] = "not_zip_or_unsupported"
    except Exception as e:
        out["archive"]["error"] = str(e)
    return out

def analyze_local_file(path: str) -> dict:
    res = {}
    try:
        if not os.path.exists(path):
            return {"error": "file_not_found"}
        fname = os.path.basename(path)
        res["file_name"] = fname
        sha256 = compute_file_sha256(path)
        res["sha256"] = sha256
        mim = detect_mime(path)
        res["mime"] = mim
        ext = os.path.splitext(fname)[1].lower()
        res["extension"] = ext

        suspicious_indicators = []
        try:
            stat = os.stat(path)
            res["size_bytes"] = stat.st_size
            if stat.st_size > (50 * 1024 * 1024):
                suspicious_indicators.append("large_file_over_50mb")
        except Exception:
            pass

        if ext in {".apk", ".exe", ".msi", ".bat", ".cmd", ".scr", ".dmg"}:
            suspicious_indicators.append(f"executable_extension:{ext}")

        yara_matches = yara_scan_file(path)
        if yara_matches:
            res["yara"] = yara_matches
            suspicious_indicators.append("yara_matches")

        vt = vt_lookup_by_hash(sha256)
        if vt:
            res["vt"] = vt
            stats = vt.get("vt_stats") or {}
            if isinstance(stats, dict):
                malicious = stats.get("malicious", 0) or 0
                total = sum([v or 0 for v in stats.values()]) if stats else 0
                res["vt_summary"] = {"malicious": malicious, "total": total}
                if total and malicious and malicious/float(total) > 0.05:
                    suspicious_indicators.append(f"vt_malicious_ratio:{malicious}/{total}")

        if ext == ".apk":
            res.update(analyze_apk_file(path))
            apk_susp = res.get("apk", {}).get("suspicious_permissions") or []
            if apk_susp:
                suspicious_indicators.append("apk_suspicious_permissions:" + ",".join(apk_susp))

        if ext in {".exe", ".msi", ".dll"}:
            res.update(analyze_pe_file(path))
            pe_susp = res.get("pe", {}).get("suspicious_imports") or []
            if pe_susp:
                suspicious_indicators.append("pe_suspicious_imports:" + ",".join(pe_susp))

        if ext in {".zip", ".rar", ".7z"} or zipfile.is_zipfile(path):
            res.update(analyze_archive_file(path))
            embedded = res.get("archive", {}).get("embedded_executables") or []
            if embedded:
                suspicious_indicators.append("archive_contains_executables")

        if ext in {".js", ".vbs", ".ps1", ".sh"}:
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    txt = f.read(20000)
                low = txt.lower()
                for kw in ("eval(", "atob(", "base64", "wscript", "activexobject", "createobject", "downloadfile"):
                    if kw in low:
                        suspicious_indicators.append(f"script_indicator:{kw}")
                        break
            except Exception:
                pass

        confidence_delta = 0.0
        if any("vt_malicious_ratio" in s for s in suspicious_indicators):
            confidence_delta += 0.6
        if any(x.startswith("apk_suspicious_permissions") for x in suspicious_indicators):
            confidence_delta += 0.35
        if any(x.startswith("pe_suspicious_imports") for x in suspicious_indicators):
            confidence_delta += 0.45
        if any(x.startswith("executable_extension") for x in suspicious_indicators):
            confidence_delta += 0.2
        if any("archive_contains_executables" in x for x in suspicious_indicators):
            confidence_delta += 0.25
        confidence_delta = min(confidence_delta, 0.99)

        res["suspicious_indicators"] = suspicious_indicators
        res["confidence_delta"] = confidence_delta

        if confidence_delta >= 0.5 or ("vt" in res and res.get("vt_summary", {}).get("malicious", 0) > 0):
            res["recommendation"] = "danger: do not open"
        elif confidence_delta >= 0.2:
            res["recommendation"] = "suspicious: be careful"
        else:
            res["recommendation"] = "likely_safe_but_check"

        return res
    except Exception as e:
        return {"error": "analyze_local_exception", "text": str(e)}

# Analysis helpers
def detect_homoglyph(domain: str) -> Optional[str]:
    if not domain:
        return None
    try:
        for ch in domain:
            if ord(ch) > 127:
                return f"Domain contains non-ascii or unicode chars: {domain}"
        return None
    except Exception:
        return None

def detect_forms_and_keywords(html_text: str) -> List[str]:
    found = []
    if not html_text:
        return found
    try:
        soup = BeautifulSoup(html_text, "html.parser")
        forms = soup.find_all("form")
        if forms:
            found.append(f"{len(forms)} form(s) found")
        keywords = ["card", "cvv", "pin", "пароль", "карт", "номер карты", "login", "password", "pay", "bank", "iban"]
        lower = html_text.lower()
        for kw in keywords:
            if kw in lower:
                found.append(f"Keyword found: {kw}")
    except Exception:
        pass
    return found

def typosquat_score(domain_label: str) -> int:
    KNOWN_BRANDS = ["paypal", "google", "facebook", "amazon", "sberbank", "halykbank", "visa", "mastercard"]
    if not fuzz:
        return 0
    best = 0
    for b in KNOWN_BRANDS:
        p = fuzz.partial_ratio(domain_label, b)
        t = fuzz.token_sort_ratio(domain_label, b)
        score = max(p, t)
        if score > best:
            best = score
    return best

def expand_shortener(url: str) -> Tuple[str, List[str]]:
    chain = safe_follow_redirects(url)
    final = chain[-1] if chain else url
    return final, chain

# Main analyzer (merged and enhanced)
def analyze_candidate_url(url: str) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "url": url,
        "domain": None,
        "file_name": None,
        "redirect_chain": [],
        "ips": [],
        "forms_or_keywords": [],
        "confidence": 0.0,
        "reasons": [],
        "analysis_details": {}
    }

    try:
        bl = is_blocklisted(url)
        if bl:
            result["confidence"] = 0.98
            result["reasons"].append(f"Blocklisted by {bl}")
            result["analysis_details"]["blocklist"] = bl
            return result
    except Exception:
        pass

    if url.startswith("file://"):
        fname = url[len("file://"):]
        result["file_name"] = fname
        ext = fname.split(".")[-1].lower() if "." in fname else ""
        if ext in {"apk", "exe", "msi", "jar", "dmg"}:
            result["confidence"] += 0.7
            result["reasons"].append(f"Executable-like extension detected: .{ext}")
        elif ext in {"zip", "rar"}:
            result["confidence"] += 0.4
            result["reasons"].append(f"Archive extension: .{ext} (could carry malware)")
        else:
            result["confidence"] += 0.25
            result["reasons"].append(f"Suspicious extension: .{ext}")
        lower = fname.lower()
        suspicious_keywords = ["update", "invoice", "payment", "bank", "secure", "login", "confirm", "pay"]
        for kw in suspicious_keywords:
            if kw in lower:
                result["confidence"] += 0.12
                result["reasons"].append(f"Filename contains suspicious keyword: {kw}")
        result["confidence"] = min(result["confidence"], 0.99)
        result["analysis_details"] = {"file_name": fname}
        return result

    try:
        chain = safe_follow_redirects(url)
        result["redirect_chain"] = chain
        final = chain[-1] if chain else url
        parsed = urlparse(final)
        domain = tldextract.extract(final).registered_domain
        result["domain"] = domain

        ts = 0
        if domain:
            sld = tldextract.extract(domain).domain or ""
            ts = typosquat_score(re.sub(r'[^a-z0-9]', '', sld.lower()))
            if ts >= 75:
                result["confidence"] += 0.35
                result["reasons"].append(f"Typosquat-like domain ({ts}%)")

        orig_domain = tldextract.extract(url).registered_domain
        if orig_domain and is_shortener_domain(orig_domain):
            result["confidence"] += 0.20
            result["reasons"].append("Shortened URL detected")
            final2, chain2 = expand_shortener(url)
            if chain2 and chain2 != chain:
                for c in chain2:
                    if c not in result["redirect_chain"]:
                        result["redirect_chain"].append(c)
                final = result["redirect_chain"][-1]

        if not urlparse(final).scheme.startswith("https"):
            result["confidence"] += 0.12
            result["reasons"].append("No HTTPS detected")

        if domain:
            ips = resolve_ips(domain)
            result["ips"] = ips
            for ip in ips:
                if is_private_ip(ip):
                    result["confidence"] += 0.3
                    result["reasons"].append(f"Domain resolves to private IP {ip}")

        status, html = fetch_content_safe(final)
        page = {}
        render_info = {}
        if html:
            fk = detect_forms_and_keywords(html)
            if fk:
                result["forms_or_keywords"] = fk
                result["reasons"].extend(fk)
                result["confidence"] += 0.15

            page = deep_page_analysis(html, final)
            if page.get("has_password_input"):
                result["confidence"] += 0.35
                result["reasons"].append("Password input field detected")
            if page.get("external_form_actions") and len(page.get("external_form_actions")) > 0:
                result["confidence"] += 0.4
                result["reasons"].append("Form submits data to external domain")

            if render_from_html is not None:
                try:
                    render_info = render_from_html(html, final)
                except Exception:
                    render_info = {}
        else:
            if render_url is not None:
                try:
                    render_info = render_url(final)
                except Exception:
                    render_info = {}

        if page:
            result["analysis_details"]["page"] = page
        if render_info:
            result["analysis_details"]["render"] = render_info

        homog = detect_homoglyph(domain)
        if homog:
            result["confidence"] += 0.18
            result["reasons"].append(homog)

        result["confidence"] = min(result["confidence"], 0.99)
        result["analysis_details"].update({"status_code": status, "final_url": final, "typoscore": ts})
        return result

    except Exception as e:
        result["reasons"].append(f"analysis_error: {e}")
        return result

def analyze_url(input_text: Optional[str] = None, file_path: Optional[str] = None, original_filename: Optional[str] = None) -> Dict[str, Any]:
    ocr_text = ""
    candidates: List[str] = []
    file_analysis_result = None

    if file_path:
        ext = os.path.splitext(file_path)[1].lower()
        if ext == ".pdf" and fitz:
            ocr_text = extract_text_from_pdf(file_path)
        elif ext == ".docx" and docx:
            ocr_text = extract_text_from_docx(file_path)
        elif ext in {".png", ".jpg", ".jpeg", ".bmp", ".tiff"}:
            qr = scan_qr_from_image(file_path) or []
            if qr:
                ocr_text = "\n".join(qr)
            ocr_img = ocr_image_file(file_path) or ""
            if ocr_img:
                ocr_text = (ocr_text + "\n" + ocr_img).strip()
        else:
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    ocr_text = f.read()
            except Exception:
                ocr_text = ""

        candidates = extract_candidates_from_text(ocr_text)

        try:
            # { "extension":".apk", "size_bytes":..., "sha256":..., "suspicious_indicators":[...], "confidence_delta":0.2, ... }
            file_analysis_result = analyze_local_file(file_path)

            if isinstance(file_analysis_result, dict):
                if original_filename:
                    file_analysis_result.setdefault("file_name", original_filename)
                else:
                    file_analysis_result.setdefault("file_name", os.path.basename(file_path))
        except Exception:
            file_analysis_result = {"error": "file_analysis_failed", "file_name": (original_filename or os.path.basename(file_path))}

        try:
            if not candidates and isinstance(file_analysis_result, dict):
                for key in ("embedded_urls", "strings", "extracted_text"):
                    vals = file_analysis_result.get(key)
                    if isinstance(vals, (list, tuple)):
                        for v in vals:
                            if isinstance(v, str):
                                candidates.extend(extract_candidates_from_text(v))
                if candidates:
                    seen_tmp = set()
                    new_cands = []
                    for c in candidates:
                        if c not in seen_tmp:
                            seen_tmp.add(c)
                            new_cands.append(c)
                    candidates = new_cands
        except Exception:
            pass

    else:
        candidates = extract_candidates_from_text(input_text or "")

    normalized = []
    analyses = []
    for cand in candidates:
        norm = normalize_candidate(cand)
        if norm:
            normalized.append(norm)

    seen = set()
    normalized_unique = []
    for n in normalized:
        if n not in seen:
            seen.add(n)
            normalized_unique.append(n)

    if not normalized_unique and input_text:
        maybe = normalize_candidate(input_text.strip())
        if maybe:
            normalized_unique.append(maybe)

    for url in normalized_unique:
        try:
            a = analyze_candidate_url(url)
        except Exception as e:
            a = {
                "url": url,
                "confidence": 0.0,
                "reasons": [f"analysis_failed: {e}"],
                "analysis_details": {}
            }
        analyses.append(a)

    if file_path and file_analysis_result is not None:
        display_name = original_filename or os.path.basename(file_path)

        suspicious_indicators = []
        try:
            suspicious_indicators = file_analysis_result.get("suspicious_indicators") or file_analysis_result.get("indicators") or []
        except Exception:
            suspicious_indicators = []

        confidence_delta = 0.0
        try:
            confidence_delta = float(file_analysis_result.get("confidence_delta", 0.0))
        except Exception:
            confidence_delta = 0.0

        file_entry = {
            "url": None,
            "file_name": display_name,
            "confidence": float(confidence_delta),
            "reasons": suspicious_indicators or [],
            "analysis_details": {"file_analysis": file_analysis_result}
        }

        try:
            if isinstance(file_entry["analysis_details"].get("file_analysis"), dict):
                file_entry["analysis_details"]["file_analysis"]["file_name"] = display_name
        except Exception:
            pass

        analyses.insert(0, file_entry)

    agg_conf = 0.0
    for a in analyses:
        try:
            agg_conf = max(agg_conf, float(a.get("confidence", 0)))
        except Exception:
            pass

    original_field = original_filename or file_path or input_text

    return {
        "original": original_field,
        "ocr_text": ocr_text,
        "candidates": normalized_unique,
        "analyses": analyses,
        "confidence": agg_conf
    }


# Deep page analysis (kept original)
def deep_page_analysis(html: str, base_url: str) -> Dict[str, Any]:
    data = {
        "has_password_input": False,
        "has_card_keywords": False,
        "form_actions": [],
        "external_form_actions": [],
        "scripts": []
    }

    if not html:
        return data

    try:
        soup = BeautifulSoup(html, "html.parser")
        base_domain = tldextract.extract(base_url).registered_domain

        for f in soup.find_all("form"):
            action = f.get("action") or ""
            full_action = urljoin(base_url, action)
            data["form_actions"].append(full_action)

            act_domain = tldextract.extract(full_action).registered_domain
            if act_domain and act_domain != base_domain:
                data["external_form_actions"].append(full_action)

            for inp in f.find_all("input"):
                t = (inp.get("type") or "").lower()
                name = (inp.get("name") or "").lower()
                if t == "password":
                    data["has_password_input"] = True
                if any(k in name for k in ["card", "cvv", "iban", "pin"]):
                    data["has_card_keywords"] = True

        for s in soup.find_all("script"):
            src = s.get("src")
            if src:
                data["scripts"].append(urljoin(base_url, src))

    except Exception:
        pass

    return data
