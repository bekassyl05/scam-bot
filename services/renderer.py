# services/renderer.py
from typing import Optional, Dict, Any, List, Tuple
from urllib.parse import urlparse, urljoin
import requests
from bs4 import BeautifulSoup
import re
import socket
import os
import base64

try:
    from readability import Document as ReadabilityDocument
except Exception:
    ReadabilityDocument = None

try:
    from langdetect import detect as lang_detect
except Exception:
    lang_detect = None

MAX_BYTES_DEFAULT = 200 * 1024
TIMEOUT_DEFAULT = 6
HEADERS = {
    "User-Agent": "ScamBot/1.0 (+https://example.local) Python-requests"
}

_PRIVATE_IP_RANGES = [
    ("10.0.0.0", "10.255.255.255"),
    ("127.0.0.0", "127.255.255.255"),
    ("172.16.0.0", "172.31.255.255"),
    ("192.168.0.0", "192.168.255.255")
]

def _ip_to_int(ip: str) -> int:
    try:
        parts = [int(p) for p in ip.split(".")]
        return (parts[0]<<24) | (parts[1]<<16) | (parts[2]<<8) | parts[3]
    except Exception:
        return 0

def _is_private_ip(ip: str) -> bool:
    try:
        ii = _ip_to_int(ip)
        for a,b in _PRIVATE_IP_RANGES:
            if _ip_to_int(a) <= ii <= _ip_to_int(b):
                return True
    except Exception:
        pass
    return False

def _resolve_host(host: str) -> List[str]:
    try:
        return socket.gethostbyname_ex(host)[2]
    except Exception:
        return []

def _clean_text(s: str) -> str:
    s = re.sub(r'\s+', ' ', s).strip()
    return s

def _absolute_url(base: str, link: str) -> str:
    try:
        return urljoin(base, link)
    except Exception:
        return link

def _extract_images(soup: BeautifulSoup, base_url: str, limit: int = 6) -> List[str]:
    imgs = []
    for img in soup.find_all("img"):
        src = img.get("src") or img.get("data-src") or ""
        if not src:
            continue
        absu = _absolute_url(base_url, src)
        imgs.append(absu)
        if len(imgs) >= limit:
            break
    return imgs

def fetch_url_content(url: str, max_bytes: int = MAX_BYTES_DEFAULT, timeout: int = TIMEOUT_DEFAULT) -> Tuple[Optional[int], Optional[str], Optional[str], List[str]]:
    warnings = []
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return None, None, None, ["unsupported_scheme"]
        host = parsed.hostname
        if host:
            ips = _resolve_host(host)
            for ip in ips:
                if _is_private_ip(ip):
                    return None, None, None, ["resolved_to_private_ip"]
        with requests.get(url, headers=HEADERS, timeout=timeout, stream=True, allow_redirects=True) as r:
            status = r.status_code
            final = r.url
            ctype = r.headers.get("Content-Type", "")

            if "text/html" not in (ctype or "") and "html" not in (ctype or ""):
                return status, final, None, [f"non_html_content:{ctype}"]
            content = b""
            for chunk in r.iter_content(2048):
                if not chunk:
                    break
                content += chunk
                if len(content) > max_bytes:
                    warnings.append("truncated_by_size")
                    break
            try:
                text = content.decode(r.encoding or "utf-8", errors="ignore")
            except Exception:
                text = content.decode("utf-8", errors="ignore")
            return status, final, text, warnings
    except requests.exceptions.RequestException as ex:
        return None, None, None, [f"request_error:{str(ex)}"]
    except Exception as ex:
        return None, None, None, [f"fetch_error:{str(ex)}"]

def render_from_html(html: str, base_url: str) -> Dict[str, Any]:
    out: Dict[str, Any] = {"ok": True, "warnings": []}
    try:
        doc_title = None
        meta_desc = None
        canonical = None
        main_text = None
        excerpt = None
        top_images = []

        if ReadabilityDocument is not None:
            try:
                rd = ReadabilityDocument(html)
                main_html = rd.summary()
                doc_title = rd.short_title()
                main_soup = BeautifulSoup(main_html, "html.parser")
                main_text = _clean_text(main_soup.get_text(separator=" ", strip=True))
            except Exception:
                main_text = None

        soup = BeautifulSoup(html, "html.parser")
        if not doc_title:
            title_tag = soup.find("title")
            doc_title = (title_tag.get_text().strip() if title_tag else None)

        desc_tag = soup.find("meta", attrs={"name":"description"}) or soup.find("meta", attrs={"property":"og:description"})
        if desc_tag:
            meta_desc = desc_tag.get("content", None)

        can_tag = soup.find("link", rel="canonical")
        if can_tag:
            canonical = can_tag.get("href")

        if not main_text:
            for s in soup(["script","style","noscript","iframe"]):
                s.extract()
            text = soup.get_text(separator=" ", strip=True)
            main_text = _clean_text(text)

        if main_text:
            excerpt = main_text[:800].rsplit(" ",1)[0]
        else:
            excerpt = ""

        top_images = _extract_images(soup, base_url)

        out.update({
            "title": doc_title,
            "meta_description": meta_desc,
            "canonical": canonical,
            "text": main_text[:20000] if main_text else "",
            "excerpt": excerpt,
            "word_count": len((main_text or "").split()),
            "top_images": top_images
        })

        if lang_detect is not None and main_text:
            try:
                out["language"] = lang_detect(main_text[:2000])
            except Exception:
                out["language"] = None

        return out
    except Exception as ex:
        return {"ok": False, "error": f"parse_error:{ex}"}

def render_url(url: str, *, fetch: bool = True, max_bytes: int = MAX_BYTES_DEFAULT, timeout: int = TIMEOUT_DEFAULT) -> Dict[str, Any]:
    if not url:
        return {"ok": False, "error": "empty_url"}

    parsed = urlparse(url)
    if not parsed.scheme:
        url = "https://" + url
        parsed = urlparse(url)

    if parsed.scheme not in ("http","https"):
        return {"ok": False, "error": "unsupported_scheme"}

    if fetch:
        status, final, html, warnings = fetch_url_content(url, max_bytes=max_bytes, timeout=timeout)
        res = {"ok": bool(html is not None), "status_code": status, "final_url": final, "content_type": None, "warnings": warnings}
        if html is None:
            return {**res, "ok": False, "error": "no_html_or_fetch_failed"}

        parsed_info = render_from_html(html, final or url)
        res.update(parsed_info)
        return res
    else:
        return {"ok": False, "error": "fetch_disabled"}

def render_url_playwright(url: str, timeout: int = 10000, viewport=(1280,720)) -> dict:
    try:
        from playwright.sync_api import sync_playwright
    except Exception:
        return {"ok": False, "error": "playwright_not_installed"}

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True, args=["--no-sandbox"])
            context = browser.new_context(viewport={"width": viewport[0], "height": viewport[1]})
            page = context.new_page()
            page.set_default_navigation_timeout(timeout)
            page.goto(url, wait_until="networkidle")
            title = page.title()
            content = page.content()

            text = page.inner_text("body") if page.query_selector("body") else ""
            excerpt = (text[:800].rsplit(" ",1)[0]) if text else ""

            img_bytes = page.screenshot(full_page=False)
            data64 = base64.b64encode(img_bytes).decode("ascii")
            dataurl = f"data:image/png;base64,{data64}"
            final = page.url
            page.close()
            context.close()
            browser.close()
            return {"ok": True, "status_code": 200, "final_url": final,
                    "title": title, "text": text, "excerpt": excerpt,
                    "screenshot": dataurl, "warnings": []}
    except Exception as ex:
        return {"ok": False, "error": str(ex)}