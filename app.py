"""NEX OSINT Pro: a local-first web UI for public-source research.
Run: python -m uvicorn app:app --host 127.0.0.1 --port 8000
"""
from __future__ import annotations
import asyncio, hashlib, hmac, ipaddress, json, logging, os, re, socket, sqlite3, uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote
import httpx
from bs4 import BeautifulSoup
from fastapi import FastAPI, Header, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

ROOT = Path(__file__).resolve().parent
log = logging.getLogger("nexosint")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
UA = "NEX-OSINT-Pro/1.0 (+public-source-research; local-user-tool)"
TIMEOUT = httpx.Timeout(20.0, connect=8.0)
app = FastAPI(title="NEX OSINT Pro", version="1.1.0", description="Live public-source research API; no mock findings.", docs_url="/api/docs", redoc_url=None)
# The frontend is hosted separately on Cloudflare Pages. Public read-only API; no cookies/credentials.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["GET", "POST", "PUT", "OPTIONS"],
    allow_headers=["*"],
)
app.mount("/assets", StaticFiles(directory=ROOT / "assets"), name="assets")


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def clean_username(value: str) -> str:
    value = value.strip().lstrip("@").strip()
    if not re.fullmatch(r"[A-Za-z0-9_.-]{2,40}", value):
        raise HTTPException(400, "Kullanıcı adı 2–40 karakter olmalı; harf, rakam, nokta, tire ve alt çizgi kullanılabilir.")
    return value


def clean_domain(value: str) -> str:
    value = value.strip().lower().rstrip(".")
    value = re.sub(r"^https?://", "", value).split("/", 1)[0].split(":", 1)[0]
    if len(value) > 253 or not re.fullmatch(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", value):
        raise HTTPException(400, "Geçerli bir alan adı gir.")
    return value


def parse_public_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    try:
        addr = ipaddress.ip_address(value.strip())
    except ValueError as exc:
        raise HTTPException(400, "Geçerli bir IP adresi gir.") from exc
    if not addr.is_global:
        raise HTTPException(400, "Private, loopback, local veya rezerve edilmiş IP dış API'lere gönderilmez.")
    return addr


def flatten_rdap(data: dict[str, Any]) -> dict[str, Any]:
    events = []
    for event in data.get("events") or []:
        events.append({"type": event.get("eventAction"), "date": event.get("eventDate")})
    nameservers = [entry.get("ldhName") for entry in data.get("nameservers") or [] if entry.get("ldhName")]
    entities = []
    for entity in data.get("entities") or []:
        name = None
        vcard = entity.get("vcardArray")
        if isinstance(vcard, list) and len(vcard) > 1:
            for item in vcard[1]:
                if len(item) >= 4 and item[0] in {"fn", "org"}:
                    name = str(item[3]); break
        roles = entity.get("roles") or []
        if roles or name:
            entities.append({"roles": roles, "name": name})
    return {"objectClassName": data.get("objectClassName"), "handle": data.get("handle"), "ldhName": data.get("ldhName"),
            "name": data.get("name"), "country": data.get("country"), "status": data.get("status") or [],
            "events": events[:30], "nameservers": nameservers[:80], "entities": entities[:20], "port43": data.get("port43")}


@app.get("/")
async def home() -> FileResponse:
    return FileResponse(ROOT / "index.html")


@app.get("/api/health")
async def health() -> dict[str, Any]:
    try:
        import maigret  # noqa: F401
        installed = True
    except Exception:
        installed = False
    return {"ok": True, "app": "NEX OSINT Pro", "version": "1.1.0", "maigret_available": installed,
            "time": now(), "mode": "live public sources; no fabricated results"}


@app.get("/api/ip")
async def ip_lookup(target: str = Query(min_length=3, max_length=253)) -> dict[str, Any]:
    target = target.strip()
    try:
        ip = str(parse_public_ip(target))
        submitted_domain = None
    except HTTPException as exc:
        if exc.status_code != 400 or re.search(r"[\s/?#]", target):
            raise
        submitted_domain = clean_domain(target)
        try:
            answers = await asyncio.get_running_loop().getaddrinfo(submitted_domain, None, type=socket.SOCK_STREAM)
            ips = list(dict.fromkeys(info[4][0] for info in answers))
            global_ips = [candidate for candidate in ips if ipaddress.ip_address(candidate).is_global]
            if not global_ips:
                raise HTTPException(502, "Alan adı genel bir IP'ye çözümlenmedi.")
            ip = global_ips[0]
        except HTTPException:
            raise
        except Exception as error:
            raise HTTPException(502, f"Domain DNS çözümlemesi başarısız: {error}") from error
    async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=True, headers={"User-Agent": UA}) as client:
        try:
            response = await client.get(f"https://ipwho.is/{quote(ip, safe='')}")
            response.raise_for_status(); data = response.json()
        except Exception as error:
            raise HTTPException(502, f"ipwho.is sorgusu başarısız: {error}") from error
    if not data.get("success", True):
        raise HTTPException(502, str(data.get("message") or "IP kaynağı yanıt vermedi."))
    connection = data.get("connection") or {}; timezone_data = data.get("timezone") or {}
    result = {"ok": True, "query": target, "ip": data.get("ip"), "type": data.get("type"), "continent": data.get("continent"),
              "country": data.get("country"), "country_code": data.get("country_code"), "region": data.get("region"),
              "city": data.get("city"), "postal": data.get("postal"), "latitude": data.get("latitude"), "longitude": data.get("longitude"),
              "flag": (data.get("flag") or {}).get("emoji"), "timezone": timezone_data.get("id"), "utc_offset": timezone_data.get("utc"),
              "asn": connection.get("asn"), "org": connection.get("org"), "isp": connection.get("isp"), "domain": connection.get("domain"),
              "source": "ipwho.is", "source_url": f"https://ipwho.is/{quote(ip, safe='')}", "queried_at": now(),
              "accuracy_note": "IP geolocation is approximate network metadata, not a person's exact GPS or home address."}
    if submitted_domain: result["resolved_domain"] = submitted_domain
    return result


async def dns_answer(client: httpx.AsyncClient, domain: str, record_type: str) -> list[dict[str, Any]]:
    response = await client.get("https://cloudflare-dns.com/dns-query", params={"name": domain, "type": record_type}, headers={"Accept": "application/dns-json"})
    response.raise_for_status(); payload = response.json()
    output = []
    for row in payload.get("Answer") or []:
        output.append({"name": str(row.get("name", "")).rstrip("."), "type": record_type, "value": str(row.get("data", "")), "ttl": row.get("TTL")})
    return output


@app.get("/api/dns")
async def dns_lookup(domain: str = Query(min_length=3, max_length=253)) -> dict[str, Any]:
    domain = clean_domain(domain)
    types = ["A", "AAAA", "MX", "NS", "CNAME", "SOA", "CAA", "TXT"]
    async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=True, headers={"User-Agent": UA}) as client:
        outcomes = await asyncio.gather(*(dns_answer(client, domain, kind) for kind in types), return_exceptions=True)
    records, errors = [], []
    for kind, outcome in zip(types, outcomes):
        if isinstance(outcome, Exception): errors.append({"type": kind, "error": str(outcome)})
        else: records.extend(outcome)
    if errors and not records:
        raise HTTPException(502, "DNS kaynağından kayıt alınamadı: " + "; ".join(f"{x['type']}: {x['error']}" for x in errors[:3]))
    return {"ok": True, "domain": domain, "records": records, "record_types": types, "partial_errors": errors,
            "source": "Cloudflare DNS over HTTPS", "source_url": "https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/", "queried_at": now()}


@app.get("/api/rdap")
async def rdap_lookup(target: str = Query(min_length=3, max_length=253)) -> dict[str, Any]:
    target = target.strip()
    try:
        ip = str(parse_public_ip(target)); path = "ip/" + quote(ip, safe=":")
    except HTTPException as exc:
        if exc.status_code != 400 or re.search(r"[\s/?#]", target): raise
        domain = clean_domain(target); path = "domain/" + quote(domain, safe=""); target = domain
    url = "https://rdap.org/" + path
    async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=True, headers={"User-Agent": UA, "Accept": "application/rdap+json, application/json"}) as client:
        try:
            response = await client.get(url); response.raise_for_status(); payload = response.json()
        except httpx.HTTPStatusError as error:
            raise HTTPException(502 if error.response.status_code >= 500 else 404, f"RDAP yanıtı: HTTP {error.response.status_code}") from error
        except Exception as error: raise HTTPException(502, f"RDAP sorgusu başarısız: {error}") from error
    return {"ok": True, "query": target, "rdap": flatten_rdap(payload), "source": "RDAP registry data", "source_url": url, "raw_url": url, "queried_at": now()}


@app.get("/api/certificates")
async def certificate_lookup(domain: str = Query(min_length=3, max_length=253)) -> dict[str, Any]:
    domain = clean_domain(domain)
    async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=True, headers={"User-Agent": UA}) as client:
        try:
            response = await client.get("https://crt.sh/", params={"q": f"%.{domain}", "output": "json"}); response.raise_for_status(); raw = response.json()
        except Exception as error: raise HTTPException(502, f"crt.sh sorgusu başarısız: {error}") from error
    items, names = [], set()
    for row in raw if isinstance(raw, list) else []:
        name = str(row.get("name_value") or "").strip()
        for host in name.splitlines():
            host = host.strip().lower().lstrip("*.").rstrip(".")
            if host == domain or host.endswith("." + domain): names.add(host)
        items.append({"id": row.get("id"), "issuer": row.get("issuer_name"), "common_name": row.get("common_name"), "name_value": name,
                      "not_before": row.get("not_before"), "not_after": row.get("not_after"), "entry_timestamp": row.get("entry_timestamp")})
    certificates = sorted(items, key=lambda x: str(x.get("entry_timestamp") or ""), reverse=True)[:200]
    hostnames = sorted(names)[:250]
    return {"ok": True, "domain": domain, "certificates": certificates, "hostnames": hostnames, "unique_hosts": len(names),
            "source": "crt.sh Certificate Transparency", "source_url": "https://crt.sh/?q=" + quote(f"%.{domain}", safe=""), "queried_at": now(),
            "note": "Certificate logs record historical issuance; a hostname may not be active today."}


@app.get("/api/telegram")
async def telegram_lookup(username: str = Query(min_length=2, max_length=40)) -> dict[str, Any]:
    username = clean_username(username)
    base = f"https://t.me/{quote(username, safe='')}"
    profile: dict[str, Any] = {}
    posts: list[dict[str, Any]] = []
    async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=True, headers={"User-Agent": "Mozilla/5.0 (compatible; NEX-OSINT/1.0; public-page-preview)"}) as client:
        try:
            response = await client.get(base)
            if response.status_code == 404: raise HTTPException(404, "Telegram herkese açık önizlemesinde bu username bulunamadı.")
            response.raise_for_status(); soup = BeautifulSoup(response.text, "html.parser")
            title = soup.find("meta", attrs={"property": "og:title"}); description = soup.find("meta", attrs={"property": "og:description"})
            image = soup.find("meta", attrs={"property": "og:image"}); page_title = soup.select_one(".tgme_page_title"); extra = soup.select_one(".tgme_page_extra"); desc = soup.select_one(".tgme_page_description")
            profile = {"username": username, "title": (title.get("content") if title else None) or (page_title.get_text(" ", strip=True) if page_title else None),
                       "description": (description.get("content") if description else None) or (desc.get_text(" ", strip=True) if desc else None),
                       "page_extra": extra.get_text(" ", strip=True) if extra else None,
                       "image_url": image.get("content") if image else None, "canonical_url": base, "http_status": response.status_code,
                       "page_title": soup.title.get_text(" ", strip=True) if soup.title else None}
            # Public channel preview is optional; Telegram may return no posts for personal profile pages.
            try:
                public = await client.get(f"https://t.me/s/{quote(username, safe='')}")
                if public.status_code < 400:
                    feed = BeautifulSoup(public.text, "html.parser")
                    for node in feed.select(".tgme_widget_message")[:30]:
                        text_node = node.select_one(".tgme_widget_message_text")
                        date_node = node.select_one(".tgme_widget_message_date")
                        views_node = node.select_one(".tgme_widget_message_views")
                        link_node = date_node.find("a") if date_node else None
                        posts.append({"text": text_node.get_text(" ", strip=True) if text_node else "[Text not shown]",
                                      "date": link_node.get("datetime") if link_node else None,
                                      "url": link_node.get("href") if link_node else None,
                                      "views": views_node.get_text(" ", strip=True) if views_node else None})
            except Exception as error: log.info("Public Telegram channel preview unavailable for %s: %s", username, error)
        except HTTPException: raise
        except Exception as error: raise HTTPException(502, f"Telegram public page sorgusu başarısız: {error}") from error
    return {"ok": True, "username": username, "profile": profile, "public_posts": posts, "page_kind": "public_web_preview",
            "source": "Telegram public web preview", "source_url": base, "queried_at": now(),
            "note": "Only fields/posts returned by the public web preview are shown. This does not access private Telegram data."}


@app.get("/api/github")
async def github_lookup(username: str = Query(min_length=1, max_length=39)) -> dict[str, Any]:
    username = username.strip()
    if not re.fullmatch(r"[A-Za-z0-9-]{1,39}", username): raise HTTPException(400, "Geçerli bir GitHub kullanıcı adı gir.")
    headers = {"User-Agent": UA, "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=True, headers=headers) as client:
        try:
            profile_response = await client.get(f"https://api.github.com/users/{quote(username, safe='')}")
            if profile_response.status_code == 404: raise HTTPException(404, "GitHub public API bu kullanıcıyı bulamadı.")
            profile_response.raise_for_status(); raw = profile_response.json()
            repos_response = await client.get(f"https://api.github.com/users/{quote(username, safe='')}/repos", params={"sort": "updated", "per_page": 12, "type": "owner"})
            repos_response.raise_for_status(); repos_raw = repos_response.json()
        except HTTPException: raise
        except Exception as error: raise HTTPException(502, f"GitHub API sorgusu başarısız: {error}") from error
    profile = {key: raw.get(key) for key in ["login", "name", "html_url", "avatar_url", "bio", "company", "blog", "location", "twitter_username", "public_repos", "public_gists", "followers", "following", "created_at", "updated_at"]}
    repos = [{"name": r.get("name"), "html_url": r.get("html_url"), "description": r.get("description"), "language": r.get("language"),
              "stargazers_count": r.get("stargazers_count"), "forks_count": r.get("forks_count"), "updated_at": r.get("updated_at"), "default_branch": r.get("default_branch")} for r in repos_raw]
    return {"ok": True, "username": username, "profile": profile, "recent_repositories": repos, "source": "GitHub REST API", "source_url": raw.get("html_url"), "queried_at": now()}


@app.get("/api/username")
async def username_lookup(username: str = Query(min_length=2, max_length=40), depth: str = Query(default="standard", pattern="^(quick|standard|extended)$")) -> dict[str, Any]:
    username = clean_username(username)
    try:
        from maigret import search as maigret_search
        from maigret.sites import MaigretDatabase
    except Exception as error:
        raise HTTPException(503, "Maigret kurulu değil. README'deki `pip install -r requirements.txt` adımını uygula.") from error
    top = {"quick": 100, "standard": 500, "extended": 1000}[depth]
    try:
        db = MaigretDatabase().load_from_path("maigret/resources/data.json")
        sites = db.ranked_sites_dict(top=top)
        if not sites: raise RuntimeError("Maigret site veritabanı boş.")
        logger = logging.getLogger("maigret.search")
        results = await asyncio.wait_for(maigret_search(username=username, site_dict=sites, logger=logger, timeout=12, is_parsing_enabled=True), timeout=240)
    except asyncio.TimeoutError as error:
        raise HTTPException(504, "Maigret taraması zaman aşımına uğradı. Daha düşük tarama derinliği seç.") from error
    except Exception as error:
        log.exception("Maigret scan failed")
        raise HTTPException(502, f"Maigret gerçek taraması çalışmadı: {type(error).__name__}: {error}") from error
    found, uncertain, checked = [], [], 0
    for site, item in results.items():
        checked += 1
        status = item.get("status")
        status_name = getattr(status, "name", None) or str(status or "UNKNOWN")
        row = {"site": str(site), "url": item.get("url_user"), "http_status": item.get("http_status"), "rank": item.get("rank"), "status": status_name,
               "ids_data": item.get("ids_data") or {}}
        try: is_found = bool(status and status.is_found())
        except Exception: is_found = "FOUND" in status_name.upper()
        if is_found: found.append(row)
        elif any(term in status_name.upper() for term in ("UNKNOWN", "MAYBE", "ERROR", "BLOCK")): uncertain.append(row)
    return {"ok": True, "username": username, "depth": depth, "sites_requested": top, "sites_checked": checked,
            "summary": {"found": len(found), "uncertain": len(uncertain), "checked": checked}, "found": found[:300], "uncertain": uncertain[:200],
            "source": "Maigret open-source engine", "source_url": "https://github.com/soxoj/maigret", "queried_at": now(),
            "note": "Profile matches are leads, not proof that accounts belong to the same person. False positives, blocks, and timeouts are possible."}


@app.get("/api/urlscan")
async def urlscan_lookup(domain: str = Query(min_length=3, max_length=253), size: int = Query(default=20, ge=1, le=100)) -> dict[str, Any]:
    domain = clean_domain(domain)
    async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=True, headers={"User-Agent": UA, "Accept": "application/json"}) as client:
        try:
            response = await client.get("https://urlscan.io/api/v1/search/", params={"q": f"domain:{domain}", "size": size}); response.raise_for_status(); payload = response.json()
        except httpx.HTTPStatusError as error:
            code = error.response.status_code
            if code == 429: detail = "urlscan.io rate limit (429). Bekle ve daha sonra tekrar dene."
            elif code in (401, 403): detail = f"urlscan.io erişimi HTTP {code} döndürdü; servis anonim aramayı kısıtlıyor olabilir."
            else: detail = f"urlscan.io yanıtı HTTP {code}."
            raise HTTPException(502, detail) from error
        except Exception as error: raise HTTPException(502, f"urlscan.io sorgusu başarısız: {error}") from error
    scans = []
    for row in payload.get("results") or []:
        page = row.get("page") or {}; task = row.get("task") or {}
        scans.append({"url": page.get("url"), "domain": page.get("domain"), "title": page.get("title"), "ip": page.get("ip"),
                      "country": page.get("country"), "server": page.get("server"), "status": page.get("status"), "time": task.get("time"),
                      "uuid": task.get("uuid"), "result_url": task.get("result"), "screenshot": task.get("screenshot")})
    return {"ok": True, "domain": domain, "total": payload.get("total", len(scans)), "results": scans, "source": "urlscan.io public search API",
            "source_url": "https://urlscan.io/search/#" + quote(f"domain:{domain}", safe=""), "queried_at": now(),
            "note": "These are historical public scans and do not guarantee the current state of any site."}


@app.get("/api/search-links")
async def search_links(query: str = Query(min_length=1, max_length=250)) -> dict[str, Any]:
    query = query.strip()
    if not query: raise HTTPException(400, "Arama terimi boş olamaz.")
    q = quote(query, safe="")
    links = [
        {"name": "Google", "url": f"https://www.google.com/search?q={q}", "purpose": "Web search"},
        {"name": "DuckDuckGo", "url": f"https://duckduckgo.com/?q={q}", "purpose": "Web search"},
        {"name": "Bing", "url": f"https://www.bing.com/search?q={q}", "purpose": "Web search"},
        {"name": "Brave Search", "url": f"https://search.brave.com/search?q={q}", "purpose": "Web search"},
        {"name": "GitHub code/repositories", "url": f"https://github.com/search?q={q}&type=repositories", "purpose": "Open-source projects"},
        {"name": "Reddit", "url": f"https://www.reddit.com/search/?q={q}", "purpose": "Public discussions"},
        {"name": "Telegram public", "url": f"https://www.google.com/search?q=site%3At.me+{q}", "purpose": "Public Telegram pages"},
        {"name": "Certificate Transparency", "url": f"https://crt.sh/?q={q}", "purpose": "Certificate log search"},
        {"name": "urlscan.io", "url": f"https://urlscan.io/search/#{q}", "purpose": "Public web scan archive"},
    ]
    return {"ok": True, "query": query, "links": links, "source": "Search engine destination links", "source_url": "https://duckduckgo.com/", "queried_at": now(),
            "note": "This module creates links to actual search pages; it does not scrape or fabricate search results."}


@app.get("/api/sources")
async def sources() -> dict[str, Any]:
    return {"ok": True, "sources": [
        {"name": "Maigret", "type": "Open-source username scan", "url": "https://github.com/soxoj/maigret", "integrated": True},
        {"name": "Telegram public web", "type": "Public page preview", "url": "https://t.me/", "integrated": True},
        {"name": "ipwho.is", "type": "IP / network metadata", "url": "https://ipwho.is/documentation", "integrated": True},
        {"name": "Cloudflare DNS over HTTPS", "type": "DNS records", "url": "https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/", "integrated": True},
        {"name": "RDAP", "type": "Registry data", "url": "https://rdap.org/", "integrated": True},
        {"name": "crt.sh", "type": "Certificate Transparency", "url": "https://crt.sh/", "integrated": True},
        {"name": "GitHub REST API", "type": "Public profile/repositories", "url": "https://docs.github.com/en/rest", "integrated": True},
        {"name": "urlscan.io", "type": "Public scan search", "url": "https://urlscan.io/docs/", "integrated": True},
        {"name": "Have I Been Pwned", "type": "API key needed for account search", "url": "https://haveibeenpwned.com/API/V3", "integrated": False},
    ]}

# Optional end-to-end encrypted sync: server stores ciphertext plus a one-way proof hash only.
SYNC_DB = Path(os.environ.get("NEX_SYNC_DB_PATH", str(ROOT / "data" / "sync.sqlite3"))).expanduser()
class SyncEnvelope(BaseModel):
    v: int = Field(ge=1, le=1)
    nonce: str = Field(min_length=16, max_length=32, pattern=r"^[A-Za-z0-9_-]+$")
    ciphertext: str = Field(min_length=24, max_length=4_000_000, pattern=r"^[A-Za-z0-9_-]+$")


def validate_sync_id(value: str) -> str:
    try: parsed = uuid.UUID(value)
    except (ValueError, AttributeError) as exc: raise HTTPException(400, "Geçersiz sync workspace ID.") from exc
    canonical = str(parsed)
    if canonical != value.lower(): raise HTTPException(400, "Sync workspace ID biçimi geçersiz.")
    return canonical


def connect_sync_db() -> sqlite3.Connection:
    SYNC_DB.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(SYNC_DB), timeout=5)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("CREATE TABLE IF NOT EXISTS encrypted_sync (workspace_id TEXT PRIMARY KEY, proof_hash TEXT NOT NULL, version INTEGER NOT NULL, nonce TEXT NOT NULL, ciphertext TEXT NOT NULL, updated_at TEXT NOT NULL)")
    return conn


def sync_proof_hash(proof: str | None) -> str:
    if not proof or not re.fullmatch(r"[A-Za-z0-9_-]{40,64}", proof): raise HTTPException(401, "Sync pairing proof eksik veya geçersiz.")
    return hashlib.sha256(proof.encode("ascii")).hexdigest()


@app.get("/api/sync/{workspace_id}")
def get_sync_workspace(workspace_id: str, x_sync_proof: str | None = Header(default=None, alias="X-Sync-Proof")) -> dict[str, Any]:
    workspace_id = validate_sync_id(workspace_id); supplied = sync_proof_hash(x_sync_proof); conn = connect_sync_db()
    try: row = conn.execute("SELECT proof_hash,version,nonce,ciphertext,updated_at FROM encrypted_sync WHERE workspace_id=?", (workspace_id,)).fetchone()
    finally: conn.close()
    if row is None: raise HTTPException(404, "Sync workspace henüz oluşturulmamış.")
    if not hmac.compare_digest(row[0], supplied): raise HTTPException(403, "Pairing proof eşleşmedi.")
    return {"ok": True, "workspace_id": workspace_id, "envelope": {"v": row[1], "nonce": row[2], "ciphertext": row[3]}, "updated_at": row[4], "encrypted": True}


@app.put("/api/sync/{workspace_id}")
def put_sync_workspace(workspace_id: str, envelope: SyncEnvelope, x_sync_proof: str | None = Header(default=None, alias="X-Sync-Proof")) -> dict[str, Any]:
    workspace_id = validate_sync_id(workspace_id); supplied = sync_proof_hash(x_sync_proof); timestamp = now(); conn = connect_sync_db()
    try:
        row = conn.execute("SELECT proof_hash FROM encrypted_sync WHERE workspace_id=?", (workspace_id,)).fetchone()
        if row is None:
            conn.execute("INSERT INTO encrypted_sync(workspace_id,proof_hash,version,nonce,ciphertext,updated_at) VALUES(?,?,?,?,?,?)", (workspace_id, supplied, envelope.v, envelope.nonce, envelope.ciphertext, timestamp))
        else:
            if not hmac.compare_digest(row[0], supplied): raise HTTPException(403, "Pairing proof eşleşmedi.")
            conn.execute("UPDATE encrypted_sync SET version=?,nonce=?,ciphertext=?,updated_at=? WHERE workspace_id=?", (envelope.v, envelope.nonce, envelope.ciphertext, timestamp, workspace_id))
        conn.commit()
    finally: conn.close()
    return {"ok": True, "workspace_id": workspace_id, "updated_at": timestamp, "encrypted": True}


@app.exception_handler(Exception)
async def handle_unexpected(request, exc: Exception):
    log.exception("Unhandled exception on %s", request.url.path)
    return JSONResponse(status_code=500, content={"detail": "Beklenmeyen sunucu hatası. Terminal günlüğünü kontrol et."})

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="127.0.0.1", port=8000, reload=False)
