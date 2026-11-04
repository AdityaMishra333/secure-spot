"""Package Scanner: checks npm dependencies using NPMScan's public API.

API docs: https://npmscan.com/api

Only package names and version specs leave this server. Git, file and URL
dependencies are never sent, because those values can contain private paths or
access tokens. Nothing submitted is stored; the cache below holds only API
results, in memory.
"""
import json
import re
import threading
import time
import urllib.error
import urllib.request
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import quote

API_BASE = "https://npmscan.com/api"
USER_AGENT = "SecureSpot/1.0"

MAX_INPUT_BYTES = 1024 * 1024
MAX_RESPONSE_BYTES = 32 * 1024 * 1024
MAX_PACKAGES = 300
# NPMScan allows 30 requests a minute per IP, and all visitors share this
# server's IP. Install script checks take one request per package.
MAX_SCRIPT_CHECKS_PER_SCAN = 15
REQUESTS_PER_MINUTE = 25
CACHE_TTL_SECONDS = 30 * 60
CACHE_MAX_ENTRIES = 2000

NAME_RE = re.compile(r"^(@[a-z0-9~-][a-z0-9._~-]*/)?[a-z0-9~-][a-z0-9._~-]*$", re.I)
EXACT_VERSION_RE = re.compile(r"^[=v]?(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.+-]+)?)$")
REGISTRY_SPEC_RE = re.compile(r"^[\w.+*^~<>=| -]{1,64}$")
ADVISORY_ID_RE = re.compile(r"^[A-Za-z0-9-]{1,64}$")
MALICIOUS_RE = re.compile(
    r"malicious (code|package)|embedded malware|^malware\b", re.I
)
SHELL_PIPE_RE = re.compile(
    r"(curl|wget)\b[^|]*\|\s*(sudo\s+)?(sh|bash|zsh)\b|\b(iwr|invoke-webrequest)\b.*\b(iex|invoke-expression)\b",
    re.I,
)

DEPENDENCY_GROUPS = (
    ("dependencies", "production"),
    ("optionalDependencies", "optional"),
    ("devDependencies", "development"),
)
INSTALL_HOOKS = ("preinstall", "install", "postinstall")

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MODERATE": 2, "LOW": 3, "UNKNOWN": 4}
SEVERITY_POINTS = {"CRITICAL": 40, "HIGH": 25, "MODERATE": 10, "LOW": 5, "UNKNOWN": 10}
SCRIPT_TIER_POINTS = {"none": 0, "low": 5, "moderate": 15, "high": 40, "critical": 70}
TYPOSQUAT_MIN_POINTS = 30

LABELS = {
    "high": "HIGH RISK - Serious problems were found",
    "medium": "MEDIUM RISK - Review these packages before installing",
    "low": "LOW RISK - A few things are worth checking",
    "incomplete": "INCOMPLETE - Some packages could not be checked",
    "safe": "NO KNOWN ISSUES - Nothing was flagged in the packages checked",
}


class ScanError(Exception):
    """A problem to show the user, with a message that is safe to display."""


class ApiUnavailable(Exception):
    """NPMScan could not be reached, refused the request, or is rate limiting."""


class PackageNotFound(Exception):
    """NPMScan answered 404 for this package or version."""


class _RateLimiter:
    """Keeps this server under NPMScan's per-IP limit for each endpoint group."""

    def __init__(self, per_minute):
        self.per_minute = per_minute
        self.lock = threading.Lock()
        self.calls = {}
        self.blocked_until = {}

    def acquire(self, group):
        now = time.monotonic()
        with self.lock:
            if now < self.blocked_until.get(group, 0):
                return False
            calls = self.calls.setdefault(group, deque())
            while calls and now - calls[0] >= 60:
                calls.popleft()
            if len(calls) >= self.per_minute:
                return False
            calls.append(now)
            return True

    def block(self, group, seconds):
        with self.lock:
            self.blocked_until[group] = time.monotonic() + seconds


class _Cache:
    """Small in-memory cache, so repeat scans don't spend the rate limit."""

    def __init__(self, ttl, max_entries):
        self.ttl = ttl
        self.max_entries = max_entries
        self.lock = threading.Lock()
        self.entries = {}

    def get(self, key):
        with self.lock:
            entry = self.entries.get(key)
            if entry is None:
                return None
            if time.monotonic() >= entry[0]:
                del self.entries[key]
                return None
            return entry[1]

    def set(self, key, value):
        with self.lock:
            if len(self.entries) >= self.max_entries:
                self.entries.pop(next(iter(self.entries)))
            self.entries[key] = (time.monotonic() + self.ttl, value)


_limiter = _RateLimiter(REQUESTS_PER_MINUTE)
_cache = _Cache(CACHE_TTL_SECONDS, CACHE_MAX_ENTRIES)


def _post(path, body, group, timeout):
    if not _limiter.acquire(group):
        raise ApiUnavailable("rate limit")

    request = urllib.request.Request(
        API_BASE + path,
        data=json.dumps(body).encode("utf-8"),
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "application/json",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read(MAX_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as error:
        if error.code == 404:
            raise PackageNotFound() from error
        if error.code == 429:
            retry_after = error.headers.get("Retry-After", "")
            _limiter.block(group, int(retry_after) if retry_after.isdigit() else 60)
        raise ApiUnavailable(f"HTTP {error.code}") from error
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        raise ApiUnavailable("network error") from error

    if len(raw) > MAX_RESPONSE_BYTES:
        raise ApiUnavailable("response too large")
    try:
        data = json.loads(raw)
    except ValueError as error:
        raise ApiUnavailable("invalid response") from error
    if not isinstance(data, dict):
        raise ApiUnavailable("invalid response")
    return data


# ---------------- Reading the input ----------------
def read_upload(raw):
    if len(raw) > MAX_INPUT_BYTES:
        raise ScanError("That file is too large. The limit is 1 MB.")
    try:
        return raw.decode("utf-8-sig")
    except UnicodeDecodeError as error:
        raise ScanError("That doesn't look like a text file. Upload a package.json file.") from error


def parse_input(text):
    """Returns (packages, not_checked, project_findings) from pasted text."""
    text = (text or "").strip()
    if not text:
        raise ScanError("Paste a package.json, type a package name, or choose a file.")
    if text.startswith("{"):
        return _parse_package_json(text)
    return _parse_package_name(text)


def _parse_package_name(text):
    name, separator, spec = text.rpartition("@")
    # "lodash" and "@scope/pkg" have no version; the "@" in the second is the scope.
    if not separator or not name:
        name, spec = text, "latest"
    if len(name) > 214 or not NAME_RE.match(name) or not REGISTRY_SPEC_RE.match(spec):
        raise ScanError(
            "That doesn't look like a package name or a package.json. "
            "Try a name like lodash or lodash@4.17.21."
        )
    return [{"name": name, "spec": spec, "group": "package"}], [], []


def _parse_package_json(text):
    try:
        data = json.loads(text)
    except (ValueError, RecursionError) as error:
        raise ScanError("That isn't valid JSON. Check that you copied the whole package.json.") from error
    if not isinstance(data, dict):
        raise ScanError("That isn't a package.json file.")
    if "lockfileVersion" in data:
        raise ScanError("Lockfiles aren't supported yet. Upload your package.json instead.")

    packages, not_checked, seen = [], [], set()
    for field, group in DEPENDENCY_GROUPS:
        dependencies = data.get(field)
        if not isinstance(dependencies, dict):
            continue
        for name, spec in dependencies.items():
            if name in seen:
                continue
            seen.add(name)
            reason = _unscannable_reason(name, spec)
            if reason:
                not_checked.append({"name": str(name)[:214], "version": "", "reason": reason})
            elif len(packages) >= MAX_PACKAGES:
                not_checked.append({
                    "name": name,
                    "version": "",
                    "reason": f"Only the first {MAX_PACKAGES} packages are checked in one scan.",
                })
            else:
                packages.append({"name": name, "spec": spec.strip(), "group": group})

    peers = data.get("peerDependencies")
    if isinstance(peers, dict):
        for name in peers:
            if name not in seen:
                seen.add(name)
                not_checked.append({
                    "name": str(name)[:214],
                    "version": "",
                    "reason": "Peer dependency: the installed version depends on the project using this package.",
                })

    project_findings = _check_project_scripts(data.get("scripts"))
    if not seen and not project_findings:
        raise ScanError("No dependencies were found in that package.json.")
    return packages, not_checked, project_findings


def _unscannable_reason(name, spec):
    if not isinstance(name, str) or len(name) > 214 or not NAME_RE.match(name):
        return "This isn't a valid npm package name."
    if not isinstance(spec, str):
        return "This dependency has an invalid version."
    if not REGISTRY_SPEC_RE.match(spec.strip()):
        return "Installed from Git, a URL, a local path or an alias, not the npm registry. Review it by hand."
    return None


def _check_project_scripts(scripts):
    findings = []
    if not isinstance(scripts, dict):
        return findings
    for hook in INSTALL_HOOKS:
        command = scripts.get(hook)
        if not isinstance(command, str):
            continue
        if SHELL_PIPE_RE.search(command):
            findings.append({
                "severity": "high",
                "points": 40,
                "text": f"The {hook} script downloads code and runs it immediately",
                "snippet": command[:160],
            })
        else:
            findings.append({
                "severity": "low",
                "points": 5,
                "text": f"The {hook} script runs automatically during npm install. Check that you trust it",
                "snippet": command[:160],
            })
    return findings


# ---------------- Known vulnerabilities ----------------
def _normalize_vulnerability(raw, highest):
    database = raw.get("database_specific")
    severity = database.get("severity") if isinstance(database, dict) else None
    severity = str(severity or highest or "UNKNOWN").upper()
    if severity == "MEDIUM":
        severity = "MODERATE"
    if severity not in SEVERITY_ORDER:
        severity = "UNKNOWN"

    advisory_id = str(raw.get("id") or "")
    summary = str(raw.get("summary") or raw.get("details") or "No description was provided.")
    fixed = raw.get("fixedVersion")
    valid_id = ADVISORY_ID_RE.match(advisory_id) is not None
    return {
        "id": advisory_id[:64],
        "summary": summary[:240],
        "severity": severity,
        "fixed": str(fixed)[:64] if fixed else None,
        "malicious": advisory_id.upper().startswith("MAL-") or bool(MALICIOUS_RE.search(summary)),
        "url": f"https://osv.dev/vulnerability/{advisory_id}" if valid_id else None,
    }


def _normalize_result(raw):
    package = raw.get("package") if isinstance(raw.get("package"), dict) else {}
    vulnerabilities = [
        _normalize_vulnerability(item, raw.get("highestSeverity"))
        for item in (raw.get("vulns") or [])
        if isinstance(item, dict)
    ]
    vulnerabilities.sort(key=lambda item: SEVERITY_ORDER[item["severity"]])
    return {
        "version": str(package.get("version") or "")[:64],
        "scanned": raw.get("scanStatus") == "scanned",
        "on_registry": raw.get("registryStatus") == "found",
        "vulnerabilities": vulnerabilities,
    }


def _query_vulnerabilities(packages):
    """Looks up one batch. Anything missing from the reply stays unchecked."""
    if not packages:
        return {}

    # Exact versions go in the packages form: the package.json form skips
    # versions no longer on npm, which is how removed malware is reported.
    exact = [p for p in packages if EXACT_VERSION_RE.match(p["spec"])]
    ranged = [p for p in packages if not EXACT_VERSION_RE.match(p["spec"])]
    results = {}

    if exact:
        body = {"packages": [
            {"name": p["name"], "version": EXACT_VERSION_RE.match(p["spec"]).group(1)}
            for p in exact
        ]}
        results.update(_read_batch(body))
    if ranged:
        # Send names and ranges only, never the rest of the user's package.json.
        # Everything goes under "dependencies" because the API skips other groups.
        content = {
            "name": "scan",
            "version": "0.0.0",
            "dependencies": {p["name"]: p["spec"] for p in ranged},
        }
        results.update(_read_batch({"content": json.dumps(content)}))
    return results


def _read_batch(body):
    try:
        data = _post("/osv/batch", body, "osv", timeout=45)
    except PackageNotFound as error:
        raise ApiUnavailable("HTTP 404") from error
    results = {}
    for raw in data.get("results") or []:
        if isinstance(raw, dict) and isinstance(raw.get("package"), dict):
            results[raw["package"].get("name")] = _normalize_result(raw)
    return results


def _check_vulnerabilities(packages):
    """Returns {name: result}. Raises ApiUnavailable if a lookup fails."""
    results, uncached = {}, []
    for package in packages:
        cached = _cache.get(("osv", package["name"], package["spec"]))
        if cached is not None:
            results[package["name"]] = cached
        else:
            uncached.append(package)

    fresh = _query_vulnerabilities(uncached)
    for package in uncached:
        result = fresh.get(package["name"])
        if result is not None:
            _cache.set(("osv", package["name"], package["spec"]), result)
            results[package["name"]] = result
    return results


# ---------------- Install script checks ----------------
def _check_install_script(name, version):
    """Returns a result dict, or None if the check couldn't be completed."""
    cache_key = ("script", name, version)
    cached = _cache.get(cache_key)
    if cached is not None:
        return cached
    try:
        data = _post("/analysis/install-script", {"name": name, "version": version}, "analysis", timeout=20)
    except (ApiUnavailable, PackageNotFound):
        return None

    findings = []
    for raw in data.get("findings") or []:
        # Lookalike names are reported through possibleTyposquatOf instead.
        if not isinstance(raw, dict) or raw.get("rule") == "typosquat":
            continue
        locations = raw.get("locations") if isinstance(raw.get("locations"), list) else []
        location = locations[0] if locations and isinstance(locations[0], dict) else {}
        findings.append({
            "text": str(raw.get("text") or raw.get("rule") or "Suspicious pattern")[:160],
            "file": str(location.get("file") or "")[:120],
            "snippet": str(location.get("snippet") or "")[:160],
        })

    typosquat = data.get("possibleTyposquatOf")
    total = data.get("totalScore") if isinstance(data.get("totalScore"), (int, float)) else 0
    result = {
        "tier": str(data.get("riskTier") or "none").lower(),
        "total": total,
        "findings": findings,
        "typosquat_of": str(typosquat.get("name"))[:214] if isinstance(typosquat, dict) and typosquat.get("name") else None,
    }
    _cache.set(cache_key, result)
    return result


def _check_install_scripts(packages):
    """Returns {name: result or None}, running at most the per-scan limit of requests."""
    results, uncached, used = {}, [], 0
    for package in packages:
        cached = _cache.get(("script", package["name"], package["version"]))
        if cached is not None:
            results[package["name"]] = cached
        elif used < MAX_SCRIPT_CHECKS_PER_SCAN:
            uncached.append(package)
            used += 1
        else:
            results[package["name"]] = None

    if uncached:
        with ThreadPoolExecutor(max_workers=4) as pool:
            answers = pool.map(lambda p: _check_install_script(p["name"], p["version"]), uncached)
            for package, answer in zip(uncached, answers):
                results[package["name"]] = answer
    return results


# ---------------- Building the report ----------------
def _score(checked, project_findings):
    if any(v["malicious"] for p in checked for v in p["vulnerabilities"]):
        return 100
    points = sum(SEVERITY_POINTS[v["severity"]] for p in checked for v in p["vulnerabilities"])
    points += sum(f["points"] for f in project_findings)

    script_points = 0
    for package in checked:
        script = package.get("script")
        if not script:
            continue
        tier_points = SCRIPT_TIER_POINTS.get(script["tier"], min(script["total"], 100))
        if script["typosquat_of"]:
            tier_points = max(tier_points, TYPOSQUAT_MIN_POINTS)
        script_points = max(script_points, tier_points)
    return min(points + script_points, 100)


def _level(score, incomplete):
    if score >= 60:
        return "high"
    if score >= 30:
        return "medium"
    if score > 0:
        return "low"
    return "incomplete" if incomplete else "safe"


def _has_issue(package):
    script = package.get("script")
    return bool(package["vulnerabilities"]) or bool(script and (script["findings"] or script["typosquat_of"]))


def scan(text):
    """Runs a full scan of pasted text. Raises ScanError with a displayable message."""
    packages, not_checked, project_findings = parse_input(text)

    results = {}
    if packages:
        try:
            results = _check_vulnerabilities(packages)
        except ApiUnavailable as error:
            raise ScanError(
                "The scanning service is busy or unreachable, so nothing was checked. "
                "Please try again in a minute."
            ) from error

    checked = []
    for package in packages:
        result = results.get(package["name"])
        label = {"name": package["name"], "version": package["spec"]}
        if result is None:
            not_checked.append({**label, "reason": "The scanning service didn't return a result for this package."})
        elif not result["scanned"]:
            not_checked.append({**label, "reason": "This package or version couldn't be found on npm. Check the spelling, or it may be private or removed."})
        elif not result["on_registry"] and not result["vulnerabilities"]:
            not_checked.append({**label, "reason": "No known issues, but it isn't on npm. It may be a typo, private, or removed for containing malware. Don't treat this as safe."})
        else:
            checked.append({
                "name": package["name"],
                "version": result["version"] or package["spec"],
                "declared": package["spec"] if package["spec"] != result["version"] else None,
                "group": package["group"],
                "on_registry": result["on_registry"],
                "vulnerabilities": result["vulnerabilities"],
            })

    # Install scripts can only be read for packages npm still has.
    scriptable = [p for p in checked if p["on_registry"]]
    scripts = _check_install_scripts(scriptable)
    scripts_unchecked = 0
    for package in scriptable:
        package["script"] = scripts.get(package["name"])
        if package["script"] is None:
            scripts_unchecked += 1

    flagged = [p for p in checked if _has_issue(p)]
    flagged.sort(key=lambda p: min(
        (SEVERITY_ORDER[v["severity"]] for v in p["vulnerabilities"]),
        default=len(SEVERITY_ORDER),
    ))
    clean = [p for p in checked if not _has_issue(p) and p.get("script") is not None]
    for package in checked:
        if not _has_issue(package) and package.get("script") is None and package["on_registry"]:
            not_checked.append({
                "name": package["name"],
                "version": package["version"],
                "reason": "No known vulnerabilities, but its install script wasn't checked because of the limit per scan. Scan it on its own, or try again in a minute.",
            })

    score = _score(checked, project_findings)
    incomplete = bool(not_checked) or scripts_unchecked > 0
    level = _level(score, incomplete)
    return {
        "score": score,
        "level": level,
        "label": LABELS[level],
        "checked_count": len(clean) + len(flagged),
        "vulnerability_count": sum(len(p["vulnerabilities"]) for p in checked),
        "project_findings": project_findings,
        "flagged": flagged,
        "clean": clean,
        "not_checked": not_checked,
    }


def npmscan_url(name):
    return "https://npmscan.com/package/" + quote(name, safe="@/")
