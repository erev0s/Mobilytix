"""Security overview tool — smart triage for LLM-driven pentesting.

Instead of making the LLM grep for patterns one by one, this tool runs
~50 security-relevant patterns in a single pass and returns focused,
categorized code snippets the LLM can reason about directly.

Think of it as "here are the 30 most interesting code locations" —
the tool does the scanning, the LLM does the reasoning.

For *obfuscated* APKs the ripgrep source patterns miss renamed symbols.
The tool therefore supports a **bytecode** scan mode that uses androguard
cross-reference analysis on actual DEX method invocations — API calls to
Android/Java SDK can never be obfuscated away by ProGuard/R8.

Scan modes:
  - ``source``  — fast ripgrep-based source grep (default, < 1 s)
  - ``bytecode`` — androguard xref analysis on DEX (5-15 s, obfuscation-proof)
  - ``both``    — run both and merge results
"""

from __future__ import annotations

import json
import os
from typing import Any, Optional

from loguru import logger

from mcp_server.backends.local_backend import run_local
from mcp_server.models.session import AnalysisSession
from mcp_server.tools.base import BaseTool
from mcp_server.tools.static.code import _ensure_decompiled
from mcp_server.tools.static.routing import get_wrapper_only_warning
from mcp_server.tools.workspace import session_workspace

# Workspace helper
def _workspace_path(session: AnalysisSession) -> str:
    return str(session_workspace(session))


# ---------------------------------------------------------------------------
# Source-level patterns (ripgrep) — grouped by vulnerability category
# ---------------------------------------------------------------------------

SECURITY_PATTERNS: dict[str, list[dict]] = {
    "authentication": [
        {"pattern": r"password|passwd|pwd|credentials", "label": "Password/credential handling"},
        {"pattern": r"login|signIn|authenticate|doLogin", "label": "Login/auth flow"},
        {"pattern": r"setPassword|checkPassword|verifyPassword", "label": "Password verification"},
        {"pattern": r"SharedPreferences.*password|getPassword|savePassword", "label": "Password storage"},
        {"pattern": r"BiometricPrompt|fingerprint|FingerprintManager", "label": "Biometric auth"},
        {"pattern": r"sessionToken|accessToken|authToken|bearer", "label": "Token handling"},
    ],
    "crypto": [
        {"pattern": r"SecretKeySpec|Cipher\.getInstance|KeyGenerator", "label": "Encryption usage"},
        {"pattern": r"\"ECB\"|/ECB/", "label": "ECB mode (weak)"},
        {"pattern": r"\"DES\"|DESede|DES/", "label": "DES/3DES (weak)"},
        {"pattern": r"MessageDigest.*MD5|\.getInstance.*MD5", "label": "MD5 hash (weak)"},
        {"pattern": r"IvParameterSpec\s*\(\s*new\s+byte", "label": "Hardcoded IV"},
        {"pattern": r"SecureRandom.*setSeed", "label": "Seeded SecureRandom (predictable)"},
        {"pattern": r"Base64\.encode|Base64\.decode", "label": "Base64 (not encryption)"},
    ],
    "network": [
        {"pattern": r"http://[^\"']*", "label": "Plaintext HTTP URLs"},
        {"pattern": r"HttpURLConnection|OkHttp|Retrofit|Volley", "label": "Network libraries"},
        {"pattern": r"X509TrustManager|checkServerTrusted|TrustAllCerts", "label": "Certificate validation"},
        {"pattern": r"SSLSocketFactory|setHostnameVerifier|ALLOW_ALL", "label": "SSL/TLS config"},
        {"pattern": r"WebView.*loadUrl|addJavascriptInterface|setJavaScriptEnabled", "label": "WebView usage"},
    ],
    "data_storage": [
        {"pattern": r"SQLiteDatabase|rawQuery|execSQL|getWritableDatabase", "label": "Database operations"},
        {"pattern": r"SharedPreferences|getSharedPreferences|edit\(\)\.put", "label": "SharedPreferences usage"},
        {"pattern": r"openFileOutput|FileOutputStream|writeToFile", "label": "File I/O"},
        {"pattern": r"getExternalStorageDirectory|getExternalFilesDir|Environment\.DIRECTORY", "label": "External storage"},
        {"pattern": r"MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE", "label": "World-accessible files"},
    ],
    "ipc_surface": [
        {"pattern": r"startActivity\(|startActivityForResult\(|sendBroadcast\(", "label": "IPC calls"},
        {"pattern": r"getIntent\(\)|getExtras\(\)|getStringExtra", "label": "Intent data reading"},
        {"pattern": r"ContentProvider|ContentResolver|content://", "label": "Content provider"},
        {"pattern": r"registerReceiver|BroadcastReceiver|onReceive", "label": "Broadcast receivers"},
        {"pattern": r"bindService|ServiceConnection|Messenger", "label": "Service binding"},
    ],
    "injection": [
        {"pattern": r"rawQuery\s*\([^)]*\+|execSQL\s*\([^)]*\+", "label": "SQL injection (concatenation)"},
        {"pattern": r"Runtime\.getRuntime\(\)\.exec|ProcessBuilder", "label": "Command execution"},
        {"pattern": r"evaluateJavascript|loadUrl.*javascript:", "label": "JavaScript injection"},
        {"pattern": r"XmlPullParser|SAXParser|DocumentBuilderFactory", "label": "XML parsing (XXE risk)"},
        {"pattern": r"Serializable|ObjectInputStream|readObject", "label": "Deserialization"},
    ],
    "logging_exposure": [
        {"pattern": r"Log\.[dviwes]\s*\(.*password|Log\.[dviwes]\s*\(.*token|Log\.[dviwes]\s*\(.*secret", "label": "Sensitive data in logs"},
        {"pattern": r"printStackTrace\(\)|System\.out\.print", "label": "Debug output"},
        {"pattern": r"BuildConfig\.DEBUG|isDebugMode|debugMode", "label": "Debug flags"},
    ],
}


# ---------------------------------------------------------------------------
# Bytecode-level API patterns (androguard xref) — obfuscation-proof
# ---------------------------------------------------------------------------
# Each entry: (class_descriptor_regex, method_name_regex, label)
# These match on actual DEX method invocations, NOT source identifiers.

BYTECODE_APIS: dict[str, list[tuple[str, str, str]]] = {
    "authentication": [
        (r"Landroid/accounts/AccountManager;", r"getPassword|getAccounts|getAuthToken", "AccountManager credentials"),
        (r"Landroid/app/KeyguardManager;", r"isDeviceSecure|isKeyguardSecure", "Keyguard / lock screen checks"),
    ],
    "crypto": [
        (r"Ljavax/crypto/Cipher;", r"getInstance", "Cipher.getInstance()"),
        (r"Ljavax/crypto/spec/SecretKeySpec;", r"<init>", "SecretKeySpec construction"),
        (r"Ljava/security/MessageDigest;", r"getInstance", "MessageDigest (hashing)"),
        (r"Ljavax/crypto/spec/IvParameterSpec;", r"<init>", "IV parameter creation"),
        (r"Ljava/security/SecureRandom;", r"setSeed", "SecureRandom.setSeed (predictable)"),
        (r"Ljavax/crypto/KeyGenerator;", r"getInstance", "KeyGenerator usage"),
        (r"Ljava/security/KeyStore;", r"getInstance|load", "KeyStore operations"),
        (r"Landroid/security/keystore/KeyGenParameterSpec;", r".*", "Android Keystore params"),
    ],
    "network": [
        (r"Ljavax/net/ssl/X509TrustManager;", r"checkServerTrusted", "TrustManager.checkServerTrusted"),
        (r"Ljavax/net/ssl/HttpsURLConnection;", r"setHostnameVerifier|setSSLSocketFactory", "HTTPS config override"),
        (r"Landroid/webkit/WebView;", r"loadUrl|loadData|loadDataWithBaseURL", "WebView content loading"),
        (r"Landroid/webkit/WebView;", r"addJavascriptInterface", "WebView JS bridge"),
        (r"Landroid/webkit/WebSettings;", r"setJavaScriptEnabled|setAllowFileAccess", "WebView risky settings"),
        (r"Ljava/net/HttpURLConnection;", r"connect|getInputStream", "HTTP connection"),
        (r"Ljavax/net/ssl/SSLContext;", r"init", "SSLContext.init (custom TLS)"),
    ],
    "data_storage": [
        (r"Landroid/database/sqlite/SQLiteDatabase;", r"rawQuery|execSQL|query", "SQLite database operations"),
        (r"Landroid/content/SharedPreferences\$Editor;", r"putString|putInt|putBoolean", "SharedPrefs write"),
        (r"Landroid/content/SharedPreferences;", r"getString|getInt|getBoolean", "SharedPrefs read"),
        (r"Ljava/io/FileOutputStream;", r"<init>|write", "File output"),
        (r"Landroid/os/Environment;", r"getExternalStorageDirectory", "External storage access"),
    ],
    "ipc_surface": [
        (r"Landroid/content/Context;", r"startActivity|startService|sendBroadcast|sendOrderedBroadcast", "IPC dispatch"),
        (r"Landroid/content/Intent;", r"getStringExtra|getExtras|getData", "Intent data extraction"),
        (r"Landroid/content/ContentResolver;", r"query|insert|delete|update", "ContentResolver ops"),
        (r"Landroid/content/Context;", r"registerReceiver", "Dynamic receiver registration"),
        (r"Landroid/app/PendingIntent;", r"getActivity|getBroadcast|getService", "PendingIntent creation"),
    ],
    "injection": [
        (r"Ljava/lang/Runtime;", r"exec", "Runtime.exec (command injection)"),
        (r"Ljava/lang/ProcessBuilder;", r"<init>|start", "ProcessBuilder (command injection)"),
        (r"Landroid/webkit/WebView;", r"evaluateJavascript", "JS evaluation"),
        (r"Ljava/io/ObjectInputStream;", r"readObject", "Deserialization"),
        (r"Ljavax/xml/parsers/SAXParserFactory;", r"newInstance", "SAX parser (XXE)"),
        (r"Ljavax/xml/parsers/DocumentBuilderFactory;", r"newInstance", "DOM parser (XXE)"),
    ],
    "logging_exposure": [
        (r"Landroid/util/Log;", r"d|v|i|w|e", "Android Log calls"),
        (r"Ljava/lang/Throwable;", r"printStackTrace", "printStackTrace()"),
        (r"Ljava/io/PrintStream;", r"println|print", "System.out.print"),
    ],
}

# Maximum number of calling methods to report per API pattern
MAX_XREF_CALLERS_PER_API = 8

# Maximum snippet lines to show per match
MAX_CONTEXT_LINES = 3
# Maximum matches per pattern
MAX_MATCHES_PER_PATTERN = 5
# Maximum total snippets in output
MAX_TOTAL_SNIPPETS = 100


class GetSecurityOverviewTool(BaseTool):
    """Scan APK for security-relevant patterns using source grep AND/OR
    bytecode cross-reference analysis (obfuscation-proof).

    Runs ~50 security-focused patterns across the codebase and returns
    categorized, focused code snippets. This is the recommended first step
    after decompilation — it shows the LLM where to focus its analysis.
    """

    name = "get_security_overview"
    description = (
        "Smart security triage: scans the APK for ~50 security-relevant "
        "patterns and returns categorized code snippets. "
        "Categories: authentication, crypto, network, data_storage, ipc_surface, "
        "injection, logging_exposure. Use 'category' to focus on one area. "
        "scan_mode: 'source' (fast ripgrep on decompiled java, <1s), "
        "'bytecode' (androguard xref analysis on DEX — works on obfuscated APKs, "
        "5-15s), or 'both' (most thorough). Default: 'source'. "
        "This should be your FIRST tool after create_session."
    )

    def input_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": "Active analysis session ID",
                },
                "category": {
                    "type": "string",
                    "description": (
                        "Optional: focus on one category. One of: "
                        "authentication, crypto, network, data_storage, "
                        "ipc_surface, injection, logging_exposure. "
                        "Omit to scan all categories."
                    ),
                },
                "scan_mode": {
                    "type": "string",
                    "enum": ["source", "bytecode", "both"],
                    "description": (
                        "Scan approach. 'source': fast ripgrep on decompiled "
                        "Java (misses obfuscated names). 'bytecode': androguard "
                        "xref on DEX bytecode (slower but obfuscation-proof, "
                        "catches all SDK API calls). 'both': run both and merge. "
                        "Default: 'source'."
                    ),
                },
            },
            "required": ["session_id"],
        }

    async def run(self, session: Optional[AnalysisSession], **kwargs: Any) -> dict:
        if session is None:
            return {"error": "No active session"}

        scan_mode = kwargs.get("scan_mode", "source")
        if scan_mode not in ("source", "bytecode", "both"):
            return {"error": f"Invalid scan_mode: {scan_mode}. Use source/bytecode/both."}

        category_filter = kwargs.get("category", "")
        all_categories = list(SECURITY_PATTERNS.keys())

        if category_filter and category_filter not in SECURITY_PATTERNS:
            return {
                "error": f"Unknown category: {category_filter}",
                "available": all_categories,
            }

        # ---- Source-level scan ----
        source_results: dict[str, list[dict]] = {}
        if scan_mode in ("source", "both"):
            try:
                await _ensure_decompiled(session)
            except RuntimeError as e:
                if scan_mode == "source":
                    return {"error": str(e)}
                # If "both", continue with bytecode-only
                logger.warning(f"Source scan unavailable: {e}, falling back to bytecode-only")
            else:
                source_results = await self._source_scan(
                    session.decompiled_path, category_filter
                )

        # ---- Bytecode-level scan ----
        bytecode_results: dict[str, list[dict]] = {}
        if scan_mode in ("bytecode", "both"):
            ws = _workspace_path(session)
            apk_path = f"{ws}/app.apk"
            bytecode_results = await self._bytecode_scan(apk_path, category_filter)

        # ---- Merge ----
        results = self._merge_results(source_results, bytecode_results)

        # Build summary
        total_snippets = 0
        summary: dict[str, dict] = {}
        for cat, hits in results.items():
            total_matches = sum(h["match_count"] for h in hits)
            summary[cat] = {
                "patterns_matched": len(hits),
                "total_locations": total_matches,
            }
            total_snippets += sum(
                len(h.get("snippets", []) + h.get("callers", []))
                for h in hits
            )

        result = {
            "scan_mode": scan_mode,
            "summary": summary,
            "total_categories_with_findings": len(results),
            "total_snippets_shown": total_snippets,
            "results": results,
            "hint": (
                "Review each category. Use read_source_file to examine full "
                "files for any interesting snippet. Use search_source for "
                "deeper investigation of specific patterns. Call add_finding "
                "for each vulnerability you identify."
                + (
                    " Bytecode results show which app methods call sensitive "
                    "APIs — useful even when source names are obfuscated."
                    if bytecode_results else ""
                )
            ),
        }
        if scan_mode in ("source", "both"):
            warning = get_wrapper_only_warning(session, self.name, scan_mode=scan_mode)
            if warning:
                result["warning"] = warning
        return result

    # ------------------------------------------------------------------
    # Source scan (ripgrep)
    # ------------------------------------------------------------------

    async def _source_scan(
        self, decompiled: str, category_filter: str
    ) -> dict[str, list[dict]]:
        """Ripgrep-based scan of decompiled Java sources."""
        if category_filter:
            categories = {category_filter: SECURITY_PATTERNS[category_filter]}
        else:
            categories = SECURITY_PATTERNS

        results: dict[str, list[dict]] = {}
        total_snippets = 0

        for cat_name, patterns in categories.items():
            cat_results = []
            for pat_info in patterns:
                if total_snippets >= MAX_TOTAL_SNIPPETS:
                    break
                matches = await self._search_pattern(
                    decompiled, pat_info["pattern"]
                )
                if matches:
                    cat_results.append({
                        "source": "ripgrep",
                        "label": pat_info["label"],
                        "match_count": len(matches),
                        "snippets": matches[:MAX_MATCHES_PER_PATTERN],
                    })
                    total_snippets += min(len(matches), MAX_MATCHES_PER_PATTERN)
            if cat_results:
                results[cat_name] = cat_results

        return results

    # ------------------------------------------------------------------
    # Bytecode scan (androguard xref)
    # ------------------------------------------------------------------

    async def _bytecode_scan(
        self, apk_path: str, category_filter: str
    ) -> dict[str, list[dict]]:
        """Androguard xref-based scan on the DEX bytecode.

        For each security-sensitive Android/Java API, find every app method
        that *calls* it. This works regardless of obfuscation because the
        framework class/method descriptors are never renamed.

        Uses temp files for the script + API list to avoid f-string/quoting
        issues with embedded JSON.
        """
        if category_filter:
            if category_filter not in BYTECODE_APIS:
                return {}
            apis_to_scan = {category_filter: BYTECODE_APIS[category_filter]}
        else:
            apis_to_scan = BYTECODE_APIS

        # Flatten into a JSON-serialisable list
        api_list = []
        for cat, entries in apis_to_scan.items():
            for cls_re, meth_re, label in entries:
                api_list.append({
                    "cat": cat,
                    "cls": cls_re,
                    "meth": meth_re,
                    "label": label,
                })

        max_callers = MAX_XREF_CALLERS_PER_API

        # Write API list and script to temp files (avoids quoting nightmares)
        import tempfile
        apis_file = tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        )
        apis_file.write(json.dumps(api_list))
        apis_file.close()

        script = f"""
import json, sys, re

from androguard.util import set_log
set_log("ERROR")
from androguard.misc import AnalyzeAPK

FRAMEWORK_PREFIXES = (
    "Landroid/", "Landroidx/", "Ljava/", "Ljavax/", "Lkotlin/",
    "Lkotlinx/", "Lcom/google/android/", "Ldalvik/", "Lorg/json/",
    "Lorg/w3c/", "Lorg/xml/", "Lsun/", "Lorg/apache/",
)

try:
    with open("{apis_file.name}") as f:
        apis = json.load(f)

    a, d, dx = AnalyzeAPK("{apk_path}")
    results = {{}}

    for api in apis:
        cat = api["cat"]
        cls_re = re.compile(api["cls"])
        meth_re = re.compile(api["meth"])
        label = api["label"]

        callers = []
        for m in dx.find_methods(classname=cls_re, methodname=meth_re):
            for ref_cls, ref_meth, offset in m.get_xref_from():
                caller_cls = ref_cls.name
                if caller_cls.startswith(FRAMEWORK_PREFIXES):
                    continue
                caller_method = ref_meth.get_method()
                caller_name = caller_cls.replace("/", ".").strip("L;")
                method_name = (
                    caller_method.get_name()
                    if hasattr(caller_method, "get_name")
                    else "?"
                )
                callers.append({{
                    "class": caller_name,
                    "method": method_name,
                }})
                if len(callers) >= {max_callers}:
                    break
            if len(callers) >= {max_callers}:
                break

        if callers:
            if cat not in results:
                results[cat] = []
            results[cat].append({{
                "label": label,
                "callers": callers,
                "caller_count": len(callers),
            }})

    print(json.dumps(results))
except Exception as e:
    print(json.dumps({{"_error": str(e)}}))
    sys.exit(0)
"""

        script_file = tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False
        )
        script_file.write(script)
        script_file.close()

        try:
            stdout, stderr, rc = await run_local(
                ["python3", script_file.name],
                timeout=120,
            )
        finally:
            # Clean up temp files
            try:
                os.unlink(apis_file.name)
                os.unlink(script_file.name)
            except OSError:
                pass

        if rc != 0:
            logger.warning(f"Bytecode scan failed (rc={rc}): {stderr[:300]}")
            return {}

        try:
            raw = json.loads(stdout)
        except json.JSONDecodeError:
            logger.warning(f"Bytecode scan: unparseable output: {stdout[:300]}")
            return {}

        if "_error" in raw:
            logger.warning(f"Bytecode scan error: {raw['_error']}")
            return {}

        # Normalise into same shape but with "callers" instead of "snippets"
        results: dict[str, list[dict]] = {}
        for cat, entries in raw.items():
            cat_hits = []
            for entry in entries:
                cat_hits.append({
                    "source": "bytecode_xref",
                    "label": entry["label"],
                    "match_count": entry["caller_count"],
                    "callers": entry["callers"],
                })
            if cat_hits:
                results[cat] = cat_hits

        return results

    # ------------------------------------------------------------------
    # Merge source + bytecode results
    # ------------------------------------------------------------------

    @staticmethod
    def _merge_results(
        source: dict[str, list[dict]],
        bytecode: dict[str, list[dict]],
    ) -> dict[str, list[dict]]:
        """Merge source-level and bytecode-level results by category."""
        merged: dict[str, list[dict]] = {}

        all_cats = set(source.keys()) | set(bytecode.keys())
        for cat in sorted(all_cats):
            hits: list[dict] = []
            if cat in source:
                hits.extend(source[cat])
            if cat in bytecode:
                hits.extend(bytecode[cat])
            if hits:
                merged[cat] = hits

        return merged

    async def _search_pattern(
        self, decompiled: str, pattern: str
    ) -> list[dict]:
        """Run a single ripgrep pattern search and parse results."""
        stdout, stderr, rc = await run_local(
            [
                "rg",
                "--json",
                "-C", str(MAX_CONTEXT_LINES),
                "--max-count", str(MAX_MATCHES_PER_PATTERN),
                "-g", "*.java",
                "-i",  # case-insensitive
                pattern,
                decompiled,
            ],
            timeout=15,
        )

        if rc >= 2:
            return []  # search error, skip

        matches = []
        for line in stdout.splitlines():
            if not line.strip():
                continue
            try:
                obj = json.loads(line)
                if obj.get("type") == "match":
                    data = obj["data"]
                    match_path = data["path"]["text"].replace(
                        decompiled + "/", ""
                    )
                    match_text = data["lines"]["text"].rstrip("\n")
                    line_num = data["line_number"]
                    matches.append({
                        "file": match_path,
                        "line": line_num,
                        "code": match_text.strip(),
                    })
            except (json.JSONDecodeError, KeyError):
                continue

        return matches
