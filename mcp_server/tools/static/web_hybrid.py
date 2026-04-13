"""Web-hybrid (Cordova / Capacitor) static analysis tool."""

from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Optional

from mcp_server.models.session import AnalysisSession
from mcp_server.tools.base import BaseTool
from mcp_server.tools.static.routing import (
    ensure_artifact_index,
    ensure_framework_metadata,
    _read_apk_entry_bytes,
)
from mcp_server.tools.workspace import session_workspace

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MAX_ASSET_SCAN_FILES = 40
MAX_ASSET_FILE_BYTES = 512 * 1024  # 512 KB per file
MAX_ITEMS = 25

URL_RE = re.compile(r"https?://[^\s\"'<>]+")
JS_INTERFACE_RE = re.compile(
    r"(?:addJavascriptInterface|@JavascriptInterface|JavascriptInterface)",
    re.IGNORECASE,
)
POSTMESSAGE_RE = re.compile(r"(?:postMessage|addEventListener\s*\(\s*['\"]message)", re.IGNORECASE)
WINDOW_LOCATION_RE = re.compile(r"window\.location(?:\.href)?\s*=", re.IGNORECASE)
AUTH_RE = re.compile(
    r"[A-Za-z0-9_.:-]*(?:token|auth|bearer|jwt|password|credential|apikey|api_key)[A-Za-z0-9_.:-]*",
    re.IGNORECASE,
)

RISKY_CORDOVA_PLUGINS = {
    "cordova-plugin-file",
    "cordova-plugin-file-transfer",
    "cordova-plugin-inappbrowser",
    "cordova-plugin-whitelist",
    "cordova-plugin-advanced-http",
    "cordova-plugin-network-information",
    "phonegap-plugin-push",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _read_entry(apk_path: str, entry: str, max_bytes: int | None = None) -> bytes | None:
    return _read_apk_entry_bytes(apk_path, entry, max_bytes=max_bytes)


def _decode(data: bytes | None) -> str | None:
    if data is None:
        return None
    return data.decode("utf-8", errors="replace")


def _parse_cordova_config(xml_text: str) -> dict[str, Any]:
    """Parse Cordova config.xml and extract security-relevant settings."""
    result: dict[str, Any] = {
        "allow_navigation": [],
        "allow_intent": [],
        "preferences": {},
        "csp": None,
        "errors": [],
    }
    try:
        root = ET.fromstring(xml_text)
        ns = {"": ""}

        for elem in root.iter():
            tag = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
            if tag == "allow-navigation":
                href = elem.get("href", "")
                if href and len(result["allow_navigation"]) < MAX_ITEMS:
                    result["allow_navigation"].append(href)
            elif tag == "allow-intent":
                href = elem.get("href", "")
                if href and len(result["allow_intent"]) < MAX_ITEMS:
                    result["allow_intent"].append(href)
            elif tag == "preference":
                name = elem.get("name", "")
                value = elem.get("value", "")
                if name:
                    result["preferences"][name] = value
            elif tag == "meta" and "Content-Security-Policy" in elem.get("http-equiv", ""):
                result["csp"] = elem.get("content", "")
    except ET.ParseError as exc:
        result["errors"].append(f"XML parse error: {exc}")
    return result


def _parse_capacitor_config(json_text: str) -> dict[str, Any]:
    """Parse capacitor.config.json and extract security-relevant settings."""
    result: dict[str, Any] = {
        "server": {},
        "allow_navigation": [],
        "plugins": [],
        "errors": [],
    }
    try:
        cfg = json.loads(json_text)
        server = cfg.get("server", {})
        result["server"] = {
            k: server[k]
            for k in ("url", "hostname", "allowNavigation", "cleartext", "androidScheme")
            if k in server
        }
        nav = server.get("allowNavigation", [])
        if isinstance(nav, list):
            result["allow_navigation"] = nav[:MAX_ITEMS]
        elif isinstance(nav, str):
            result["allow_navigation"] = [nav]
        plugins = cfg.get("plugins", {})
        result["plugins"] = list(plugins.keys())[:MAX_ITEMS]
    except (json.JSONDecodeError, TypeError) as exc:
        result["errors"].append(f"JSON parse error: {exc}")
    return result


def _parse_cordova_plugins(js_text: str) -> list[dict[str, str]]:
    """Extract plugin entries from cordova_plugins.js."""
    plugins: list[dict[str, str]] = []
    # Pattern: { "id": "...", "file": "...", "clobbers": [...] }
    for m in re.finditer(
        r'\{\s*["\']id["\']\s*:\s*["\']([^"\']+)["\'].*?(?:["\']file["\']\s*:\s*["\']([^"\']*)["\'])?',
        js_text,
        re.DOTALL,
    ):
        entry = {"id": m.group(1)}
        if m.group(2):
            entry["file"] = m.group(2)
        if len(plugins) < MAX_ITEMS:
            plugins.append(entry)
    return plugins


def _parse_capacitor_plugins(json_text: str) -> list[dict[str, str]]:
    """Extract plugin entries from capacitor.plugins.json."""
    plugins: list[dict[str, str]] = []
    try:
        data = json.loads(json_text)
        if isinstance(data, list):
            for entry in data[:MAX_ITEMS]:
                if isinstance(entry, dict):
                    plugins.append(
                        {k: entry[k] for k in ("id", "pkg", "classpath") if k in entry}
                    )
        elif isinstance(data, dict):
            for key, val in list(data.items())[:MAX_ITEMS]:
                plugins.append({"id": key, **({"classpath": val} if isinstance(val, str) else {})})
    except (json.JSONDecodeError, TypeError):
        pass
    return plugins


def _parse_kony_config(json_text: str) -> dict[str, Any]:
    """Parse a Kony/Visualizer config.json for security-relevant settings."""
    result: dict[str, Any] = {
        "app_id": None,
        "services": [],
        "https_enabled": None,
        "server_urls": [],
        "errors": [],
    }
    try:
        data = json.loads(json_text)
        result["app_id"] = data.get("appID") or data.get("appid")
        https_val = data.get("httpsEnabled")
        if https_val is None and isinstance(data.get("security"), dict):
            https_val = data["security"].get("httpsEnabled")
        result["https_enabled"] = https_val

        services = data.get("services") or data.get("ServiceDocuments") or {}
        if isinstance(services, dict):
            for svc_name, svc_data in services.items():
                result["services"].append(svc_name)
                if isinstance(svc_data, dict):
                    url = svc_data.get("serviceUrl") or svc_data.get("url") or svc_data.get("baseUrl")
                    if url and isinstance(url, str):
                        result["server_urls"].append(url)

        for key in ("baseUrl", "serverUrl", "serviceUrl", "apiUrl"):
            url = data.get(key)
            if url and isinstance(url, str):
                result["server_urls"].append(url)
    except (json.JSONDecodeError, AttributeError, TypeError) as exc:
        result["errors"].append(str(exc))
    return result


def _scan_web_asset(content: str) -> dict[str, Any]:
    """Scan a single web asset file for bridge and security signals."""
    result: dict[str, Any] = {
        "urls": [],
        "js_interfaces": [],
        "postmessage_calls": [],
        "window_location_assignments": [],
        "auth_tokens": [],
    }
    seen: dict[str, set] = {k: set() for k in result}

    for line in content.splitlines():
        stripped = line.strip()
        if not stripped:
            continue

        for m in URL_RE.findall(stripped):
            if len(result["urls"]) < MAX_ITEMS and m not in seen["urls"]:
                seen["urls"].add(m)
                result["urls"].append(m)

        if JS_INTERFACE_RE.search(stripped):
            snippet = stripped[:200]
            if snippet not in seen["js_interfaces"]:
                seen["js_interfaces"].add(snippet)
                result["js_interfaces"].append(snippet)

        if POSTMESSAGE_RE.search(stripped):
            snippet = stripped[:200]
            if snippet not in seen["postmessage_calls"]:
                seen["postmessage_calls"].add(snippet)
                result["postmessage_calls"].append(snippet)

        if WINDOW_LOCATION_RE.search(stripped):
            snippet = stripped[:200]
            if snippet not in seen["window_location_assignments"]:
                seen["window_location_assignments"].add(snippet)
                result["window_location_assignments"].append(snippet)

        for m in AUTH_RE.findall(stripped):
            if len(result["auth_tokens"]) < MAX_ITEMS and m not in seen["auth_tokens"]:
                seen["auth_tokens"].add(m)
                result["auth_tokens"].append(m)

    return result


def _merge_asset_scans(scans: list[dict[str, Any]]) -> dict[str, Any]:
    merged: dict[str, list] = {
        "urls": [],
        "js_interfaces": [],
        "postmessage_calls": [],
        "window_location_assignments": [],
        "auth_tokens": [],
    }
    seen: dict[str, set] = {k: set() for k in merged}
    for scan in scans:
        for key in merged:
            for item in scan.get(key, []):
                if item not in seen[key] and len(merged[key]) < MAX_ITEMS:
                    seen[key].add(item)
                    merged[key].append(item)
    return merged


# ---------------------------------------------------------------------------
# Tool
# ---------------------------------------------------------------------------

class AnalyzeWebHybridTool(BaseTool):
    """Bridge and config analysis for Cordova, Capacitor, and similar web-hybrid APKs."""

    name = "analyze_web_hybrid"
    description = (
        "Analyze a Cordova, Capacitor, or web-hybrid APK's bridge configuration and web assets. "
        "Parses config.xml / capacitor.config.json for CSP, navigation allowlists, and plugin "
        "registrations. Scans bundled JS/HTML assets for JavascriptInterface exposure, "
        "postMessage patterns, window.location assignments, and hardcoded URLs. "
        "Returns structured bridge_exposure, csp_findings, plugin_list, and recovered signals."
    )

    def input_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": "Active analysis session ID",
                },
            },
            "required": ["session_id"],
        }

    async def run(self, session: Optional[AnalysisSession], **kwargs: Any) -> dict:
        if session is None:
            return {"error": "No active session"}

        framework = ensure_framework_metadata(session)
        primary = framework.get("primary_framework", "")
        if primary not in {"Cordova", "Capacitor", "Kony Visualizer"}:
            return {
                "error": "This tool applies to Cordova, Capacitor, and Kony Visualizer APKs.",
                "primary_framework": primary,
            }

        apk_path = f"{session_workspace(session)}/app.apk"
        artifact_index = ensure_artifact_index(session)

        config_analysis: dict[str, Any] = {}
        plugin_list: list[dict[str, str]] = []
        csp_findings: list[str] = []
        allow_navigation: list[str] = []

        # --- Cordova config.xml ---
        cordova_config_raw = _decode(_read_entry(apk_path, "res/xml/config.xml"))
        if cordova_config_raw:
            cfg = _parse_cordova_config(cordova_config_raw)
            config_analysis["cordova_config"] = cfg
            allow_navigation.extend(cfg["allow_navigation"])
            if cfg["allow_navigation"] and "*" in cfg["allow_navigation"]:
                csp_findings.append("allow-navigation contains wildcard '*' — any URL can be loaded in WebView")
            if cfg["csp"]:
                csp_findings.append(f"CSP from config.xml: {cfg['csp']}")
            # Check AllowBrowserGap preference
            if cfg["preferences"].get("AllowBrowserGap", "").lower() == "true":
                csp_findings.append("AllowBrowserGap=true: Cordova default whitelist is bypassed")

        # --- cordova_plugins.js ---
        cordova_plugins_raw = _decode(_read_entry(apk_path, "assets/www/cordova_plugins.js"))
        if cordova_plugins_raw:
            plugin_list.extend(_parse_cordova_plugins(cordova_plugins_raw))

        # --- Capacitor config ---
        cap_config_raw = _decode(_read_entry(apk_path, "assets/capacitor.config.json"))
        if cap_config_raw:
            cfg = _parse_capacitor_config(cap_config_raw)
            config_analysis["capacitor_config"] = cfg
            allow_navigation.extend(cfg["allow_navigation"])
            if cfg["server"].get("cleartext"):
                csp_findings.append("Capacitor cleartext traffic is explicitly enabled")
            if cfg["server"].get("allowNavigation"):
                nav = cfg["server"]["allowNavigation"]
                if isinstance(nav, list) and "*" in nav:
                    csp_findings.append("Capacitor allowNavigation contains wildcard '*'")

        # --- Capacitor plugins ---
        cap_plugins_raw = _decode(_read_entry(apk_path, "assets/capacitor.plugins.json"))
        if cap_plugins_raw:
            plugin_list.extend(_parse_capacitor_plugins(cap_plugins_raw))

        # --- Kony config ---
        if primary == "Kony Visualizer":
            for kony_cfg_path in ("assets/KonyApps/config.json", "assets/konyconfig.json"):
                kony_cfg_raw = _decode(_read_entry(apk_path, kony_cfg_path))
                if kony_cfg_raw:
                    kony_cfg = _parse_kony_config(kony_cfg_raw)
                    config_analysis["kony_config"] = kony_cfg
                    if kony_cfg.get("https_enabled") is False:
                        csp_findings.append(
                            "Kony httpsEnabled is false — cleartext traffic is explicitly permitted"
                        )
                    elif kony_cfg.get("https_enabled") is None:
                        csp_findings.append(
                            "Kony httpsEnabled not found in config — cleartext traffic may be permitted"
                        )
                    for url in kony_cfg["server_urls"]:
                        if url not in allow_navigation:
                            allow_navigation.append(url)
                    break

        # Flag risky plugins
        risky_plugins = [
            p for p in plugin_list if p.get("id", "") in RISKY_CORDOVA_PLUGINS
        ]

        # --- Scan web assets ---
        web_roots = ["assets/www/", "assets/public/"]
        if primary == "Kony Visualizer":
            web_roots.append("assets/KonyApps/")

        web_artifacts = [
            a for a in artifact_index.get("artifacts", {}).get("web_assets", [])
            if any(a["path"].startswith(root) for root in web_roots)
            and a.get("text_compatible")
        ][:MAX_ASSET_SCAN_FILES]

        asset_scans: list[dict[str, Any]] = []
        scanned_files: list[str] = []

        # Kony top-level JS files (kony.js, konyframework.js) are not in assets/www/
        if primary == "Kony Visualizer":
            for kony_js in ("assets/kony.js", "assets/konyframework.js"):
                raw = _read_entry(apk_path, kony_js, max_bytes=MAX_ASSET_FILE_BYTES)
                if raw:
                    content = raw.decode("utf-8", errors="replace")
                    scan = _scan_web_asset(content)
                    if any(scan[k] for k in scan):
                        asset_scans.append(scan)
                        scanned_files.append(kony_js)

        for artifact in web_artifacts:
            raw = _read_entry(apk_path, artifact["path"], max_bytes=MAX_ASSET_FILE_BYTES)
            if raw:
                content = raw.decode("utf-8", errors="replace")
                scan = _scan_web_asset(content)
                # Only keep non-empty scans
                if any(scan[k] for k in scan):
                    asset_scans.append(scan)
                    scanned_files.append(artifact["path"])

        merged = _merge_asset_scans(asset_scans)

        bridge_exposure: list[str] = []
        if merged["js_interfaces"]:
            bridge_exposure.append(
                f"JavascriptInterface usage found in {len(merged['js_interfaces'])} location(s)"
            )
        if merged["postmessage_calls"]:
            bridge_exposure.append(
                f"postMessage calls found in {len(merged['postmessage_calls'])} location(s)"
            )
        if merged["window_location_assignments"]:
            bridge_exposure.append(
                f"window.location assignments found in {len(merged['window_location_assignments'])} location(s)"
            )

        result: dict[str, Any] = {
            "primary_framework": primary,
            "config_analysis": config_analysis,
            "plugin_list": plugin_list,
            "risky_plugins": risky_plugins,
            "csp_findings": csp_findings,
            "allow_navigation": allow_navigation[:MAX_ITEMS],
            "bridge_exposure": bridge_exposure,
            "web_assets_scanned": len(scanned_files),
            "scanned_files": scanned_files[:20],
            "recovered": {
                "urls": merged["urls"],
                "js_interfaces": merged["js_interfaces"],
                "postmessage_calls": merged["postmessage_calls"],
                "window_location_assignments": merged["window_location_assignments"],
                "auth_tokens": merged["auth_tokens"],
            },
            "dynamic_hypotheses": [
                "Test CSP and navigation allowlist enforcement by attempting restricted navigations.",
                "Verify JavascriptInterface exposure: test for XSS-to-native escalation paths.",
                "Intercept postMessage traffic to confirm origin validation at the bridge.",
                "Confirm plugin permissions and capabilities in a real device context.",
            ],
            "hint": (
                "Correlate recovered URLs and auth tokens with the manifest deep-link config "
                "and dynamic traffic capture. Review risky plugins for capability misuse."
            ),
        }

        session.metadata.setdefault("web_hybrid", {})["bridge_analysis"] = {
            "primary_framework": primary,
            "plugin_count": len(plugin_list),
            "risky_plugin_count": len(risky_plugins),
            "web_assets_scanned": len(scanned_files),
        }
        return result
