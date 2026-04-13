"""Manifest parsing and reconnaissance tools.

These tools handle APK session creation, metadata extraction, Android manifest
parsing, component enumeration, and manifest security checking.
"""

from __future__ import annotations

import os
import shutil
import xml.etree.ElementTree as ET
from typing import Any, Optional

from loguru import logger

from mcp_server.backends.local_backend import read_file_content, run_local
from mcp_server.models.enums import (
    AnalysisPhase,
    FindingCategory,
    Severity,
)
from mcp_server.models.finding import Finding
from mcp_server.models.session import AnalysisSession
from mcp_server.session_manager import SessionManager
from mcp_server.tools.base import BaseTool
from mcp_server.tools.workspace import session_workspace, workspace_for_session_id

try:
    from apkInspector.axml import parse_apk_for_manifest
    _HAS_APK_INSPECTOR = True
except ImportError:
    _HAS_APK_INSPECTOR = False

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _workspace_path(session: AnalysisSession) -> str:
    """Return the workspace directory for a session inside the container."""
    return str(session_workspace(session))


def _host_workspace_path(session: AnalysisSession) -> str:
    """Return the workspace directory for a session on the host."""
    return str(session_workspace(session))


async def _ensure_decoded(session: AnalysisSession) -> str:
    """Ensure the APK has been decoded with apktool. Returns decoded path."""
    if session.decoded_path:
        return session.decoded_path

    ws = _workspace_path(session)
    decoded = f"{ws}/decoded"
    apk = f"{ws}/app.apk"

    # Remove any leftovers from a previous partial decode to avoid
    # apktool's PathAlreadyExists error on the 'res' directory.
    if os.path.isdir(decoded):
        shutil.rmtree(decoded, ignore_errors=True)

    stdout, stderr, rc = await run_local(
        ["apktool", "d", "-f", "-o", decoded, apk],
        timeout=120,
    )
    if rc != 0:
        raise RuntimeError(f"apktool decode failed: {stderr}")

    session.decoded_path = decoded
    logger.info("APK decoded to {}", decoded)
    return decoded


def _get_manifest_via_apkinspector(apk_path: str) -> str:
    """Extract and decode AndroidManifest.xml using apkInspector.

    This is a fallback for when apktool cannot decode the APK (common with
    malware that uses ZIP/manifest tampering to break standard tools).
    apkInspector's parser is resilient against these evasion techniques.

    Returns the decoded manifest as an XML string.  The output is
    *minimalistic* compared to apktool — resource references stay as
    numeric IDs (e.g. ``@2131234567``) rather than resolved names.
    """
    if not _HAS_APK_INSPECTOR:
        raise RuntimeError(
            "apkInspector is not installed — cannot fall back to "
            "resilient manifest extraction."
        )
    xml_string = parse_apk_for_manifest(apk_path, raw=False, lite=False)
    return xml_string


async def _ensure_manifest_xml(session: AnalysisSession) -> tuple[str, bool]:
    """Get the decoded AndroidManifest.xml content for a session.

    Tries apktool first (full resource resolution).  If apktool fails,
    falls back to apkInspector (minimalistic but tamper-resilient).

    Returns:
        A tuple of (xml_string, used_fallback).
    """
    ws = _workspace_path(session)
    apk = f"{ws}/app.apk"

    # --- Primary: apktool ---
    try:
        decoded = await _ensure_decoded(session)
        manifest_path = f"{decoded}/AndroidManifest.xml"
        stdout, stderr, rc = await read_file_content(manifest_path)
        if rc == 0 and stdout.strip():
            return stdout, False
        logger.warning(
            "apktool decoded but manifest unreadable: {}", stderr
        )
    except RuntimeError as exc:
        logger.warning("apktool decode failed, trying apkInspector: {}", exc)

    # --- Fallback: apkInspector ---
    xml_string = _get_manifest_via_apkinspector(apk)
    return xml_string, True


def _parse_manifest_xml(xml_content: str) -> dict:
    """Parse AndroidManifest.xml into a structured dict."""
    # Handle Android namespace
    ns = {"android": "http://schemas.android.com/apk/res/android"}

    root = ET.fromstring(xml_content)

    # Package info
    package = root.get("package", "")

    # Permissions
    uses_permissions = []
    for perm in root.findall("uses-permission"):
        name = perm.get(f"{{{ns['android']}}}name", perm.get("android:name", ""))
        if name:
            uses_permissions.append(name)

    # Also try without namespace prefix (apktool decodes differently)
    for perm in root.findall(".//uses-permission"):
        name = perm.get(f"{{{ns['android']}}}name", "")
        if name and name not in uses_permissions:
            uses_permissions.append(name)

    # Application attributes
    app = root.find("application")
    app_attrs = {}
    if app is not None:
        for attr_name in [
            "debuggable", "allowBackup", "usesCleartextTraffic",
            "networkSecurityConfig", "label", "name",
        ]:
            val = app.get(f"{{{ns['android']}}}{attr_name}")
            if val is not None:
                app_attrs[attr_name] = val

    # Components
    components = {
        "activities": [],
        "services": [],
        "receivers": [],
        "providers": [],
    }

    tag_map = {
        "activity": "activities",
        "service": "services",
        "receiver": "receivers",
        "provider": "providers",
    }

    if app is not None:
        for tag, key in tag_map.items():
            for elem in app.findall(tag):
                comp = _parse_component(elem, ns)
                components[key].append(comp)

    return {
        "package": package,
        "uses_permissions": uses_permissions,
        "application_attributes": app_attrs,
        "components": components,
        "sdk": {
            "min_sdk": root.find("uses-sdk").get(f"{{{ns['android']}}}minSdkVersion", "")
            if root.find("uses-sdk") is not None else "",
            "target_sdk": root.find("uses-sdk").get(f"{{{ns['android']}}}targetSdkVersion", "")
            if root.find("uses-sdk") is not None else "",
        },
    }


def _parse_component(elem: ET.Element, ns: dict) -> dict:
    """Parse a component element (activity, service, etc.)."""
    android_ns = ns["android"]

    name = elem.get(f"{{{android_ns}}}name", "")
    exported = elem.get(f"{{{android_ns}}}exported")
    permission = elem.get(f"{{{android_ns}}}permission", "")
    enabled = elem.get(f"{{{android_ns}}}enabled", "true")

    # Parse intent filters
    intent_filters = []
    for if_elem in elem.findall("intent-filter"):
        actions = [
            a.get(f"{{{android_ns}}}name", "")
            for a in if_elem.findall("action")
        ]
        categories = [
            c.get(f"{{{android_ns}}}name", "")
            for c in if_elem.findall("category")
        ]
        data_elems = []
        for d in if_elem.findall("data"):
            data_dict = {}
            for attr in ["scheme", "host", "path", "pathPrefix", "mimeType"]:
                val = d.get(f"{{{android_ns}}}{attr}")
                if val:
                    data_dict[attr] = val
            if data_dict:
                data_elems.append(data_dict)

        intent_filters.append({
            "actions": actions,
            "categories": categories,
            "data": data_elems,
        })

    # Determine if effectively exported
    # If exported is not set, it's implicitly exported if there are intent filters
    is_exported = False
    if exported == "true":
        is_exported = True
    elif exported is None and intent_filters:
        is_exported = True

    result = {
        "name": name,
        "exported": is_exported,
        "explicit_exported": exported,
        "permission": permission,
        "enabled": enabled,
        "intent_filters": intent_filters,
    }

    # Provider-specific attributes
    if elem.tag == "provider":
        result["authorities"] = elem.get(f"{{{android_ns}}}authorities", "")
        result["grantUriPermissions"] = elem.get(
            f"{{{android_ns}}}grantUriPermissions", "false"
        )
        result["readPermission"] = elem.get(f"{{{android_ns}}}readPermission", "")
        result["writePermission"] = elem.get(f"{{{android_ns}}}writePermission", "")

        # Path permissions
        path_permissions = []
        for pp in elem.findall("path-permission"):
            path_permissions.append({
                "path": pp.get(f"{{{android_ns}}}path", ""),
                "pathPrefix": pp.get(f"{{{android_ns}}}pathPrefix", ""),
                "readPermission": pp.get(f"{{{android_ns}}}readPermission", ""),
                "writePermission": pp.get(f"{{{android_ns}}}writePermission", ""),
                "permission": pp.get(f"{{{android_ns}}}permission", ""),
            })
        result["path_permissions"] = path_permissions

    return result


# ---------------------------------------------------------------------------
# Inbox helpers
# ---------------------------------------------------------------------------

INBOX_DIR = os.environ.get("MOBILYTIX_INBOX", "/inbox")


def _resolve_apk_path(raw_path: str) -> str:
    """Resolve an APK path argument to an actual file inside the container.

    Supports:
      - Full inbox path:  /inbox/app.apk          → used as-is
      - Bare filename:    app.apk                  → /inbox/app.apk
      - Host path:        /home/user/app.apk       → looks for app.apk in /inbox/

    Resolution never accepts files outside the mounted inbox, even if the
    caller passes an absolute path that exists inside the container.
    """
    raw_path = str(raw_path).strip()
    basename = os.path.basename(raw_path)
    inbox_root = os.path.realpath(INBOX_DIR)

    candidates = []
    if os.path.isabs(raw_path):
        candidates.append(raw_path)
        if basename:
            candidates.append(os.path.join(INBOX_DIR, basename))
    else:
        candidates.append(os.path.join(INBOX_DIR, raw_path))

    for candidate in candidates:
        real_candidate = os.path.realpath(candidate)
        try:
            is_in_inbox = os.path.commonpath([inbox_root, real_candidate]) == inbox_root
        except ValueError:
            is_in_inbox = False
        if is_in_inbox and os.path.isfile(real_candidate):
            return real_candidate

    # Return an inbox path for error reporting without exposing arbitrary paths.
    fallback_name = basename or raw_path.lstrip(os.sep)
    return os.path.join(INBOX_DIR, fallback_name)


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------


class ListInboxTool(BaseTool):
    """List APK files available for analysis in the /inbox directory.

    Users mount a host APK folder into /inbox. This tool lets the AI
    discover which APKs are ready for analysis.
    """

    name = "list_inbox"
    description = (
        "List APK files available for analysis. Users mount a host APK folder "
        "into /inbox, and this tool shows what is available. "
        "Call this FIRST to discover APKs before calling create_session. "
        "No arguments required."
    )

    def input_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {},
            "required": [],
        }

    async def run(self, session: Optional[AnalysisSession], **kwargs: Any) -> dict:
        if not os.path.isdir(INBOX_DIR):
            return {
                "error": f"Inbox directory not found: {INBOX_DIR}",
                "hint": "Make sure the inbox volume is mounted.",
            }

        files = []
        for entry in sorted(os.listdir(INBOX_DIR)):
            full = os.path.join(INBOX_DIR, entry)
            if os.path.isfile(full):
                size = os.path.getsize(full)
                files.append({
                    "filename": entry,
                    "path": full,
                    "size_bytes": size,
                    "size_mb": round(size / (1024 * 1024), 2),
                    "is_apk": entry.lower().endswith(".apk"),
                })

        apk_count = sum(1 for f in files if f["is_apk"])

        return {
            "inbox_dir": INBOX_DIR,
            "total_files": len(files),
            "apk_count": apk_count,
            "files": files,
            "hint": (
                "To analyze an APK, call create_session with the 'path' value "
                "from any file above."
            ) if apk_count > 0 else (
                "No APK files found. Ask the user to place an APK in the mounted APK folder."
            ),
        }


class CreateSessionTool(BaseTool):
    """Create or resume an APK analysis session.

    On first call for a given APK, copies the file into the analysis workspace
    and creates a new session.  On subsequent calls **with the same APK**
    (identified by SHA-256 hash), the existing session is returned —
    preserving all decoded/decompiled artifacts and findings from previous
    analysis runs.

    Pass ``force_new=true`` to discard the previous workspace and start
    from scratch.
    """

    name = "create_session"
    description = (
        "Create or resume an APK analysis session. If the same APK was "
        "already analyzed, the existing session is resumed (with all prior "
        "decoded/decompiled artifacts intact). Pass force_new=true to "
        "discard the old session and start clean. "
        "The APK must be available in the mounted APK folder at /inbox — use list_inbox first. "
        "Returns session_id, apk_hash, file_size, and whether this is "
        "a resumed or fresh session."
    )

    def __init__(self, session_manager: SessionManager) -> None:
        self._sm = session_manager

    def input_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "apk_path": {
                    "type": "string",
                    "description": (
                        "APK filename or path. Can be just a filename like 'app.apk' "
                        "(will look in /inbox/) or a full path like '/inbox/app.apk'."
                    ),
                },
                "session_name": {
                    "type": "string",
                    "description": "Optional human-readable session name",
                },
                "force_new": {
                    "type": "boolean",
                    "description": (
                        "If true, discard any existing session for this APK and start "
                        "from scratch. Default: false (resume existing session)."
                    ),
                },
            },
            "required": ["apk_path"],
        }

    async def run(self, session: Optional[AnalysisSession], **kwargs: Any) -> dict:
        raw_path = kwargs["apk_path"]
        session_name = kwargs.get("session_name", "")
        force_new = kwargs.get("force_new", False)

        # Smart path resolution: bare filename → /inbox/filename, host path → inbox lookup
        apk_path = _resolve_apk_path(raw_path)

        # Verify file exists
        if not os.path.isfile(apk_path):
            available = []
            if os.path.isdir(INBOX_DIR):
                available = [f for f in os.listdir(INBOX_DIR) if f.lower().endswith(".apk")]
            return {
                "error": f"APK file not found: {raw_path}",
                "resolved_path": apk_path,
                "hint": (
                    f"Available APKs in inbox: {available}"
                    if available
                    else "No APKs in inbox. Ask the user to place an APK in the mounted APK folder."
                ),
            }

        if not os.path.basename(apk_path).lower().endswith(".apk"):
            return {
                "error": f"Input file is not an APK: {raw_path}",
                "resolved_path": apk_path,
                "hint": "Use list_inbox and pass an .apk file from the mounted APK folder.",
            }

        # Compute hash **before** creating session — this is the dedup key
        apk_hash, file_size = self._sm.compute_apk_hash(apk_path)
        session_id = apk_hash[:12]  # Short hash as session ID

        # ── Check for existing session with the same APK hash ──
        existing = self._sm.get_session_by_hash(apk_hash)

        if existing and not force_new:
            # Resume the existing session
            logger.info(
                "Resuming existing session {} for APK hash {}",
                existing.id,
                apk_hash[:12],
            )

            # Ensure app.apk is present — re-copy from inbox if it was deleted
            # or if a previous copy failed (e.g. permission error on first run).
            ws_dir = _workspace_path(existing)
            ws_apk = f"{ws_dir}/app.apk"
            if not os.path.isfile(ws_apk):
                logger.warning(
                    "app.apk missing from resumed workspace {} — re-copying from {}",
                    ws_dir,
                    apk_path,
                )
                os.makedirs(ws_dir, exist_ok=True)
                shutil.copy2(apk_path, ws_apk)
                # Workspace may also have been lost — clear stale decoded/decompiled paths
                existing.workspace_dir = ws_dir
                if existing.decoded_path and not os.path.isdir(existing.decoded_path):
                    existing.decoded_path = None
                if existing.decompiled_path and not os.path.isdir(existing.decompiled_path):
                    existing.decompiled_path = None

            return {
                "session_id": existing.id,
                "apk_path": apk_path,
                "apk_hash": apk_hash,
                "file_size": file_size,
                "file_size_mb": round(file_size / (1024 * 1024), 2),
                "workspace": existing.workspace_dir,
                "resumed": True,
                "decoded": existing.decoded_path is not None,
                "decompiled": existing.decompiled_path is not None,
                "prior_findings": len(existing.findings),
                "prior_tools": list(set(existing.tools_called)),
                "hint": (
                    "Existing analysis session resumed — all prior artifacts and "
                    "findings are intact. Continue where you left off. "
                    "To start fresh, call create_session with force_new=true."
                ),
            }

        # ── Force new: clean up old workspace if any ──
        if existing and force_new:
            old_ws = existing.workspace_dir
            if old_ws and os.path.isdir(old_ws):
                shutil.rmtree(old_ws, ignore_errors=True)
                logger.info("Pruned old workspace {}", old_ws)
            try:
                self._sm.delete_session(existing.id)
            except KeyError:
                pass

        # ── Create fresh session ──
        # Build the workspace and copy the APK before registering the session
        # so that a permission failure here doesn't leave an orphaned in-memory
        # session with no APK and no hash-index entry.
        host_ws = str(workspace_for_session_id(session_id))
        os.makedirs(host_ws, exist_ok=True)
        dest = os.path.join(host_ws, "app.apk")
        shutil.copy2(apk_path, dest)  # raises on failure — session not yet registered

        new_session = self._sm.create_session(apk_path, session_id=session_id)
        new_session.workspace_dir = host_ws

        if session_name:
            new_session.metadata["session_name"] = session_name

        new_session.metadata["apk_hash"] = apk_hash
        new_session.metadata["file_size"] = file_size

        # Register in hash index
        self._sm.index_hash(apk_hash, new_session.id)

        # Persist session metadata to survive restarts
        self._sm.save_session_meta(new_session)

        return {
            "session_id": new_session.id,
            "apk_path": apk_path,
            "apk_hash": apk_hash,
            "file_size": file_size,
            "file_size_mb": round(file_size / (1024 * 1024), 2),
            "workspace": host_ws,
            "resumed": False,
            "hint": (
                "Fresh session created. Proceed with detect_framework, "
                "check_apk_tampering, then plan_static_analysis."
            ),
        }


class GetApkMetadataTool(BaseTool):
    """Extract detailed APK metadata including package info and signing details.

    Uses aapt2 and apksigner to gather comprehensive APK information.
    """

    name = "get_apk_metadata"
    description = (
        "Get detailed APK metadata: package name, version, SDK targets, "
        "signing schemes, certificate info. Populates session.package_name "
        "and session.app_name automatically."
    )

    async def run(self, session: Optional[AnalysisSession], **kwargs: Any) -> dict:
        if session is None:
            return {"error": "No active session"}

        ws = _workspace_path(session)
        apk = f"{ws}/app.apk"

        # Run aapt2 dump badging
        stdout, stderr, rc = await run_local(
            ["aapt2", "dump", "badging", apk],
            timeout=60,
        )

        metadata: dict[str, Any] = {}

        if rc == 0:
            for line in stdout.splitlines():
                if line.startswith("package:"):
                    # Parse: package: name='...' versionCode='...' versionName='...'
                    for part in line.split(" "):
                        if part.startswith("name="):
                            metadata["package_name"] = part.split("=")[1].strip("'")
                        elif part.startswith("versionCode="):
                            metadata["version_code"] = part.split("=")[1].strip("'")
                        elif part.startswith("versionName="):
                            metadata["version_name"] = part.split("=")[1].strip("'")
                elif line.startswith("sdkVersion:"):
                    metadata["min_sdk"] = line.split(":")[1].strip().strip("'")
                elif line.startswith("targetSdkVersion:"):
                    metadata["target_sdk"] = line.split(":")[1].strip().strip("'")
                elif line.startswith("application-label:"):
                    metadata["app_name"] = line.split(":")[1].strip().strip("'")
                elif line.startswith("uses-permission:"):
                    if "permissions" not in metadata:
                        metadata["permissions"] = []
                    perm = line.split("name=")[1].strip().strip("'") if "name=" in line else ""
                    if perm:
                        metadata["permissions"].append(perm)
        else:
            metadata["aapt2_error"] = stderr[:500]

        # Run apksigner verify
        stdout, stderr, rc = await run_local(
            ["apksigner", "verify", "--verbose", "--print-certs", apk],
            timeout=30,
        )

        signing = {}
        if rc == 0:
            for line in stdout.splitlines():
                line = line.strip()
                if "Verified using v1 scheme" in line:
                    signing["v1"] = "true" in line.lower()
                elif "Verified using v2 scheme" in line:
                    signing["v2"] = "true" in line.lower()
                elif "Verified using v3 scheme" in line:
                    signing["v3"] = "true" in line.lower()
                elif "Verified using v4 scheme" in line:
                    signing["v4"] = "true" in line.lower()
                elif "Signer #1 certificate DN:" in line:
                    signing["cert_subject"] = line.split(":", 1)[1].strip()
                elif "Signer #1 certificate SHA-256" in line:
                    signing["cert_fingerprint_sha256"] = line.split(":", 1)[1].strip()
        else:
            signing["apksigner_error"] = stderr[:500]

        metadata["signing"] = signing

        # Update session metadata
        if "package_name" in metadata:
            session.package_name = metadata["package_name"]
        if "app_name" in metadata:
            session.app_name = metadata["app_name"]

        session.metadata["apk_metadata"] = metadata
        return metadata


class GetManifestTool(BaseTool):
    """Parse and return the full AndroidManifest.xml as a structured dict.

    Decodes the APK with apktool if not already decoded, then parses the
    manifest to extract permissions, components, and security-relevant attributes.
    """

    name = "get_manifest"
    description = (
        "Get the full parsed AndroidManifest.xml as a structured dict. "
        "Returns: package name, permissions, application attributes "
        "(debuggable, allowBackup, etc.), and all declared components."
    )

    async def run(self, session: Optional[AnalysisSession], **kwargs: Any) -> dict:
        if session is None:
            return {"error": "No active session"}

        try:
            xml_content, used_fallback = await _ensure_manifest_xml(session)
        except RuntimeError as exc:
            return {"error": f"Could not retrieve manifest: {exc}"}

        try:
            parsed = _parse_manifest_xml(xml_content)
        except ET.ParseError as e:
            return {
                "error": f"Manifest XML parse error: {e}",
                "raw_manifest": xml_content[:5000],
            }

        # Update session
        if parsed.get("package"):
            session.package_name = parsed["package"]
        if parsed.get("application_attributes", {}).get("label"):
            session.app_name = parsed["application_attributes"]["label"]

        session.metadata["manifest"] = parsed
        session.current_phase = AnalysisPhase.STATIC

        if used_fallback:
            parsed["_manifest_source"] = "apkInspector"
            parsed["_manifest_warning"] = (
                "apktool failed to decode this APK — the manifest was extracted "
                "using apkInspector's tamper-resilient parser instead. Resource "
                "references (e.g. @2131234567) are NOT resolved to human-readable "
                "names. Component and permission analysis is still valid."
            )
            logger.warning(
                "Manifest retrieved via apkInspector fallback (apktool failed)"
            )

        return parsed


class ListExportedComponentsTool(BaseTool):
    """List all exported components from the AndroidManifest.

    Returns activities, services, receivers, and providers that are exported
    (explicitly or implicitly via intent filters). Automatically creates
    Finding objects for exported components that lack permission protection.
    """

    name = "list_exported_components"
    description = (
        "List all exported activities, services, receivers, and providers. "
        "Automatically flags exported components without permission protection "
        "as security findings."
    )

    async def run(self, session: Optional[AnalysisSession], **kwargs: Any) -> dict:
        if session is None:
            return {"error": "No active session"}

        # Get or parse manifest
        if "manifest" not in session.metadata:
            try:
                xml_content, _ = await _ensure_manifest_xml(session)
                session.metadata["manifest"] = _parse_manifest_xml(xml_content)
            except (RuntimeError, ET.ParseError) as exc:
                return {"error": f"Cannot read manifest: {exc}"}

        manifest = session.metadata["manifest"]
        components = manifest.get("components", {})

        exported = {
            "activities": [],
            "services": [],
            "receivers": [],
            "providers": [],
        }

        findings_created = 0
        for comp_type, comp_list in components.items():
            for comp in comp_list:
                if comp.get("exported"):
                    exported[comp_type].append(comp)

                    # Create finding for unprotected exported components
                    if not comp.get("permission"):
                        finding = Finding(
                            title=f"Exported {comp_type[:-1]} without permission: {comp['name']}",
                            severity=Severity.INFO,
                            category=FindingCategory.EXPORTED_COMPONENT,
                            description=(
                                f"The {comp_type[:-1]} {comp['name']} is exported "
                                f"but has no permission requirement. Any app can interact with it."
                            ),
                    evidence="android:exported=\"true\", no android:permission set",
                            location=f"AndroidManifest.xml ({comp['name']})",
                            tool="list_exported_components",
                            phase=AnalysisPhase.RECON.value,
                            cwe_id="CWE-926",
                            recommendation=(
                                "Add android:permission to restrict access, or set "
                                "android:exported=\"false\" if external access is not needed."
                            ),
                        )
                        if session.add_finding(finding):
                            findings_created += 1

        total_exported = sum(len(v) for v in exported.values())
        return {
            "total_exported": total_exported,
            "findings_created": findings_created,
            **{k: v for k, v in exported.items()},
        }


class CheckManifestSecurityTool(BaseTool):
    """Check the AndroidManifest.xml for common security misconfigurations.

    Analyzes application attributes and component settings, creating findings
    for: debuggable=true, allowBackup=true, cleartext traffic, missing
    network security config, unprotected exported components.
    """

    name = "check_manifest_security"
    description = (
        "Check the manifest for security misconfigurations: debuggable, "
        "allowBackup, cleartext traffic, missing network security config, "
        "and unprotected exported components. Creates findings for each issue."
    )

    async def run(self, session: Optional[AnalysisSession], **kwargs: Any) -> dict:
        if session is None:
            return {"error": "No active session"}

        # Get or parse manifest
        if "manifest" not in session.metadata:
            try:
                xml_content, _ = await _ensure_manifest_xml(session)
                session.metadata["manifest"] = _parse_manifest_xml(xml_content)
            except (RuntimeError, ET.ParseError) as exc:
                return {"error": f"Cannot read manifest: {exc}"}

        manifest = session.metadata["manifest"]
        app_attrs = manifest.get("application_attributes", {})
        findings_created = []

        # Check debuggable
        if app_attrs.get("debuggable", "").lower() == "true":
            f = Finding(
                title="Application is debuggable",
                severity=Severity.HIGH,
                category=FindingCategory.CONFIGURATION_ISSUE,
                description=(
                    "The application has android:debuggable=\"true\" set in the manifest. "
                    "This allows any user to attach a debugger to the app, inspect memory, "
                    "and modify runtime behavior."
                ),
                evidence="android:debuggable=\"true\"",
                location="AndroidManifest.xml (application)",
                tool="check_manifest_security",
                phase=AnalysisPhase.RECON.value,
                cwe_id="CWE-489",
                recommendation="Set android:debuggable=\"false\" in release builds.",
            )
            if session.add_finding(f):
                findings_created.append(f.to_dict())

        # Check allowBackup
        if app_attrs.get("allowBackup", "").lower() == "true":
            f = Finding(
                title="Application allows backup",
                severity=Severity.MEDIUM,
                category=FindingCategory.INSECURE_DATA_STORAGE,
                description=(
                    "The application has android:allowBackup=\"true\". An attacker with "
                    "physical device access (or ADB) can extract the app's private data "
                    "via adb backup."
                ),
                evidence="android:allowBackup=\"true\"",
                location="AndroidManifest.xml (application)",
                tool="check_manifest_security",
                phase=AnalysisPhase.RECON.value,
                cwe_id="CWE-530",
                recommendation=(
                    "Set android:allowBackup=\"false\" or implement a BackupAgent "
                    "that excludes sensitive data."
                ),
            )
            if session.add_finding(f):
                findings_created.append(f.to_dict())

        # Check usesCleartextTraffic
        if app_attrs.get("usesCleartextTraffic", "").lower() == "true":
            f = Finding(
                title="Application allows cleartext traffic",
                severity=Severity.HIGH,
                category=FindingCategory.INSECURE_COMMUNICATION,
                description=(
                    "The application has android:usesCleartextTraffic=\"true\", allowing "
                    "unencrypted HTTP traffic. Sensitive data may be exposed to network "
                    "eavesdroppers."
                ),
                evidence="android:usesCleartextTraffic=\"true\"",
                location="AndroidManifest.xml (application)",
                tool="check_manifest_security",
                phase=AnalysisPhase.RECON.value,
                cwe_id="CWE-319",
                recommendation=(
                    "Set android:usesCleartextTraffic=\"false\" and use HTTPS for all "
                    "network communication."
                ),
            )
            if session.add_finding(f):
                findings_created.append(f.to_dict())

        # Check missing networkSecurityConfig
        if not app_attrs.get("networkSecurityConfig"):
            f = Finding(
                title="Missing Network Security Configuration",
                severity=Severity.MEDIUM,
                category=FindingCategory.CONFIGURATION_ISSUE,
                description=(
                    "The application does not declare a networkSecurityConfig. "
                    "A custom network security config allows fine-grained control "
                    "over TLS settings, certificate pinning, and cleartext traffic policies."
                ),
                evidence="No android:networkSecurityConfig attribute in <application>",
                location="AndroidManifest.xml (application)",
                tool="check_manifest_security",
                phase=AnalysisPhase.RECON.value,
                cwe_id="CWE-295",
                recommendation=(
                    "Add a network_security_config.xml that enforces HTTPS, "
                    "pins known certificates, and disables cleartext traffic."
                ),
            )
            if session.add_finding(f):
                findings_created.append(f.to_dict())

        # Check exported services/receivers without intent filters
        components = manifest.get("components", {})
        for comp_type in ["services", "receivers"]:
            for comp in components.get(comp_type, []):
                if (
                    comp.get("exported")
                    and comp.get("explicit_exported") == "true"
                    and not comp.get("intent_filters")
                    and not comp.get("permission")
                ):
                    f = Finding(
                        title=(
                            f"Explicitly exported {comp_type[:-1]} without intent filter: "
                            f"{comp['name']}"
                        ),
                        severity=Severity.HIGH,
                        category=FindingCategory.EXPORTED_COMPONENT,
                        description=(
                            f"The {comp_type[:-1]} {comp['name']} is explicitly exported "
                            f"without any intent filter or permission. This is unusual and "
                            f"may indicate an unprotected entry point."
                        ),
                        evidence=(
                            "android:exported=\"true\", no intent-filter, "
                            "no android:permission"
                        ),
                        location=f"AndroidManifest.xml ({comp['name']})",
                        tool="check_manifest_security",
                        phase=AnalysisPhase.RECON.value,
                        cwe_id="CWE-926",
                        recommendation=(
                            "Remove android:exported=\"true\" if not needed, or "
                            "add permission protection."
                        ),
                    )
                    if session.add_finding(f):
                        findings_created.append(f.to_dict())

        return {
            "findings_count": len(findings_created),
            "findings": findings_created,
            "checked": [
                "debuggable",
                "allowBackup",
                "usesCleartextTraffic",
                "networkSecurityConfig",
                "exported_services_without_filters",
                "exported_receivers_without_filters",
            ],
        }
