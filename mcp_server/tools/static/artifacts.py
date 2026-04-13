"""Framework-aware artifact indexing and static route planning tools."""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any, Optional

from mcp_server.backends.local_backend import run_local
from mcp_server.models.session import AnalysisSession
from mcp_server.tools.base import BaseTool
from mcp_server.tools.static.routing import (
    ARTIFACT_CATEGORIES,
    build_static_route,
    ensure_artifact_index,
    ensure_framework_metadata,
    extract_artifact_to_workspace,
    normalize_scope,
)
from mcp_server.tools.workspace import ensure_session_artifact_path, session_workspace


def _artifact_lookup(
    artifact_index: dict[str, Any], artifact_path: str
) -> tuple[str, dict[str, Any]] | tuple[None, None]:
    for category, items in artifact_index.get("artifacts", {}).items():
        for item in items:
            if item["path"] == artifact_path:
                return category, item
    return None, None


def _iter_scope_artifacts(
    artifact_index: dict[str, Any], scope: str | None = None
) -> list[tuple[str, dict[str, Any]]]:
    categories = [scope] if scope else list(ARTIFACT_CATEGORIES)
    artifacts: list[tuple[str, dict[str, Any]]] = []
    for category in categories:
        for item in artifact_index.get("artifacts", {}).get(category, []):
            artifacts.append((category, item))
    return artifacts


def _search_cache_root(session: AnalysisSession) -> Path:
    return ensure_session_artifact_path(session, "artifacts", "text_cache")


def _stage_text_artifacts(
    session: AnalysisSession,
    artifact_index: dict[str, Any],
    scope: str | None,
) -> tuple[Path, int]:
    cache_root = _search_cache_root(session)
    staged = 0

    for _, artifact in _iter_scope_artifacts(artifact_index, scope):
        if not artifact.get("text_compatible"):
            continue
        dest = cache_root / artifact["path"]
        if dest.exists():
            staged += 1
            continue
        src = extract_artifact_to_workspace(session, artifact["path"])
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(src.read_bytes())
        staged += 1

    return cache_root, staged


def _parse_rg_matches(raw: str, root: Path, artifact_index: dict[str, Any]) -> tuple[list[dict[str, Any]], int]:
    matches: list[dict[str, Any]] = []
    total_matches = 0

    for line in raw.splitlines():
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue

        if obj.get("type") == "match":
            data = obj["data"]
            full_path = Path(data["path"]["text"])
            rel_path = str(full_path.relative_to(root))
            category, artifact = _artifact_lookup(artifact_index, rel_path)
            matches.append(
                {
                    "artifact_path": rel_path,
                    "category": category,
                    "format_hint": artifact["format_hint"] if artifact else None,
                    "line": data["line_number"],
                    "match": data["lines"]["text"].rstrip("\n"),
                    "submatches": [sm["match"]["text"] for sm in data.get("submatches", [])],
                }
            )
            total_matches += 1
        elif obj.get("type") == "summary":
            stats = obj.get("data", {}).get("stats", {})
            total_matches = stats.get("matches", total_matches)

    return matches, total_matches


def _ensure_tampering_metadata(session: AnalysisSession) -> dict[str, Any]:
    cached = session.metadata.get("tampering")
    if cached:
        return cached

    from mcp_server.tools.static.tampering import CheckApkTamperingTool

    apk_path = f"{session_workspace(session)}/app.apk"
    tool = CheckApkTamperingTool()
    result = tool._check_tampering(apk_path, strict=False)
    session.metadata["tampering"] = result
    return result


class PlanStaticAnalysisTool(BaseTool):
    """Build an ordered static-analysis route based on APK framework and containers."""

    name = "plan_static_analysis"
    description = (
        "Plan the framework-aware static analysis workflow for the active APK. "
        "Computes or reuses framework detection, artifact inventory, and tampering metadata, "
        "then returns ordered next steps, recommended tools, wrapper-only tools, and dynamic follow-up hypotheses."
    )

    async def run(self, session: Optional[AnalysisSession], **kwargs: Any) -> dict:
        if session is None:
            return {"error": "No active session"}

        framework = ensure_framework_metadata(session)
        artifact_index = ensure_artifact_index(session)
        tampering = _ensure_tampering_metadata(session)
        route = build_static_route(session, framework=framework, artifact_index=artifact_index, tampering=tampering)

        result = {
            **route,
            "framework": framework,
            "tampering_verdict": ((tampering or {}).get("assessment") or {}).get("verdict", "UNKNOWN"),
            "artifact_summary": artifact_index["counts"],
            "hint": (
                "Follow the ordered steps above. Use the primary deep-analysis step first, "
                "then use wrapper-only tools only for bridge or manifest context."
            ),
        }

        return result


class ListStaticArtifactsTool(BaseTool):
    """List APK artifacts grouped by framework-aware category."""

    name = "list_static_artifacts"
    description = (
        "Index APK artifacts into dex, web_assets, js_bundle, native_libs, managed_assemblies, "
        "config, and engine_assets. Returns paths, sizes, format hints, and artifact roots."
    )

    def input_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": "Active analysis session ID",
                },
                "scope": {
                    "type": "string",
                    "enum": list(ARTIFACT_CATEGORIES),
                    "description": "Optional category filter.",
                },
            },
            "required": ["session_id"],
        }

    async def run(self, session: Optional[AnalysisSession], **kwargs: Any) -> dict:
        if session is None:
            return {"error": "No active session"}

        try:
            scope = normalize_scope(kwargs.get("scope"))
        except ValueError as exc:
            return {"error": str(exc)}

        artifact_index = ensure_artifact_index(session)
        framework = ensure_framework_metadata(session)

        categories = [scope] if scope else list(ARTIFACT_CATEGORIES)
        artifacts = {
            category: artifact_index["artifacts"][category]
            for category in categories
            if artifact_index["artifacts"].get(category)
        }
        counts = {category: artifact_index["counts"][category] for category in categories}

        result = {
            "scope": scope or "all",
            "primary_container": framework.get("primary_container"),
            "artifact_roots": {
                category: artifact_index["artifact_roots"].get(category, [])
                for category in categories
                if artifact_index["artifact_roots"].get(category)
            },
            "counts": counts,
            "artifacts": artifacts,
            "total_indexed": sum(counts.values()),
            "hint": "Use read_static_artifact to inspect one file or search_static_artifacts to grep text-compatible assets.",
        }
        return result


class ReadStaticArtifactTool(BaseTool):
    """Read a specific APK artifact by its APK-relative path."""

    name = "read_static_artifact"
    description = (
        "Read a specific APK artifact by path as returned by list_static_artifacts. "
        "Best for JS bundles, HTML, JSON, XML, config files, and other text-friendly assets."
    )

    def input_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": "Active analysis session ID",
                },
                "path": {
                    "type": "string",
                    "description": "APK-relative artifact path returned by list_static_artifacts.",
                },
                "mode": {
                    "type": "string",
                    "enum": ["text", "base64"],
                    "default": "text",
                    "description": "Read mode. Use base64 for binary-heavy artifacts.",
                },
            },
            "required": ["session_id", "path"],
        }

    async def run(self, session: Optional[AnalysisSession], **kwargs: Any) -> dict:
        if session is None:
            return {"error": "No active session"}

        artifact_path = kwargs["path"]
        mode = kwargs.get("mode", "text")
        artifact_index = ensure_artifact_index(session)
        category, artifact = _artifact_lookup(artifact_index, artifact_path)

        if artifact is None:
            return {"error": f"Artifact not found: {artifact_path}"}

        try:
            extracted = extract_artifact_to_workspace(session, artifact_path)
        except (FileNotFoundError, ValueError) as exc:
            return {"error": str(exc)}

        raw_bytes = extracted.read_bytes()
        binary_warning = None

        if mode == "base64":
            content = base64.b64encode(raw_bytes).decode("ascii")
        else:
            if not artifact.get("text_compatible"):
                binary_warning = (
                    "This artifact is not strongly text-compatible; output may contain replacement characters. "
                    "Use mode='base64' if you need raw bytes."
                )
            content = raw_bytes.decode("utf-8", errors="replace")

        max_chars = 50000
        truncated = len(content) > max_chars
        result = {
            "path": artifact_path,
            "category": category,
            "format_hint": artifact.get("format_hint"),
            "mode": mode,
            "content": content[:max_chars],
            "truncated": truncated,
            "total_chars": len(content),
        }
        if binary_warning:
            result["warning"] = binary_warning
        return result


class SearchStaticArtifactsTool(BaseTool):
    """Search text-compatible APK artifacts with ripgrep."""

    name = "search_static_artifacts"
    description = (
        "Search text-compatible APK artifacts with ripgrep. Best for JS bundles, web assets, "
        "Flutter asset config, and other non-DEX files."
    )

    def input_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": "Active analysis session ID",
                },
                "pattern": {
                    "type": "string",
                    "description": "Regex pattern to search for.",
                },
                "scope": {
                    "type": "string",
                    "enum": list(ARTIFACT_CATEGORIES),
                    "description": "Optional artifact category filter.",
                },
                "file_filter": {
                    "type": "string",
                    "description": "Optional ripgrep glob filter.",
                },
                "context_lines": {
                    "type": "integer",
                    "default": 3,
                    "description": "Context lines before/after each match.",
                },
            },
            "required": ["session_id", "pattern"],
        }

    async def run(self, session: Optional[AnalysisSession], **kwargs: Any) -> dict:
        if session is None:
            return {"error": "No active session"}

        try:
            scope = normalize_scope(kwargs.get("scope"))
        except ValueError as exc:
            return {"error": str(exc)}

        artifact_index = ensure_artifact_index(session)
        cache_root, staged = _stage_text_artifacts(session, artifact_index, scope)
        if staged == 0:
            return {
                "pattern": kwargs["pattern"],
                "scope": scope or "all",
                "total_matches": 0,
                "matches": [],
                "warning": "No text-compatible artifacts were available in the requested scope.",
            }

        pattern = kwargs["pattern"]
        file_filter = kwargs.get("file_filter")
        context_lines = kwargs.get("context_lines", 3)

        cmd = [
            "rg",
            "--json",
            "-C",
            str(context_lines),
            "--max-count",
            "50",
        ]
        if file_filter:
            cmd.extend(["-g", file_filter])
        cmd.extend([pattern, str(cache_root)])

        stdout, stderr, rc = await run_local(cmd, timeout=60)
        if rc >= 2:
            return {"error": f"Artifact search failed: {stderr[:500]}"}

        matches, total_matches = _parse_rg_matches(stdout, cache_root, artifact_index)

        return {
            "pattern": pattern,
            "scope": scope or "all",
            "searched_artifacts": staged,
            "total_matches": total_matches,
            "matches_shown": len(matches),
            "truncated": total_matches > 50,
            "matches": matches[:50],
        }
