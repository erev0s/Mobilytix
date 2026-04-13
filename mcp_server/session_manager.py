"""Session manager — CRUD operations for analysis sessions.

Provides in-memory storage of AnalysisSession objects keyed by session ID.
Supports discovering sessions from existing workspace directories on disk
and looking up sessions by APK hash to avoid duplicate analysis.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
from pathlib import Path
from datetime import datetime

from loguru import logger

from .models.enums import AnalysisPhase
from .models.finding import Finding
from .models.session import AnalysisSession


class SessionManager:
    """Manages the lifecycle of APK analysis sessions."""

    def __init__(self) -> None:
        self._sessions: dict[str, AnalysisSession] = {}
        # Index: apk_hash → session_id  (for dedup)
        self._hash_index: dict[str, str] = {}

    def create_session(self, apk_path: str, session_id: str | None = None) -> AnalysisSession:
        """Create a new analysis session for the given APK.

        Args:
            apk_path: Path to the APK file (host or container path).
            session_id: Optional explicit session ID (e.g. hash-based).
                        If None, a random UUID is generated.

        Returns:
            The newly created AnalysisSession.
        """
        session = AnalysisSession(apk_path=apk_path, id=session_id) if session_id else AnalysisSession(apk_path=apk_path)
        self._sessions[session.id] = session
        logger.info("Created session {} for APK: {}", session.id, apk_path)
        return session

    def register_session(self, session: AnalysisSession) -> None:
        """Register an externally-created session (e.g. rehydrated from disk)."""
        self._sessions[session.id] = session
        apk_hash = session.metadata.get("apk_hash")
        if apk_hash:
            self._hash_index[apk_hash] = session.id
        logger.info("Registered session {} (hash={})", session.id, apk_hash or "?")

    def index_hash(self, apk_hash: str, session_id: str) -> None:
        """Record the mapping from APK hash → session ID."""
        self._hash_index[apk_hash] = session_id

    def get_session_by_hash(self, apk_hash: str) -> AnalysisSession | None:
        """Look up a session by APK SHA256 hash. Returns None if not found."""
        sid = self._hash_index.get(apk_hash)
        if sid and sid in self._sessions:
            return self._sessions[sid]
        return None

    def get_session(self, session_id: str) -> AnalysisSession:
        """Retrieve a session by ID.

        Args:
            session_id: The unique session identifier.

        Returns:
            The matching AnalysisSession.

        Raises:
            KeyError: If no session with that ID exists.
        """
        if session_id not in self._sessions:
            raise KeyError(f"Session not found: {session_id}")
        return self._sessions[session_id]

    def list_sessions(self) -> list[AnalysisSession]:
        """Return all active sessions."""
        return list(self._sessions.values())

    def delete_session(self, session_id: str) -> None:
        """Delete a session by ID.

        Args:
            session_id: The unique session identifier.

        Raises:
            KeyError: If no session with that ID exists.
        """
        if session_id not in self._sessions:
            raise KeyError(f"Session not found: {session_id}")
        session = self._sessions[session_id]
        # Remove from hash index
        apk_hash = session.metadata.get("apk_hash")
        if apk_hash and self._hash_index.get(apk_hash) == session_id:
            del self._hash_index[apk_hash]
        del self._sessions[session_id]
        logger.info("Deleted session {}", session_id)

    def has_session(self, session_id: str) -> bool:
        """Check if a session exists."""
        return session_id in self._sessions

    # ------------------------------------------------------------------
    # Workspace discovery — scan /workspace for previous sessions
    # ------------------------------------------------------------------

    def discover_sessions(self, workspace_root: str) -> int:
        """Scan the workspace directory for existing session workspaces.

        Each subdirectory that contains an ``app.apk`` is treated as a
        prior session.  A lightweight AnalysisSession is rehydrated with
        whatever metadata can be recovered from disk (hash, decoded/
        decompiled paths, saved ``session.json``).

        Returns the number of sessions discovered.
        """
        if not os.path.isdir(workspace_root):
            return 0

        count = 0
        for entry in os.listdir(workspace_root):
            session_dir = os.path.join(workspace_root, entry)
            apk_file = os.path.join(session_dir, "app.apk")
            if not os.path.isdir(session_dir) or not os.path.isfile(apk_file):
                continue
            if entry in self._sessions:
                continue  # already known

            # Rehydrate session
            session = self._rehydrate_session(entry, session_dir, apk_file)
            if session:
                self.register_session(session)
                count += 1

        logger.info("Discovered {} existing sessions in {}", count, workspace_root)
        return count

    @staticmethod
    def _rehydrate_session(
        session_id: str, session_dir: str, apk_file: str
    ) -> AnalysisSession | None:
        """Rebuild an AnalysisSession from an existing workspace directory."""
        try:
            # Try loading saved metadata first
            meta_path = os.path.join(session_dir, "session.json")
            metadata: dict = {}
            if os.path.isfile(meta_path):
                with open(meta_path) as f:
                    metadata = json.load(f)

            # Compute hash if not in metadata
            if "apk_hash" not in metadata:
                sha256 = hashlib.sha256()
                with open(apk_file, "rb") as f:
                    for chunk in iter(lambda: f.read(8192), b""):
                        sha256.update(chunk)
                metadata["apk_hash"] = sha256.hexdigest()
                metadata["file_size"] = os.path.getsize(apk_file)

            session = AnalysisSession(apk_path=apk_file, id=session_id)
            session.metadata = metadata
            session.workspace_dir = session_dir
            session.tools_called = list(metadata.get("tools_called") or [])
            findings = metadata.get("findings") or []
            if isinstance(findings, list):
                session.findings = [
                    Finding.from_dict(item)
                    for item in findings
                    if isinstance(item, dict)
                ]

            phase = metadata.get("current_phase")
            if isinstance(phase, str):
                try:
                    session.current_phase = AnalysisPhase(phase)
                except ValueError:
                    pass

            created_at = metadata.get("created_at")
            if isinstance(created_at, str):
                try:
                    session.created_at = datetime.fromisoformat(created_at)
                except ValueError:
                    pass

            # Recover decoded / decompiled paths if they exist
            decoded = os.path.join(session_dir, "decoded")
            if os.path.isdir(decoded):
                session.decoded_path = decoded
            decompiled = os.path.join(session_dir, "decompiled")
            if os.path.isdir(decompiled):
                session.decompiled_path = decompiled

            # Recover package name / app name from metadata
            apk_meta = metadata.get("apk_metadata") or {}
            if metadata.get("package_name"):
                session.package_name = metadata["package_name"]
            elif apk_meta.get("package_name"):
                session.package_name = apk_meta["package_name"]
            if metadata.get("app_name"):
                session.app_name = metadata["app_name"]
            elif apk_meta.get("app_name"):
                session.app_name = apk_meta["app_name"]

            logger.debug(
                "Rehydrated session {} (hash={})",
                session_id,
                metadata.get("apk_hash", "?")[:12],
            )
            return session
        except Exception as exc:
            logger.warning("Failed to rehydrate session {}: {}", session_id, exc)
            return None

    @staticmethod
    def compute_apk_hash(apk_path: str) -> tuple[str, int]:
        """Compute SHA256 hash and size of an APK file.

        Returns (hex_hash, file_size_bytes).
        """
        sha256 = hashlib.sha256()
        size = 0
        with open(apk_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
                size += len(chunk)
        return sha256.hexdigest(), size

    @staticmethod
    def save_session_meta(session: AnalysisSession) -> None:
        """Persist key session metadata to disk so it survives restarts."""
        ws = session.workspace_dir
        if not ws or not os.path.isdir(ws):
            return
        meta_path = os.path.join(ws, "session.json")
        try:
            payload = {
                "apk_hash": session.metadata.get("apk_hash"),
                "file_size": session.metadata.get("file_size"),
                "apk_metadata": session.metadata.get("apk_metadata"),
                "framework": session.metadata.get("framework"),
                "artifact_index": session.metadata.get("artifact_index"),
                "static_route": session.metadata.get("static_route"),
                "flutter_aot": session.metadata.get("flutter_aot"),
                "tampering": session.metadata.get("tampering"),
                "package_name": session.package_name,
                "app_name": session.app_name,
                "current_phase": session.current_phase.value,
                "tools_called": list(session.tools_called),
                "findings": [f.to_dict() for f in session.findings],
                "created_at": session.created_at.isoformat(),
            }
            with open(meta_path, "w") as f:
                json.dump(payload, f, indent=2, default=str)
        except Exception as exc:
            logger.warning("Failed to save session meta: {}", exc)
