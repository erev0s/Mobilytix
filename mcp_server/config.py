"""Configuration loader for Mobilytix.

Loads config from config/config.yaml, falling back to config/config.example.yaml.
Environment variables can override config values:
  MOBILYTIX_WORKSPACE  -> platform.workspace_dir
  MOBILYTIX_LOG_LEVEL  -> platform.log_level
  MOBILYTIX_TRANSPORT  -> mcp.transport
  MOBILYTIX_HOST       -> mcp.host
  MOBILYTIX_PORT       -> mcp.port
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml
from loguru import logger


def _find_project_root() -> Path:
    """Walk up from this file to find the project root (contains pyproject.toml)."""
    current = Path(__file__).resolve().parent.parent
    for candidate in [current, current.parent]:
        if (candidate / "pyproject.toml").exists():
            return candidate
    return current


PROJECT_ROOT = _find_project_root()
FALLBACK_WORKSPACE_DIR = Path("/tmp/mobilytix-workspace")


@dataclass
class PlatformConfig:
    workspace_dir: str = "/tmp/Mobilytix"
    log_level: str = "INFO"


@dataclass
class McpConfig:
    transport: str = "http"  # http | stdio
    host: str = "127.0.0.1"
    port: int = 3000


@dataclass
class DockerConfig:
    android_image: str = "erev0s/mobilytix:android-latest"
    static_image: str = "erev0s/mobilytix:static-latest"
    static_container: str = "mobilytix-static"
    android_container: str = "mobilytix-android"
    adb_port: int = 5555
    frida_port: int = 27042
    mitmproxy_port: int = 8080


@dataclass
class MobilytixConfig:
    platform: PlatformConfig = field(default_factory=PlatformConfig)
    mcp: McpConfig = field(default_factory=McpConfig)
    docker: DockerConfig = field(default_factory=DockerConfig)

    @classmethod
    def from_dict(cls, data: dict) -> "MobilytixConfig":
        """Create config from a dictionary (parsed YAML)."""
        cfg = cls()
        if "platform" in data:
            for k, v in data["platform"].items():
                if hasattr(cfg.platform, k):
                    setattr(cfg.platform, k, v)
        if "mcp" in data:
            for k, v in data["mcp"].items():
                if hasattr(cfg.mcp, k):
                    setattr(cfg.mcp, k, v)
        if "docker" in data:
            for k, v in data["docker"].items():
                if hasattr(cfg.docker, k):
                    setattr(cfg.docker, k, v)
        return cfg


def load_config(config_path: Optional[str] = None) -> MobilytixConfig:
    """Load configuration from YAML file.

    Search order:
      1. Explicit config_path argument
      2. MOBILYTIX_CONFIG env var
      3. config/config.yaml (project root)
      4. config/config.example.yaml (project root)
      5. Defaults
    """
    paths_to_try = []

    if config_path:
        paths_to_try.append(Path(config_path))

    env_path = os.environ.get("MOBILYTIX_CONFIG")
    if env_path:
        paths_to_try.append(Path(env_path))

    paths_to_try.append(PROJECT_ROOT / "config" / "config.yaml")
    paths_to_try.append(PROJECT_ROOT / "config" / "config.example.yaml")

    data: dict = {}
    for p in paths_to_try:
        if p.exists():
            logger.info("Loading config from {}", p)
            with open(p) as f:
                data = yaml.safe_load(f) or {}
            break
    else:
        logger.warning("No config file found, using defaults")

    cfg = MobilytixConfig.from_dict(data)

    # Environment variable overrides
    if ws := os.environ.get("MOBILYTIX_WORKSPACE"):
        cfg.platform.workspace_dir = ws
    if ll := os.environ.get("MOBILYTIX_LOG_LEVEL"):
        cfg.platform.log_level = ll
    if transport := os.environ.get("MOBILYTIX_TRANSPORT"):
        cfg.mcp.transport = transport
    if host := os.environ.get("MOBILYTIX_HOST"):
        cfg.mcp.host = host
    if port := os.environ.get("MOBILYTIX_PORT"):
        try:
            cfg.mcp.port = int(port)
        except ValueError:
            logger.warning("Invalid MOBILYTIX_PORT value {!r}; using {}", port, cfg.mcp.port)

    return cfg


def ensure_workspace_dir(path: str) -> Path:
    """Return a writable workspace directory, falling back to /tmp when needed."""
    workspace = Path(path)
    try:
        workspace.mkdir(parents=True, exist_ok=True)
        return workspace
    except OSError as exc:
        fallback = FALLBACK_WORKSPACE_DIR
        fallback.mkdir(parents=True, exist_ok=True)
        logger.warning(
            "Cannot create workspace at {} ({}: {}) - falling back to {}",
            workspace,
            type(exc).__name__,
            exc,
            fallback,
        )
        return fallback


# Global config instance — loaded on first import
config = load_config()
