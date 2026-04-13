"""Tests for configuration and workspace fallback behavior."""

from pathlib import Path
from unittest.mock import patch

from mcp_server.config import ensure_workspace_dir, load_config


def test_load_config_does_not_create_workspace_on_load(tmp_path):
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "platform:\n"
        "  workspace_dir: /workspace\n"
        "  log_level: INFO\n",
        encoding="utf-8",
    )

    with patch("mcp_server.config.Path.mkdir", side_effect=AssertionError("unexpected mkdir")):
        cfg = load_config(str(config_path))

    assert cfg.platform.workspace_dir == "/workspace"


def test_ensure_workspace_dir_falls_back_on_oserror(tmp_path):
    desired = Path("/workspace")
    fallback = tmp_path / "fallback-workspace"

    def fake_mkdir(self, parents=False, exist_ok=False):
        if self == desired:
            raise OSError(30, "Read-only file system")
        return None

    with (
        patch("mcp_server.config.FALLBACK_WORKSPACE_DIR", fallback),
        patch("mcp_server.config.Path.mkdir", new=fake_mkdir),
    ):
        resolved = ensure_workspace_dir(str(desired))

    assert resolved == fallback
