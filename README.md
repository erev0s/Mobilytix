# Mobilytix

![Mobilytix](mobilytix-logo.png)

Mobilytix is an MCP server for AI-assisted mobile application penetration testing. The current release focuses on Android APKs: it wraps tooling such as `jadx`, `apktool`, `aapt2`, `apkInspector`, `Frida`, `adb`, `mitmproxy`, and related helpers so any MCP-capable AI agent or client can run structured analysis, collect findings, and persist the work across restarts.

## What works today

Mobilytix currently supports:

- MCP access over Streamable HTTP for any MCP-capable AI agent or client
- local stdio MCP mode for development and clients that prefer stdio
- Android APK session management with persisted workspaces, decoded artifacts, generated outputs, tool history, and findings
- Android static analysis for manifests, exported components, framework detection, tampering checks, decompilation, source/artifact search, secrets, SAST, certificates, crypto patterns, native libraries, and common cross-platform Android app frameworks
- Android dynamic analysis through the Docker dynamic profile, including emulator setup, app install/launch, UI inspection/actions, logcat, Frida scripts, screenshots, and app data inspection
- mitmproxy-assisted traffic review through `start_traffic_capture`, `stop_traffic_capture`, `get_captured_requests`, `get_captured_flow_body`, and `find_sensitive_traffic`
- findings management and report generation through MCP tools

## Benchmark results

Mobilytix was evaluated against a curated set of 42 vulnerabilities drawn from two open-source intentionally-vulnerable Android apps:

- [Ostorlab insecure Android app](https://github.com/Ostorlab/ostorlab_insecure_android_app) — covers Android-native and Flutter/AOT rule classes
- [Allsafe Android](https://github.com/t0thkr1s/allsafe-android) — covers a broad range of common Android weaknesses

Column key: **Expected** = ground-truth vulnerabilities the report should find; **Instance TP** = exact matches (correct mechanism, sink, or code path); **Instance recall** = Instance TP ÷ Expected; **Family-level recall** = exact + family-level matches ÷ Expected (directional coverage even without exact detail); **FN** = misses (expected but not found).

| Dataset | Expected | Instance TP | Instance recall | Family-level recall | FN |
|---|---:|---:|---:|---:|---:|
| Allsafe filtered | 7 | 5 | 71.4% | 85.7% | 2 |
| Ostorlab Android-native | 22 | 21 | 95.5% | 100.0% | 1 |
| Ostorlab Flutter | 13 | 12 | 92.3% | 100.0% | 1 |
| **Total** | **42** | **38** | **90.5%** | **97.6%** | **4** |

Overall strict instance recall is **90.5%** (38/42) and family-level recall is **97.6%** (41/42). See `benchmark/mobilytix_pentest_benchmark_evaluation.md` for full scoring methodology and per-finding detail.

## Future work and limits

- iOS and IPA analysis are planned future work; the current runtime and toolset are Android-focused.
- Dynamic analysis currently targets an Android emulator. The optional Docker dynamic profile needs Linux with KVM.
- HTTPS interception is assisted, not guaranteed. It depends on emulator proxy state, mitmproxy CA installation, and the target app's trust behavior; apps with certificate pinning or custom trust logic can require manual follow-up.

## Quick start

This is the primary new-user path. It pulls prebuilt images from Docker Hub and exposes Mobilytix over HTTP MCP on the local host.

### Prerequisites

- Docker Engine
- Docker Compose v2
- An MCP client that supports HTTP / Streamable HTTP
- Linux with KVM only if you want the optional Android emulator profile

### Start the runtime

1. Create a runtime env file and set the host mount paths:

```bash
cp .env.runtime.example .env.runtime
```

Set these values in `.env.runtime`:

- `MOBILYTIX_APK_INPUT_DIR`: host folder containing APKs to analyze
- `MOBILYTIX_WORKSPACE_DIR`: absolute host folder outside this repo where Mobilytix should persist sessions and artifacts
- `MOBILYTIX_IMAGE_TAG`: base image tag to pull, usually `latest`; the runtime uses `static-<tag>` and `android-<tag>`
- `MOBILYTIX_IMAGE_REPOSITORY`: optional Docker Hub repository override; default is `erev0s/mobilytix`

2. Start the default runtime:

```bash
docker compose --env-file .env.runtime -f docker/docker-compose.runtime.yml up -d
```

This starts:

- `static`: the Mobilytix MCP server on `http://localhost:3000/mcp`
- `mitmproxy`: traffic interception backend used by Mobilytix

Default runtime exposure is local-first:

- the MCP HTTP endpoint is bound to `127.0.0.1:3000` on the host
- the optional dynamic profile binds emulator control/viewer ports to `127.0.0.1`
- the MCP server still listens on `0.0.0.0` inside the container so Docker port forwarding works

Do not change the host bindings to `0.0.0.0` unless the host is in an isolated
lab network or the services are behind your own auth/reverse-proxy layer.

3. Point your MCP client at:

```text
http://localhost:3000/mcp
```

Example client config for HTTP-capable MCP clients:

```json
{
  "mcpServers": {
    "mobilytix": {
      "url": "http://localhost:3000/mcp"
    }
  }
}
```

Claude Terminal can add the running HTTP MCP server with:

```bash
claude mcp add --transport http mobilytix http://localhost:3000/mcp
```

4. Ask your client to analyze an APK. The tool flow is:

- `list_inbox` to discover APKs from the mounted `/inbox`
- `create_session` with a filename such as `app.apk`
- framework-aware static and optional dynamic analysis tools

### Optional profiles

Start the Android emulator for dynamic analysis:

```bash
docker compose --env-file .env.runtime --profile dynamic -f docker/docker-compose.runtime.yml up -d
```

Start the MCP Inspector UI:

```bash
docker compose --env-file .env.runtime --profile inspector -f docker/docker-compose.runtime.yml up -d
```

### What persists across restarts

Mobilytix persists all session state under the mounted `/workspace` directory. This directory is user-defined through `MOBILYTIX_WORKSPACE_DIR` and should stay outside the public repository. For each session this includes:

- `session.json`
- the copied `app.apk`
- decoded and decompiled artifacts
- generated outputs such as `semgrep_output.json` and `apkleaks_output.json`
- findings and tool history restored by session rehydration on startup

## Develop Mobilytix

This path is for contributors working from source.

### Contributor workflow

```bash
git clone https://github.com/erev0s/Mobilytix
cd Mobilytix
export MOBILYTIX_APK_INPUT_DIR=/absolute/path/to/your/apks
export MOBILYTIX_WORKSPACE_DIR=/absolute/path/to/your/workspace
./scripts/setup.sh
```

The contributor compose file still builds images locally and keeps the same in-container paths:

- APK input mounted at `/inbox`
- session workspace mounted at `/workspace`

For local stdio development you can still run:

```bash
python -m mcp_server
```

For local HTTP development:

```bash
python -m mcp_server --http
```

### Publishing images

Both runtime images are in one Docker Hub repository with different tags:

- `erev0s/mobilytix:static-<tag>`
- `erev0s/mobilytix:android-<tag>`

## Tools

Mobilytix exposes 63 tools across static and dynamic analysis phases. See [TOOLS.md](TOOLS.md) for the full parameter reference.

| Category | Tools |
|----------|-------|
| Session management | `list_inbox`, `create_session`, `get_analysis_status`, `list_sessions`, `prune_session` |
| Reconnaissance | `detect_framework`, `check_apk_tampering`, `plan_static_analysis`, `get_apk_metadata`, `get_manifest`, `list_exported_components`, `check_manifest_security` |
| Framework artifacts | `list_static_artifacts`, `search_static_artifacts`, `read_static_artifact`, `analyze_flutter_aot`, `analyze_flutter_debug`, `analyze_react_native_bundle`, `analyze_web_hybrid`, `analyze_managed_assemblies`, `analyze_unity_metadata` |
| Code analysis | `decompile_apk`, `search_source`, `read_source_file`, `get_class_list`, `analyze_class`, `get_security_overview` |
| Secrets & SAST | `scan_secrets`, `run_sast`, `analyze_certificate`, `find_crypto_issues` |
| Native | `list_native_libs`, `analyze_native_strings`, `analyze_native_binary`, `disassemble_native_function`, `decompile_native_function` |
| Dynamic — device | `start_dynamic_session`, `ensure_frida_server`, `install_apk`, `launch_app`, `stop_app`, `get_logcat`, `list_running_processes`, `take_screenshot` |
| Dynamic — UI | `inspect_ui`, `ui_action`, `wait_for_ui` |
| Dynamic — Frida | `list_loaded_classes`, `run_frida_script`, `run_frida_codeshare_script` |
| Dynamic — traffic | `start_traffic_capture`, `stop_traffic_capture`, `get_captured_requests`, `get_captured_flow_body`, `find_sensitive_traffic` |
| Dynamic — storage | `pull_app_data`, `read_shared_preferences`, `query_app_database`, `list_app_files` |
| Findings | `add_finding`, `list_findings`, `get_findings_summary`, `generate_report` |

---

## Dynamic analysis status

Dynamic Android support is available for emulator setup, UI interaction, Frida scripts, app data inspection, and mitmproxy-assisted traffic review. The dynamic traffic path still needs more engineering for repeatable HTTPS interception, proxy state handling, and apps with certificate pinning or custom trust logic. iOS analysis is future work; this release and runtime are Android-focused.

---

## Security Notice

This tool is for authorized security testing only. Only use Mobilytix on applications you own or have explicit written permission to test. The authors are not responsible for misuse.

## License

Mobilytix source code is licensed under [Apache 2.0](LICENSE). The Docker runtimes bundle or reference third-party tools under their own licenses; see [NOTICE](NOTICE).
