# Mobilytix Tool Reference

Complete reference for all 63 tools exposed by the Mobilytix MCP server.

---

## Session Management

### `list_inbox`
List APK files available under the mounted `/inbox` directory.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| none | - | no | No arguments |

**Returns:** Mounted inbox path, discovered files, APK count, and paths you can pass to `create_session`.

### `create_session`
Create a new analysis session for an APK file.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `apk_path` | string | yes | APK filename from `list_inbox` or a path under `/inbox` |

**Returns:** Session ID, APK hash, workspace path, and whether the session was resumed or created fresh.

### `get_analysis_status`
Get the current state of an analysis session — phase, tools used, finding counts.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `session_id` | string | yes | Session ID |

**Returns:** Current phase, tools called, findings by severity, uncovered phases.

### `list_sessions`
List all known analysis sessions.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| none | - | no | No arguments |

**Returns:** Session ID, APK hash, package name, decoded/decompiled status, and findings count for each session.

### `prune_session`
Delete a session and its entire workspace directory (decoded, decompiled, findings, etc.).

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `session_id` | string | yes | The ID of the session to prune |

**Returns:** Confirmation with workspace path and file count deleted. **This action is irreversible.**

---

## Static Analysis — Reconnaissance

Recommended phase-0 order: `detect_framework` → `check_apk_tampering` → `plan_static_analysis`.

### `detect_framework`
Detect the application framework and dominant code container.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `session_id` | string | yes | Session ID |

**Returns:** Primary framework, detected build technologies, dominant code container, format hints, support level, artifact roots.

### `check_apk_tampering`
Check whether the APK was structurally manipulated to confuse static tooling.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `session_id` | string | yes | Session ID |
| `strict` | boolean | no | Enable stricter ZIP/header comparisons |

**Returns:** Tampering verdict, indicator list, and risk summary.

### `plan_static_analysis`
Build the framework-aware static analysis route for the current APK.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `session_id` | string | yes | Session ID |

**Returns:** Ordered next steps, primary deep-analysis step, recommended tools, wrapper-only tools, cross-category checks, and dynamic follow-up hypotheses.

### `get_apk_metadata`
Extract basic APK information using `aapt2 dump badging`.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `session_id` | string | yes | Session ID |

**Returns:** Package name, version, min/target SDK, permissions, signing info.

### `get_manifest`
Parse the full AndroidManifest.xml after decoding with apktool.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `session_id` | string | yes | Session ID |

**Returns:** Full parsed manifest — permissions, components, intent filters, application attributes.

### `list_exported_components`
List all exported Android components (activities, services, receivers, providers).

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `session_id` | string | yes | Session ID |

**Returns:** Exported components with types, permissions, and intent filters. Auto-creates findings for unprotected components.

### `check_manifest_security`
Automated security checks on manifest configuration.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `session_id` | string | yes | Session ID |

**Returns:** List of configuration issues found (debuggable, allowBackup, cleartext traffic, etc.).

---

## Static Analysis — Framework Artifacts

### `list_static_artifacts`
Index APK artifacts into framework-aware categories.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `session_id` | string | yes | Session ID |
| `scope` | string | no | Optional category filter: `dex`, `web_assets`, `js_bundle`, `native_libs`, `managed_assemblies`, `config`, `engine_assets` |

**Returns:** Artifact paths, sizes, format hints, counts, and artifact roots.

### `search_static_artifacts`
Search text-compatible non-DEX artifacts with ripgrep.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `session_id` | string | yes | Session ID |
| `pattern` | string | yes | Search pattern (regex supported) |
| `scope` | string | no | Optional artifact category filter |
| `file_filter` | string | no | Optional glob filter |
| `context_lines` | integer | no | Lines of context (default: 3) |

**Returns:** Matches with artifact path, category, line number, and context.

### `read_static_artifact`
Read one APK artifact by its APK-relative path.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `session_id` | string | yes | Session ID |
| `path` | string | yes | Artifact path as returned by `list_static_artifacts` |
| `mode` | string | no | `text` or `base64` (default: `text`) |

**Returns:** Artifact content with category and format hint.

### `analyze_flutter_aot`
Run `blutter` against a Flutter release/AOT APK and summarize the output.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `session_id` | string | yes | Session ID |
| `architecture` | string | no | Native ABI to analyze. Default: `arm64-v8a` |
| `rebuild` | boolean | no | Pass `--rebuild` to `blutter` |
| `timeout_seconds` | integer | no | Maximum seconds to allow `blutter` to run. Default: `7200` |

**Returns:** Structured Flutter AOT output including recovered URLs, channel names, routes, storage identifiers, auth/crypto/trust hints, generated output files, and cached session metadata. Requires `blutter` and currently supports Android `arm64-v8a` release/AOT targets.

### `analyze_flutter_debug`
Analyze a Flutter debug/JIT APK: scans `flutter_assets/` for channel names, URLs, and plugin registrations.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `session_id` | string | yes | Session ID |

**Returns:** `plugin_map`, `channel_names`, `high_risk_channels`, `recovered` signal dict, `kernel_blob_present`. Only applies to the `flutter_debug` route.

### `analyze_react_native_bundle`
Extract signals from a React Native JS bundle (plain JS or Hermes bytecode).

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `session_id` | string | yes | Session ID |

**Returns:** For plain JS: `recovered` dict with URLs, native modules, storage identifiers, OTA patterns, auth/crypto/trust terms, and `signal_lines`. For Hermes: partial string recovery plus structured `dynamic_hypotheses`; when `hermes-dec` is installed it also runs the Hermes pipeline and returns `hermes_backend`, `generated_outputs`, and `signal_lines`.

### `analyze_web_hybrid`
Analyze a Cordova, Capacitor, or Kony Visualizer APK: parses bridge configs, plugin lists, and web assets for security signals.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `session_id` | string | yes | Session ID |

**Returns:** `plugin_list`, `risky_plugins`, `csp_findings`, `allow_navigation`, `bridge_exposure`, `recovered` signal dict.

### `analyze_managed_assemblies`
Decompile priority Xamarin/.NET or Unity Mono assemblies with `ilspycmd` and extract security signals.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `session_id` | string | yes | Session ID |
| `max_assemblies` | integer | no | Maximum priority assemblies to decompile. Default: 5 |

**Returns:** `priority_assemblies`, `deferred_assemblies`, `decompiled` results, `recovered` signal dict.

### `analyze_unity_metadata`
Run `Il2CppDumper` against a Unity IL2CPP APK's `global-metadata.dat` and triage recovered type/method names by security category.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `session_id` | string | yes | Session ID |

**Returns:** `security_categories` dict, recovered type/method/field counts, `dynamic_hypotheses`. Applies to the `unity_il2cpp` route only.

---

## Static Analysis — Code

### `decompile_apk`
Decompile the APK to Java source using jadx.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `session_id` | string | yes | Session ID |

**Returns:** Source tree grouped by package, total file count.

### `search_source`
Search decompiled source with ripgrep.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `session_id` | string | yes | Session ID |
| `pattern` | string | yes | Search pattern (regex supported) |
| `file_glob` | string | no | File glob filter (e.g. `*.java`) |
| `context_lines` | integer | no | Lines of context (default: 3) |

**Returns:** Matches with file path, line number, and context.

### `read_source_file`
Read a specific source file from the decompiled output.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `session_id` | string | yes | Session ID |
| `file_path` | string | yes | Relative path to the source file |

**Returns:** File content (max 50K characters).

### `get_class_list`
List all classes in the APK using androguard.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `session_id` | string | yes | Session ID |

**Returns:** Classes grouped by package.

### `analyze_class`
Deep-analyze a specific class — methods, fields, inheritance.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `session_id` | string | yes | Session ID |
| `class_name` | string | yes | Fully-qualified class name |

**Returns:** Methods, fields, superclass, interfaces, method calls.

### `get_security_overview`
Run smart security triage across source and/or bytecode.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `session_id` | string | yes | Session ID |
| `category` | string | no | Optional category filter |
| `scan_mode` | string | no | `source`, `bytecode`, or `both` |

**Returns:** Categorized security-relevant snippets or callers.

---

## Static Analysis — Secrets & SAST

### `scan_secrets`
Scan the APK for hardcoded secrets using apkleaks.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `session_id` | string | yes | Session ID |

**Returns:** Secrets found by type, with auto-created findings.

### `run_sast`
Run semgrep SAST with the `p/android` ruleset.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `session_id` | string | yes | Session ID |

**Returns:** SAST findings with severity, category, CWE, and location.

### `analyze_certificate`
Analyze APK signing certificate and scheme.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `session_id` | string | yes | Session ID |

**Returns:** Certificate details, flags debug certs and weak signing schemes.

### `find_crypto_issues`
Search for weak cryptography patterns (ECB, DES, MD5, etc.).

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `session_id` | string | yes | Session ID |

**Returns:** Crypto issues found with file locations and evidence.

---

## Static Analysis — Native

### `list_native_libs`
List native libraries (.so files) in the APK.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `session_id` | string | yes | Session ID |

**Returns:** Libraries by architecture with sizes.

### `analyze_native_strings`
Extract interesting strings from native libraries.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `session_id` | string | yes | Session ID |
| `lib_name` | string | yes | Library filename to analyze |

**Returns:** URLs, IPs, format strings, function names found in the binary.

### `analyze_native_binary`
Run radare2-suite ELF triage (`rabin2`) against a native library.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `session_id` | string | yes | Session ID |
| `lib_name` | string | yes | Library filename to analyze |
| `architecture` | string | no | ABI directory (default `arm64-v8a`) |
| `max_items` | integer | no | Max imports/symbols/sections/strings returned per category |

**Returns:** ELF security properties, linked libraries, imports, symbols, JNI exports, section summaries, and filtered embedded strings.

### `disassemble_native_function`
Disassemble one native function with radare2.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `session_id` | string | yes | Session ID |
| `lib_name` | string | yes | Library filename to analyze |
| `symbol` | string | conditional | Function symbol/flag to disassemble |
| `address` | string/integer | conditional | Function address or offset |
| `architecture` | string | no | ABI directory (default `arm64-v8a`) |
| `analysis_mode` | string | no | `targeted` (default), `aa`, or `aaa` |
| `max_instructions` | integer | no | Maximum instructions returned |

**Returns:** Function metadata and a bounded disassembly listing.

### `decompile_native_function`
Decompile one native function with radare2 + r2dec.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `session_id` | string | yes | Session ID |
| `lib_name` | string | yes | Library filename to analyze |
| `symbol` | string | conditional | Function symbol/flag to decompile |
| `address` | string/integer | conditional | Function address or offset |
| `architecture` | string | no | ABI directory (default `arm64-v8a`) |
| `analysis_mode` | string | no | `targeted` (default), `aa`, or `aaa` |
| `max_lines` | integer | no | Maximum decompiled lines returned |

**Returns:** Function metadata and bounded pseudo-C output from `r2dec`.

---

## Dynamic Analysis — Device

### `start_dynamic_session`
Start the Android emulator container.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `session_id` | string | yes | Session ID |

**Returns:** Device serial, ADB/Frida bridge status, and current mitmproxy CA state.

### `ensure_frida_server`
Check whether `frida-server` is running and start it when the binary is already on the emulator.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `session_id` | string | yes | Session ID |
| `force_restart` | boolean | no | Stop stale processes and relaunch even if a partial process is detected |

**Returns:** Whether frida-server was already running or which recovery method started it, plus `process_running`, `port_listening`, and `bridge_reachable` status flags.

### `install_apk`
Install the APK on the emulator.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `session_id` | string | yes | Session ID |

**Returns:** Installation result.

### `launch_app`
Launch the app on the emulator.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `session_id` | string | yes | Session ID |
| `activity` | string | no | Specific activity to launch |

**Returns:** Launch status.

### `stop_app`
Force-stop the app.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `session_id` | string | yes | Session ID |

### `get_logcat`
Get filtered logcat output for the app.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `session_id` | string | yes | Session ID |
| `lines` | integer | no | Number of lines (default: 200) |
| `tag_filter` | string | no | Filter by log tag |

**Returns:** Log lines, auto-flags sensitive data patterns.

### `list_running_processes`
List processes on the device.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `session_id` | string | yes | Session ID |

### `take_screenshot`
Capture a screenshot of the emulator screen.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `session_id` | string | yes | Session ID |

### `inspect_ui`
Capture the current Android UI hierarchy with `uiautomator dump`.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `session_id` | string | yes | Session ID |
| `include_screenshot` | boolean | no | Capture a screenshot with the UI dump |
| `interactive_only` | boolean | no | Only return interactive nodes |
| `max_elements` | integer | no | Maximum number of elements to return |

**Returns:** Parsed UI elements with text, content description, resource ID, widget class, bounds, and interactivity flags.

### `ui_action`
Perform a constrained UI action through `adb shell input`.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `session_id` | string | yes | Session ID |
| `action` | string | yes | `tap`, `long_press`, `swipe`, `type_text`, `keyevent`, `back`, or `home` |
| `element_id` | string | no | Target element from the latest `inspect_ui` result |
| `x` / `y` | integer | no | Tap coordinates when not using `element_id` |
| `start_x` / `start_y` / `end_x` / `end_y` | integer | no | Swipe coordinates |
| `duration_ms` | integer | no | Press or swipe duration |
| `text` | string | no | Text to enter for `type_text` |
| `keycode` | string | no | Allowlisted Android keyevent name for `keyevent` |
| `post_action_wait_ms` | integer | no | Delay before post-action capture |
| `capture_ui_after` | boolean | no | Capture a fresh UI dump after the action |
| `include_screenshot` | boolean | no | Capture a screenshot after the action |

**Returns:** Execution status, resolved target information, and optionally a refreshed post-action UI state.

### `wait_for_ui`
Poll the UI hierarchy until a selector appears or disappears.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `session_id` | string | yes | Session ID |
| `text` | string | no | Case-insensitive substring to match against text and content descriptions |
| `resource_id` | string | no | Exact Android resource ID |
| `content_desc` | string | no | Case-insensitive content description match |
| `class_name` | string | no | Case-insensitive widget class match |
| `package_name` | string | no | Exact package name match |
| `state` | string | no | `present` or `absent` |
| `timeout_seconds` | integer | no | Maximum polling time |
| `poll_interval_ms` | integer | no | Delay between polls |
| `include_screenshot` | boolean | no | Capture a screenshot when polling ends |
| `interactive_only` | boolean | no | Only evaluate interactive nodes |
| `max_elements` | integer | no | Maximum number of elements to retain per poll |

**Returns:** Whether the selector matched before timeout, the matched elements, attempt count, and the final UI state snapshot.

---

## Dynamic Analysis — Frida / Instrumentation

### `list_loaded_classes`
List all Java classes loaded by the app at runtime.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `session_id` | string | yes | Session ID |
| `filter_pattern` | string | no | Filter pattern for class names |
| `process_name` | string | no | Attach to a custom process name when it differs from the package |
| `spawn` | boolean | no | Use Frida spawn for the package if the app is not running |
| `timeout_seconds` | integer | no | Seconds to monitor Frida output before returning |
| `max_results` | integer | no | Maximum number of classes to return; `0` for all |

### `run_frida_script`
Execute a custom Frida JavaScript script and return everything it emits during the capture window.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `session_id` | string | yes | Session ID |
| `script` | string | yes | Frida JavaScript code to inject |
| `process_name` | string | no | Attach to a custom process name when it differs from the package |
| `spawn` | boolean | no | Use Frida spawn for the package if the app is not running |
| `timeout_seconds` | integer | no | Seconds to monitor Frida output before returning |
| `max_messages` | integer | no | Maximum number of parsed messages to return; `0` for all |

### `run_frida_codeshare_script`
Execute a Frida CodeShare script and return everything it emits during the capture window.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `session_id` | string | yes | Session ID |
| `codeshare_slug` | string | yes | CodeShare slug like `user/project` |
| `process_name` | string | no | Attach to a custom process name when it differs from the package |
| `spawn` | boolean | no | Use Frida spawn for the package if the app is not running |
| `timeout_seconds` | integer | no | Seconds to monitor Frida output before returning |
| `max_messages` | integer | no | Maximum number of parsed messages to return; `0` for all |

**Note:** The tool auto-confirms the Frida CodeShare trust prompt on first use so the capture can proceed non-interactively.

---

## Dynamic Analysis — Traffic

These tools assist with mitmproxy-based Android traffic review. Traffic interception still depends on emulator proxy state, CA installation, and the target app's trust behavior; apps with pinning or custom trust logic may need manual follow-up.

### `start_traffic_capture`
Start intercepting HTTP(S) traffic through mitmproxy. Enables the device proxy.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `session_id` | string | yes | Session ID |

**Note:** Verifies that the mitmproxy CA is installed in the emulator system trust store first. If HTTPS traffic still fails, the likely cause is app pinning or custom trust logic.

### `stop_traffic_capture`
Stop traffic capture, save results, and disable the device proxy.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `session_id` | string | yes | Session ID |

### `get_captured_requests`
Retrieve intercepted HTTP requests from the mitmproxy API.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `session_id` | string | yes | Session ID |

**Returns:** Request and response metadata plus body previews up to 8 192 bytes. When a body exceeds that limit, the result includes a hint to use `get_captured_flow_body` with the returned `flow_id`.

### `get_captured_flow_body`
Retrieve the full request and/or response body for a captured flow.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `session_id` | string | yes | Session ID |
| `flow_id` | string | yes | Flow ID returned by `get_captured_requests` |
| `message` | string | no | `request`, `response`, or `both` |
| `max_bytes` | integer | no | Maximum bytes to return per body; `0` for the full body |

**Returns:** Full request/response body. Text bodies are returned as UTF-8 strings; binary bodies are base64-encoded.

### `find_sensitive_traffic`
Automatically scan captured traffic for sensitive data.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `session_id` | string | yes | Session ID |

**Returns:** Findings for HTTP (non-HTTPS) traffic, auth tokens, PII.

---

## Dynamic Analysis — Storage

### `pull_app_data`
Pull `/data/data/<package>` from the device.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `session_id` | string | yes | Session ID |

**Returns:** File listing categorized by type (databases, shared_prefs, files, cache).

### `read_shared_preferences`
Parse and analyze a SharedPreferences XML file.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `session_id` | string | yes | Session ID |
| `pref_file` | string | yes | Preferences filename |

**Returns:** All preference entries, auto-flags sensitive keys.

### `query_app_database`
Run a SELECT query on an app's SQLite database.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `session_id` | string | yes | Session ID |
| `db_name` | string | yes | Database filename |
| `query` | string | yes | SQL SELECT query |

**Returns:** Query results as a list of dicts. Only SELECT allowed.

### `list_app_files`
List files in the app's data directory with permissions.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `session_id` | string | yes | Session ID |
| `directory` | string | no | Subdirectory to list |

**Returns:** Files with permissions, auto-flags world-readable/writable.

---

## Findings Management

### `add_finding`
Manually add a security finding to the session.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `session_id` | string | yes | Session ID |
| `title` | string | yes | Finding title |
| `severity` | string | yes | `critical`, `high`, `medium`, `low`, `info` |
| `category` | string | yes | Finding category |
| `description` | string | yes | Full description |
| `evidence` | string | no | Supporting evidence |
| `cwe_id` | string | no | CWE identifier |
| `recommendation` | string | no | Fix recommendation |

### `list_findings`
List all findings in the current session.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `session_id` | string | yes | Session ID |
| `severity` | string | no | Filter by severity |
| `category` | string | no | Filter by category |

### `get_findings_summary`
Get a statistical summary of all findings.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `session_id` | string | yes | Session ID |

### `generate_report`
Generate a complete markdown penetration test report.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `session_id` | string | yes | Session ID |
