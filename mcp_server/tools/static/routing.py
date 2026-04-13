"""Shared framework-aware routing helpers for static analysis.

This module is the source of truth for:
  - APK fingerprinting and framework detection
  - artifact indexing by code container
  - static analysis route planning
  - wrapper-only warnings for DEX-centric tools
"""

from __future__ import annotations

import os
import zipfile
from pathlib import Path
from typing import Any

from mcp_server.models.session import AnalysisSession
from mcp_server.tools.workspace import ensure_session_artifact_path, session_workspace

try:
    from apkInspector.headers import ZipEntry

    _HAS_APK_INSPECTOR = True
except ImportError:
    _HAS_APK_INSPECTOR = False


ARTIFACT_CATEGORIES = (
    "dex",
    "web_assets",
    "js_bundle",
    "native_libs",
    "managed_assemblies",
    "config",
    "engine_assets",
)

TEXT_COMPATIBLE_HINTS = {
    "css",
    "html",
    "javascript",
    "json",
    "jsx",
    "text",
    "xml",
    "yaml",
}

FRAMEWORK_SIGNATURES: list[dict[str, Any]] = [
    {
        "name": "Flutter",
        "build_technology": "flutter",
        "indicators": [
            "lib/armeabi-v7a/libflutter.so",
            "lib/arm64-v8a/libflutter.so",
            "lib/x86_64/libflutter.so",
            "libflutter.so",
        ],
        "analysis_guide": {
            "primary_target": "lib/<arch>/libapp.so plus assets/flutter_assets/",
            "tools": [
                "Use list_static_artifacts to inventory Flutter assets and native libraries",
                "Use read_static_artifact/search_static_artifacts on flutter_assets for routes and config",
                "Use analyze_flutter_aot on arm64-v8a release builds, with analyze_native_strings/analyze_native_binary as fallback before targeted disassembly/decompilation",
                "Use get_security_overview(scan_mode='bytecode') for wrapper and bridge calls",
            ],
            "source_analysis": (
                "Jadx primarily shows the Android wrapper and plugin bridge. "
                "Meaningful Flutter logic is often outside standard Java source."
            ),
            "obfuscation_note": (
                "Release Flutter builds typically compile Dart into libapp.so. "
                "Recoverable assets are higher-yield than source grep."
            ),
            "key_files": [
                "lib/<arch>/libapp.so",
                "lib/<arch>/libflutter.so",
                "assets/flutter_assets/",
            ],
        },
    },
    {
        "name": "React Native",
        "build_technology": "react_native",
        "indicators": [
            "lib/armeabi-v7a/libreactnativejni.so",
            "lib/arm64-v8a/libreactnativejni.so",
            "libreactnativejni.so",
            "assets/index.android.bundle",
        ],
        "analysis_guide": {
            "primary_target": "assets/index.android.bundle and native bridge classes",
            "tools": [
                "Use list_static_artifacts to inspect JS bundle, Hermes runtime, and bridge libs",
                "Use read_static_artifact/search_static_artifacts for plain JS bundles",
                "Use get_security_overview(scan_mode='bytecode') for native bridge exposure",
                "Use list_native_libs plus analyze_native_strings/analyze_native_binary for linked native modules, then disassemble/decompile the highest-value JNI entry points",
            ],
            "source_analysis": (
                "Jadx primarily shows the Android wrapper and bridge modules, not the application JS."
            ),
            "obfuscation_note": (
                "If Hermes is present, the bundle may require manual follow-up with Hermes tooling."
            ),
            "key_files": [
                "assets/index.android.bundle",
                "assets/shell-app.bundle",
                "lib/<arch>/libhermes.so",
                "lib/<arch>/libreactnativejni.so",
            ],
        },
    },
    {
        "name": "Cordova",
        "build_technology": "cordova",
        "indicators": [
            "assets/www/index.html",
            "assets/www/cordova.js",
            "assets/www/cordova_plugins.js",
        ],
        "analysis_guide": {
            "primary_target": "assets/www/ web assets and plugin bridge config",
            "tools": [
                "Use search_static_artifacts/read_static_artifact on assets/www/",
                "Review cordova_plugins.js and config.xml first",
                "Use get_manifest/check_manifest_security for native wrapper exposure",
            ],
            "source_analysis": "Jadx mainly shows the WebView wrapper and plugins.",
            "obfuscation_note": "Web assets may be minified but remain text-searchable.",
            "key_files": [
                "assets/www/",
                "assets/www/cordova_plugins.js",
                "res/xml/config.xml",
            ],
        },
    },
    {
        "name": "Capacitor",
        "build_technology": "capacitor",
        "indicators": [
            "assets/capacitor.config.json",
            "assets/public/index.html",
            "assets/capacitor.plugins.json",
        ],
        "analysis_guide": {
            "primary_target": "assets/public/ web app plus Capacitor bridge config",
            "tools": [
                "Use search_static_artifacts/read_static_artifact on assets/public/",
                "Review capacitor.config.json and capacitor.plugins.json first",
                "Use get_manifest/check_manifest_security for native wrapper exposure",
            ],
            "source_analysis": "Jadx mainly shows the native bridge shell.",
            "obfuscation_note": "Web assets are usually still text-searchable.",
            "key_files": [
                "assets/public/",
                "assets/capacitor.config.json",
                "assets/capacitor.plugins.json",
            ],
        },
    },
    {
        "name": "Xamarin",
        "build_technology": "dotnet",
        "indicators": [
            "assemblies/Xamarin.Mobile.dll",
            "assemblies/mscorlib.dll",
            "libmonodroid.so",
            "libmonosgen-2.0.so",
        ],
        "analysis_guide": {
            "primary_target": "assemblies/*.dll and related Mono runtime artifacts",
            "tools": [
                "Use list_static_artifacts to inventory managed assemblies",
                "Use read_static_artifact for config and assembly metadata strings",
                "Use list_native_libs for runtime bindings",
            ],
            "source_analysis": "Jadx mainly shows Mono/Xamarin bootstrap code.",
            "obfuscation_note": "Semantic managed decompilation is deferred in this stage.",
            "key_files": [
                "assemblies/*.dll",
                "lib/<arch>/libmonodroid.so",
            ],
        },
    },
    {
        "name": "Unity",
        "build_technology": "unity",
        "indicators": [
            "libunity.so",
            "lib/armeabi-v7a/libunity.so",
            "lib/arm64-v8a/libunity.so",
            "assets/bin/Data/Managed/UnityEngine.dll",
            "assets/bin/Data/Managed/UnityEditor.dll",
        ],
        "analysis_guide": {
            "primary_target": "Managed assemblies for Mono or libil2cpp.so/global-metadata.dat for IL2CPP",
            "tools": [
                "Use list_static_artifacts to distinguish Mono from IL2CPP immediately",
                "Review engine assets, metadata, and native libraries before wrapper code",
                "Use analyze_native_strings and analyze_native_binary on libil2cpp.so or libunity.so where present before targeted function work",
            ],
            "source_analysis": "Jadx mainly shows the Unity player wrapper.",
            "obfuscation_note": "IL2CPP workflows are manual follow-up in this stage.",
            "key_files": [
                "assets/bin/Data/Managed/",
                "lib/<arch>/libil2cpp.so",
                "assets/bin/Data/Managed/Metadata/global-metadata.dat",
            ],
        },
    },
    {
        "name": "Unreal Engine",
        "build_technology": "unreal",
        "indicators": [
            "libUE4.so",
            "lib/armeabi-v7a/libUE4.so",
            "lib/arm64-v8a/libUE4.so",
            "assets/Unreal/UE4Game/Manifest.xml",
        ],
        "analysis_guide": {
            "primary_target": "libUE4.so and packaged Unreal content",
            "tools": [
                "Use list_static_artifacts to inventory engine assets and native libs",
                "Use analyze_native_strings and analyze_native_binary on libUE4.so before targeted function work",
                "Treat wrapper-level Java source as secondary",
            ],
            "source_analysis": "Jadx mainly shows the Android activity wrapper.",
            "obfuscation_note": "Deep Unreal native analysis is manual follow-up in this stage.",
            "key_files": [
                "lib/<arch>/libUE4.so",
                "assets/Unreal/",
                "*.pak",
            ],
        },
    },
    {
        "name": "LibGDX",
        "build_technology": "native_android",
        "indicators": [
            "libgdx.so",
            "lib/armeabi-v7a/libgdx.so",
            "lib/arm64-v8a/libgdx.so",
            "assets/libgdx.jar",
        ],
        "analysis_guide": {
            "primary_target": "Standard Java/Kotlin classes with asset review as follow-up",
            "tools": [
                "Use the normal DEX pipeline first",
                "Inventory native libs and assets as secondary steps",
            ],
            "source_analysis": "Jadx is effective for LibGDX apps.",
            "obfuscation_note": "Standard R8/ProGuard caveats apply.",
            "key_files": ["classes.dex", "assets/"],
        },
    },
    {
        "name": "Expo (React Native)",
        "build_technology": "react_native",
        "indicators": [
            "assets/shell-app.bundle",
            "assets/expo-manifest.json",
        ],
        "analysis_guide": {
            "primary_target": "Expo JS bundle and manifest/update configuration",
            "tools": [
                "Use list_static_artifacts to inspect shell-app.bundle and expo-manifest.json",
                "Use read_static_artifact/search_static_artifacts for text bundles",
                "Review update URLs and native bridge exposure",
            ],
            "source_analysis": "Same wrapper limitation as React Native.",
            "obfuscation_note": "JS bundles are usually text-searchable unless Hermes packaging is used.",
            "key_files": [
                "assets/shell-app.bundle",
                "assets/expo-manifest.json",
            ],
        },
    },
    {
        "name": "Kony Visualizer",
        "build_technology": "web_hybrid",
        "indicators": [
            "assets/kony.js",
            "assets/konyframework.js",
            "assets/KonyApps/config.json",
        ],
        "analysis_guide": {
            "primary_target": "JavaScript assets and Kony config",
            "tools": [
                "Use search_static_artifacts/read_static_artifact on assets/",
                "Review KonyApps/config.json before wrapper code",
            ],
            "source_analysis": "Jadx mainly shows the native shell.",
            "obfuscation_note": "JavaScript remains text-searchable in most builds.",
            "key_files": [
                "assets/kony.js",
                "assets/konyframework.js",
                "assets/KonyApps/config.json",
            ],
        },
    },
    {
        "name": "Kotlin Multiplatform (KMP)",
        "build_technology": "native_android",
        "indicators": [
            "lib/armeabi-v7a/libkotlin_shared.so",
            "lib/arm64-v8a/libkotlin_shared.so",
        ],
        "analysis_guide": {
            "primary_target": "Java/Kotlin bytecode with optional shared native support",
            "tools": [
                "Use the normal DEX pipeline first",
                "Inventory native libs as secondary follow-up",
            ],
            "source_analysis": "Jadx is effective for KMP Android targets.",
            "obfuscation_note": "Standard R8/ProGuard caveats apply.",
            "key_files": ["classes.dex", "lib/<arch>/libkotlin_shared.so"],
        },
    },
]

ROUTE_TEMPLATES: dict[str, dict[str, Any]] = {
    "native_java_kotlin": {
        "title": "Native Android (DEX-first)",
        "support_level": "full",
        "analysis_focus": "Meaningful logic is primarily in DEX bytecode.",
        "primary_deep_analysis_step": "Decompile DEX and triage native Android source first.",
        "recommended_tools": [
            "get_apk_metadata",
            "get_manifest",
            "list_exported_components",
            "check_manifest_security",
            "get_security_overview",
            "decompile_apk",
            "search_source",
            "read_source_file",
            "scan_secrets",
            "run_sast",
            "find_crypto_issues",
            "list_native_libs",
            "analyze_native_strings",
            "analyze_native_binary",
            "disassemble_native_function",
            "decompile_native_function",
        ],
        "deprioritized_tools": [],
        "wrapper_only_tools": [],
        "manual_followup": [
            "Trace JNI entry points if custom native libraries are present.",
        ],
        "dynamic_hypotheses": [
            "Intercept authentication and token-refresh flows found in DEX.",
            "Validate any custom TLS or WebView trust logic dynamically.",
        ],
    },
    "flutter_debug": {
        "title": "Flutter Debug / Recoverable Assets",
        "support_level": "guided",
        "analysis_focus": (
            "Prioritise flutter_assets, plugin registration clues, and the Android wrapper."
        ),
        "primary_deep_analysis_step": "Run analyze_flutter_debug to extract plugin/channel map from flutter_assets and wrapper correlation before generic source review.",
        "recommended_tools": [
            "get_apk_metadata",
            "get_manifest",
            "check_manifest_security",
            "list_static_artifacts",
            "analyze_flutter_debug",
            "search_static_artifacts",
            "read_static_artifact",
            "list_native_libs",
            "analyze_native_strings",
            "analyze_native_binary",
            "disassemble_native_function",
            "decompile_native_function",
            "get_security_overview",
        ],
        "deprioritized_tools": [
            "run_sast",
            "search_source",
        ],
        "wrapper_only_tools": [
            "decompile_apk",
            "search_source",
            "run_sast",
        ],
        "manual_followup": [
            "Confirm whether recoverable Dart artifacts expose auth, routes, or storage names.",
        ],
        "dynamic_hypotheses": [
            "Hook platform-channel calls and intercept backend endpoints discovered in flutter_assets.",
            "Validate certificate pinning and root-detection paths dynamically.",
        ],
    },
    "flutter_release_aot": {
        "title": "Flutter Release / AOT",
        "support_level": "partial",
        "analysis_focus": "Prioritise libapp.so, libflutter.so, flutter_assets, and wrapper/plugin review.",
        "primary_deep_analysis_step": "Run analyze_flutter_aot on arm64-v8a, then correlate results with flutter_assets before Java source.",
        "recommended_tools": [
            "get_apk_metadata",
            "get_manifest",
            "check_manifest_security",
            "list_static_artifacts",
            "analyze_flutter_aot",
            "read_static_artifact",
            "search_static_artifacts",
            "list_native_libs",
            "analyze_native_strings",
            "analyze_native_binary",
            "disassemble_native_function",
            "decompile_native_function",
            "get_security_overview",
        ],
        "deprioritized_tools": [
            "decompile_apk",
            "search_source",
            "run_sast",
        ],
        "wrapper_only_tools": [
            "decompile_apk",
            "search_source",
            "run_sast",
            "get_security_overview(scan_mode='source')",
        ],
        "manual_followup": [
            "Manual follow-up is still needed when blutter is unavailable, the target ABI is unsupported, the recovered AOT output is incomplete, or the target uses an older Dart runtime that blutter cannot compile against.",
        ],
        "dynamic_hypotheses": [
            "Intercept endpoints and storage keys recovered from libapp.so or flutter_assets.",
            "Confirm platform-channel trust and anti-debug behaviour dynamically.",
        ],
    },
    "react_native_plain_js": {
        "title": "React Native (Plain JS Bundle)",
        "support_level": "full",
        "analysis_focus": "Prioritise the JS bundle, then the Android bridge and native modules.",
        "primary_deep_analysis_step": "Run analyze_react_native_bundle to extract endpoints, native modules, and auth/crypto signals from the JS bundle before wrapper classes.",
        "recommended_tools": [
            "get_apk_metadata",
            "get_manifest",
            "check_manifest_security",
            "list_static_artifacts",
            "analyze_react_native_bundle",
            "search_static_artifacts",
            "read_static_artifact",
            "get_security_overview",
            "list_native_libs",
            "analyze_native_strings",
            "analyze_native_binary",
            "disassemble_native_function",
            "decompile_native_function",
        ],
        "deprioritized_tools": [
            "run_sast",
            "search_source",
        ],
        "wrapper_only_tools": [
            "decompile_apk",
            "search_source",
            "run_sast",
        ],
        "manual_followup": [
            "Confirm native-module boundaries where sensitive actions cross out of JS.",
        ],
        "dynamic_hypotheses": [
            "Intercept API calls and auth flows named in the bundle.",
            "Test OTA or update endpoints if present.",
        ],
    },
    "react_native_hermes": {
        "title": "React Native (Hermes Bytecode)",
        "support_level": "partial",
        "analysis_focus": "Prioritise Hermes bundle inventory, bridge classes, and native modules.",
        "primary_deep_analysis_step": (
            "Run analyze_react_native_bundle to invoke hermes-dec when available, "
            "recover Hermes pseudo-code/disassembly-backed signals, then triage "
            "bridge/native modules."
        ),
        "recommended_tools": [
            "get_apk_metadata",
            "get_manifest",
            "check_manifest_security",
            "list_static_artifacts",
            "analyze_react_native_bundle",
            "read_static_artifact",
            "get_security_overview",
            "list_native_libs",
            "analyze_native_strings",
            "analyze_native_binary",
            "disassemble_native_function",
            "decompile_native_function",
        ],
        "deprioritized_tools": [
            "run_sast",
            "search_source",
            "search_static_artifacts",
        ],
        "wrapper_only_tools": [
            "decompile_apk",
            "search_source",
            "run_sast",
        ],
        "manual_followup": [
            "Manual follow-up is still needed when hermes-dec is unavailable, "
            "decompilation is incomplete, or bridge/native behaviour is not "
            "recoverable from pseudo-code.",
        ],
        "dynamic_hypotheses": [
            "Use runtime traffic capture to confirm endpoints not recoverable from Hermes bytecode.",
            "Trace native bridge entry points that accept JS-controlled data.",
        ],
    },
    "web_hybrid": {
        "title": "Web-Hybrid App",
        "support_level": "full",
        "analysis_focus": "Prioritise bundled web assets and bridge/plugin configuration.",
        "primary_deep_analysis_step": "Run analyze_web_hybrid to extract plugin list, CSP config, navigation allowlists, and bridge exposure from web assets before wrapper classes.",
        "recommended_tools": [
            "get_apk_metadata",
            "get_manifest",
            "check_manifest_security",
            "list_static_artifacts",
            "analyze_web_hybrid",
            "search_static_artifacts",
            "read_static_artifact",
            "get_security_overview",
        ],
        "deprioritized_tools": [
            "run_sast",
            "search_source",
        ],
        "wrapper_only_tools": [
            "decompile_apk",
            "search_source",
            "run_sast",
        ],
        "manual_followup": [
            "Review plugin bridges and risky WebView settings in detail where assets expose native capabilities.",
        ],
        "dynamic_hypotheses": [
            "Test CSP, origin handling, deep links, and file access dynamically.",
            "Intercept API calls and auth flows defined in bundled JS.",
        ],
    },
    "dotnet": {
        "title": ".NET / Xamarin / Managed Assemblies",
        "support_level": "guided",
        "analysis_focus": "Prioritise managed assemblies, config, and native bindings before wrapper code.",
        "primary_deep_analysis_step": "Run analyze_managed_assemblies to decompile managed assemblies and extract auth/crypto/trust signals before Java source.",
        "recommended_tools": [
            "get_apk_metadata",
            "get_manifest",
            "check_manifest_security",
            "list_static_artifacts",
            "analyze_managed_assemblies",
            "read_static_artifact",
            "search_static_artifacts",
            "list_native_libs",
            "analyze_native_strings",
            "analyze_native_binary",
            "disassemble_native_function",
            "decompile_native_function",
        ],
        "deprioritized_tools": [
            "run_sast",
            "search_source",
        ],
        "wrapper_only_tools": [
            "decompile_apk",
            "search_source",
            "run_sast",
        ],
        "manual_followup": [
            "Managed decompilation with dnSpy/ILSpy-equivalent tooling is deferred.",
        ],
        "dynamic_hypotheses": [
            "Confirm auth, storage, and trust flows whose names only surface in assembly metadata or strings.",
        ],
    },
    "unity_mono": {
        "title": "Unity Mono",
        "support_level": "guided",
        "analysis_focus": "Prioritise managed Unity assemblies and Data assets before wrapper code.",
        "primary_deep_analysis_step": "Run analyze_managed_assemblies to decompile Unity managed assemblies and extract signals before Java source.",
        "recommended_tools": [
            "get_apk_metadata",
            "get_manifest",
            "check_manifest_security",
            "list_static_artifacts",
            "analyze_managed_assemblies",
            "read_static_artifact",
            "search_static_artifacts",
            "list_native_libs",
            "analyze_native_strings",
            "analyze_native_binary",
            "disassemble_native_function",
            "decompile_native_function",
        ],
        "deprioritized_tools": [
            "run_sast",
            "search_source",
        ],
        "wrapper_only_tools": [
            "decompile_apk",
            "search_source",
            "run_sast",
        ],
        "manual_followup": [
            "Full C# decompilation is deferred, but assembly inventory should drive later review.",
        ],
        "dynamic_hypotheses": [
            "Validate networking, auth, and anti-tamper paths surfaced by managed assembly names.",
        ],
    },
    "unity_il2cpp": {
        "title": "Unity IL2CPP",
        "support_level": "partial",
        "analysis_focus": "Prioritise libil2cpp.so, global-metadata.dat, and Unity Data assets.",
        "primary_deep_analysis_step": "Run analyze_unity_metadata to recover type/method names from libil2cpp.so metadata, then triage with analyze_native_strings/analyze_native_binary before targeted disassembly or decompilation.",
        "recommended_tools": [
            "get_apk_metadata",
            "get_manifest",
            "check_manifest_security",
            "list_static_artifacts",
            "analyze_unity_metadata",
            "read_static_artifact",
            "list_native_libs",
            "analyze_native_strings",
            "analyze_native_binary",
            "disassemble_native_function",
            "decompile_native_function",
        ],
        "deprioritized_tools": [
            "decompile_apk",
            "search_source",
            "run_sast",
            "search_static_artifacts",
        ],
        "wrapper_only_tools": [
            "decompile_apk",
            "search_source",
            "run_sast",
        ],
        "manual_followup": [
            "Metadata-aware IL2CPP tooling is required for deeper semantic recovery.",
        ],
        "dynamic_hypotheses": [
            "Intercept network and anti-tamper behaviour discovered in strings or metadata.",
        ],
    },
    "unreal_native": {
        "title": "Unreal Native",
        "support_level": "partial",
        "analysis_focus": "Prioritise native Unreal libraries and packaged content.",
        "primary_deep_analysis_step": "Review native Unreal libraries and packaged content before Java source.",
        "recommended_tools": [
            "get_apk_metadata",
            "get_manifest",
            "check_manifest_security",
            "list_static_artifacts",
            "read_static_artifact",
            "list_native_libs",
            "analyze_native_strings",
            "analyze_native_binary",
            "disassemble_native_function",
            "decompile_native_function",
        ],
        "deprioritized_tools": [
            "decompile_apk",
            "search_source",
            "run_sast",
        ],
        "wrapper_only_tools": [
            "decompile_apk",
            "search_source",
            "run_sast",
        ],
        "manual_followup": [
            "Deep Unreal pak/native reverse engineering is deferred.",
        ],
        "dynamic_hypotheses": [
            "Prioritise traffic capture and native trust validation for Unreal endpoints.",
        ],
    },
    "mixed_hardened": {
        "title": "Mixed / Hardened APK",
        "support_level": "partial",
        "analysis_focus": "Map all containers and analyse the highest-value path per container.",
        "primary_deep_analysis_step": "Inventory all code containers and prioritise the richest non-wrapper artifact first.",
        "recommended_tools": [
            "get_apk_metadata",
            "get_manifest",
            "check_manifest_security",
            "list_static_artifacts",
            "read_static_artifact",
            "search_static_artifacts",
            "get_security_overview",
            "list_native_libs",
            "analyze_native_strings",
            "analyze_native_binary",
            "disassemble_native_function",
            "decompile_native_function",
        ],
        "deprioritized_tools": [],
        "wrapper_only_tools": [],
        "manual_followup": [
            "Expect staged payloads, encrypted assets, or anti-analysis wrappers.",
        ],
        "dynamic_hypotheses": [
            "Validate which container actually drives auth, network, and anti-debug logic at runtime.",
        ],
    },
}

DEFAULT_NATIVE_GUIDE = {
    "primary_target": "classes.dex and related Java/Kotlin sources",
    "tools": [
        "Use get_security_overview(scan_mode='both') for initial triage",
        "Use decompile_apk/search_source/read_source_file for manual review",
        "Inventory native libraries early if JNI may contain sensitive logic",
        "Use analyze_native_strings and analyze_native_binary on custom JNI libraries",
        "Use disassemble_native_function/decompile_native_function on the highest-value JNI or auth/network functions",
    ],
    "source_analysis": "Jadx is the primary semantic tool for standard native Android apps.",
    "obfuscation_note": "Switch to bytecode analysis when source identifiers are obfuscated.",
    "key_files": [
        "classes.dex",
        "AndroidManifest.xml",
        "res/",
    ],
}

FRAMEWORK_TO_ROUTE = {
    "Native (Java/Kotlin)": "native_java_kotlin",
    "Flutter": "flutter_release_aot",
    "React Native": "react_native_plain_js",
    "Expo (React Native)": "react_native_plain_js",
    "Cordova": "web_hybrid",
    "Capacitor": "web_hybrid",
    "Xamarin": "dotnet",
    "Unity": "unity_mono",
    "Unreal Engine": "unreal_native",
    "LibGDX": "native_java_kotlin",
    "Kony Visualizer": "web_hybrid",
    "Kotlin Multiplatform (KMP)": "native_java_kotlin",
}

CONFIG_EXTENSIONS = {".conf", ".config", ".ini", ".json", ".properties", ".toml", ".txt", ".xml", ".yaml", ".yml"}
TEXT_EXTENSIONS = {".css", ".html", ".js", ".json", ".jsx", ".mjs", ".ts", ".tsx", ".txt", ".xml", ".yaml", ".yml"}
JS_BUNDLE_NAMES = {"index.android.bundle", "shell-app.bundle", "app.bundle"}
ENGINE_SUFFIXES = {".pak"}

CROSS_CATEGORY_CHECKS = [
    "Exported components, deep links, and app links from the manifest",
    "Network trust configuration, cleartext traffic, and proxy/debug hints",
    "Authentication, token storage, and refresh/session handling clues",
    "WebView, bridge, or plugin exposure where native and non-native code cross",
    "Native libraries, third-party SDKs, and anti-debug/tamper indicators",
]

DEX_CENTRIC_WRAPPER_WARNING_TOOLS = {
    "decompile_apk",
    "search_source",
    "run_sast",
    "get_security_overview",
}


def list_apk_file_names(apk_path: str) -> set[str]:
    """List file names inside an APK with apkInspector fallback where available."""
    if _HAS_APK_INSPECTOR:
        try:
            zip_entry = ZipEntry.parse(apk_path, raw=False)
            return set(zip_entry.namelist())
        except Exception:
            pass

    with zipfile.ZipFile(apk_path, "r") as zf:
        return set(zf.namelist())


def list_apk_file_infos(apk_path: str) -> list[dict[str, Any]]:
    """Return APK entries with sizes."""
    infos: list[dict[str, Any]] = []
    try:
        with zipfile.ZipFile(apk_path, "r") as zf:
            for item in zf.infolist():
                if item.is_dir():
                    continue
                infos.append(
                    {
                        "path": item.filename,
                        "size": item.file_size,
                    }
                )
    except zipfile.BadZipFile:
        for name in sorted(list_apk_file_names(apk_path)):
            infos.append({"path": name, "size": 0})
    return infos


def _read_apk_entry_bytes(apk_path: str, entry_path: str, max_bytes: int | None = None) -> bytes | None:
    try:
        with zipfile.ZipFile(apk_path, "r") as zf:
            data = zf.read(entry_path)
    except Exception:
        return None
    return data[:max_bytes] if max_bytes is not None else data


def _basename(path: str) -> str:
    return path.rsplit("/", 1)[-1]


def _is_text_compatible(path: str, format_hint: str) -> bool:
    if format_hint in TEXT_COMPATIBLE_HINTS:
        return True
    ext = Path(path).suffix.lower()
    return ext in TEXT_EXTENSIONS


def _artifact_root(path: str, category: str) -> str:
    parts = path.split("/")
    if category == "dex":
        return parts[0]
    if category == "native_libs":
        return "lib/"
    if category == "managed_assemblies":
        if path.startswith("assets/bin/Data/Managed/"):
            return "assets/bin/Data/Managed/"
        return "assemblies/"
    if category == "web_assets":
        if path.startswith("assets/www/"):
            return "assets/www/"
        if path.startswith("assets/public/"):
            return "assets/public/"
        return "assets/"
    if category == "engine_assets":
        if path.startswith("assets/bin/Data/"):
            return "assets/bin/Data/"
        if path.startswith("assets/Unreal/"):
            return "assets/Unreal/"
        return path
    if category == "js_bundle":
        return path
    if category == "config":
        if path.startswith("assets/flutter_assets/"):
            return "assets/flutter_assets/"
        if len(parts) > 1:
            return "/".join(parts[:-1]) + "/"
    return path


def _classify_artifact(path: str) -> tuple[str | None, str]:
    lower = path.lower()
    ext = Path(path).suffix.lower()
    base = _basename(lower)

    if lower.endswith(".dex"):
        return "dex", "dex"

    if lower.endswith(".so"):
        return "native_libs", "shared_library"

    if lower.endswith(".dll"):
        return "managed_assemblies", "dotnet_assembly"

    if base in JS_BUNDLE_NAMES or lower.endswith(".bundle") or lower.endswith(".hbc"):
        if lower.endswith(".hbc"):
            return "js_bundle", "hermes_bytecode"
        return "js_bundle", "javascript"

    if lower.startswith("assets/www/") or lower.startswith("assets/public/"):
        if ext == ".html":
            return "web_assets", "html"
        if ext == ".css":
            return "web_assets", "css"
        if ext in {".js", ".mjs", ".jsx", ".ts", ".tsx"}:
            return "web_assets", "javascript"
        return "web_assets", "text" if ext in TEXT_EXTENSIONS else "binary_asset"

    if lower.startswith("assets/bin/data/") or "global-metadata.dat" in lower or ext in ENGINE_SUFFIXES:
        if "global-metadata.dat" in lower:
            return "engine_assets", "unity_metadata"
        if ext in ENGINE_SUFFIXES:
            return "engine_assets", "engine_package"
        if lower.endswith(".dll"):
            return "managed_assemblies", "dotnet_assembly"
        return "engine_assets", "binary_asset"

    if lower.endswith("config.xml") or base in {
        "capacitor.config.json",
        "capacitor.plugins.json",
        "cordova_plugins.js",
        "expo-manifest.json",
        "assetmanifest.json",
        "pubspec.yaml",
        "google-services.json",
        "firebase-config.json",
    }:
        if ext == ".js":
            return "config", "javascript"
        if ext == ".json":
            return "config", "json"
        if ext in {".yaml", ".yml"}:
            return "config", "yaml"
        return "config", "xml"

    if lower.startswith("assets/flutter_assets/"):
        if ext == ".json":
            return "config", "json"
        if ext in {".txt", ".yaml", ".yml"}:
            return "config", "text"
        if ext == ".xml":
            return "config", "xml"
        return "config", "binary_asset"

    if lower.startswith("assets/") and ext in {".html", ".js", ".css"}:
        return "web_assets", "javascript" if ext == ".js" else ext.lstrip(".")

    if ext in CONFIG_EXTENSIONS:
        if ext == ".json":
            return "config", "json"
        if ext in {".yaml", ".yml"}:
            return "config", "yaml"
        if ext == ".xml":
            return "config", "xml"
        if ext == ".js":
            return "config", "javascript"
        return "config", "text"

    return None, "binary_asset"


def build_artifact_index(apk_path: str) -> dict[str, Any]:
    """Index APK artifacts into framework-aware categories."""
    infos = list_apk_file_infos(apk_path)
    categories: dict[str, list[dict[str, Any]]] = {name: [] for name in ARTIFACT_CATEGORIES}
    artifact_roots: dict[str, list[str]] = {name: [] for name in ARTIFACT_CATEGORIES}

    for info in infos:
        path = info["path"]
        category, format_hint = _classify_artifact(path)
        if category is None:
            continue

        artifact = {
            "path": path,
            "size": info["size"],
            "format_hint": format_hint,
            "text_compatible": _is_text_compatible(path, format_hint),
        }
        categories[category].append(artifact)

        root = _artifact_root(path, category)
        if root not in artifact_roots[category]:
            artifact_roots[category].append(root)

    for category in ARTIFACT_CATEGORIES:
        categories[category].sort(key=lambda item: (item["path"]))
        artifact_roots[category].sort()

    counts = {category: len(items) for category, items in categories.items()}

    return {
        "counts": counts,
        "artifacts": categories,
        "artifact_roots": {k: v for k, v in artifact_roots.items() if v},
        "total_indexed": sum(counts.values()),
        "all_files": len(infos),
    }


def _has_any(file_names: set[str], *patterns: str) -> bool:
    return any(any(pattern in name for name in file_names) for pattern in patterns)


def _infer_format_hints(apk_path: str, file_names: set[str], artifact_index: dict[str, Any]) -> dict[str, Any]:
    hints: dict[str, Any] = {}

    if _has_any(file_names, "libflutter.so"):
        if _has_any(file_names, "kernel_blob.bin"):
            hints["flutter_mode"] = "debug_or_recoverable"
        elif _has_any(file_names, "libapp.so"):
            hints["flutter_mode"] = "release_aot"
        else:
            hints["flutter_mode"] = "unknown"
        hints["blutter_available"] = blutter_script_path().is_file()

    if _has_any(file_names, "index.android.bundle", "shell-app.bundle", ".bundle"):
        bundle_path = next(
            (
                artifact["path"]
                for artifact in artifact_index["artifacts"]["js_bundle"]
                if artifact["path"].endswith((".bundle", ".hbc"))
            ),
            None,
        )
        bundle_head = _read_apk_entry_bytes(apk_path, bundle_path, max_bytes=8) if bundle_path else None
        if bundle_head and (bundle_head.startswith(b"HBC") or bundle_head.startswith(bytes.fromhex("c61fbc03"))):
            hints["js_bundle_type"] = "hermes"
        elif _has_any(file_names, "libhermes.so") or bundle_path and bundle_path.endswith(".hbc"):
            hints["js_bundle_type"] = "hermes"
        else:
            hints["js_bundle_type"] = "plain_js"

    if _has_any(file_names, "libunity.so"):
        if _has_any(file_names, "libil2cpp.so", "global-metadata.dat"):
            hints["unity_backend"] = "il2cpp"
        elif any(artifact["path"].endswith(".dll") for artifact in artifact_index["artifacts"]["managed_assemblies"]):
            hints["unity_backend"] = "mono"

    if artifact_index["artifacts"]["native_libs"]:
        abis = sorted(
            {
                artifact["path"].split("/")[1]
                for artifact in artifact_index["artifacts"]["native_libs"]
                if artifact["path"].count("/") >= 2
            }
        )
        if abis:
            hints["native_abis"] = abis

    if artifact_index["artifacts"]["js_bundle"]:
        hints["js_bundle_paths"] = [artifact["path"] for artifact in artifact_index["artifacts"]["js_bundle"][:3]]

    if artifact_index["artifacts"]["managed_assemblies"]:
        hints["managed_entrypoints"] = [
            artifact["path"] for artifact in artifact_index["artifacts"]["managed_assemblies"][:5]
        ]

    return hints


def _default_native_result(file_names: set[str], artifact_index: dict[str, Any]) -> dict[str, Any]:
    native_libs = [artifact["path"].split("/")[-1] for artifact in artifact_index["artifacts"]["native_libs"]]
    dex_count = len(artifact_index["artifacts"]["dex"])
    return {
        "primary_framework": "Native (Java/Kotlin)",
        "all_detected": ["Native (Java/Kotlin)"],
        "is_native_android": True,
        "detected_details": [],
        "build_technologies": ["native_android"],
        "analysis_guide": DEFAULT_NATIVE_GUIDE,
        "apk_contents_summary": {
            "total_files": len(file_names),
            "dex_files": dex_count,
            "native_libs_count": len(native_libs),
            "native_libs": native_libs[:20],
            "asset_files_count": len([name for name in file_names if name.startswith("assets/")]),
        },
    }


def _framework_details(
    file_names: set[str],
) -> list[dict[str, Any]]:
    details: list[dict[str, Any]] = []
    for signature in FRAMEWORK_SIGNATURES:
        matched = [indicator for indicator in signature["indicators"] if any(indicator in name for name in file_names)]
        if matched:
            details.append(
                {
                    "framework": signature["name"],
                    "build_technology": signature["build_technology"],
                    "matched_files": matched,
                    "analysis_guide": signature["analysis_guide"],
                }
            )
    return details


def _effective_support_level(route_key: str, format_hints: dict[str, Any]) -> str:
    """Downgrade template support_level to 'partial' when the required backend tool is absent."""
    template_level = ROUTE_TEMPLATES[route_key]["support_level"]

    if route_key == "flutter_release_aot":
        if not format_hints.get("blutter_available", False):
            return "partial"

    elif route_key in ("dotnet", "unity_mono"):
        ilspy = Path(os.environ.get("ILSPY_PATH", "/opt/ilspy/ilspycmd"))
        if not ilspy.is_file():
            return "partial"

    elif route_key == "unity_il2cpp":
        dumper = Path(os.environ.get("IL2CPPDUMPER_PATH", "/usr/local/bin/il2cppdumper"))
        if not dumper.is_file():
            return "partial"

    elif route_key == "react_native_hermes":
        if format_hints.get("js_bundle_type") == "hermes":
            hermes_dec = Path(os.environ.get("HERMES_DEC_PATH", "/opt/hermes-dec/hbc-decompiler"))
            if not hermes_dec.is_file():
                return "partial"

    return template_level


# Native lib name substrings that indicate a packer or protection framework.
# These signal a hardened APK regardless of the primary app framework.
_PACKER_LIB_PATTERNS: frozenset[str] = frozenset([
    "jiagu",       # 360 Jiagu
    "secshell",    # Bangcle/SecShell
    "rsprotect",   # ijiami RSProtect
    "ijiami",      # ijiami
    "bangcle",     # Bangcle
    "ddog",        # DataDome / anti-tamper
    "nsafer",      # NQ Shield
    "nqshield",    # NQ Shield
    "virbox",      # Virbox Protector
    "safenet",     # SafeNet Sentinel
    "libanticrack",
    "libprotect",
    "libDexProtect",
    "libdexprotect",
    "libNativeGun",
    "libnativegun",
    "libShell",
    "libshell",
])


def _choose_route_key(
    primary_framework: str,
    details: list[dict[str, Any]],
    format_hints: dict[str, Any],
    artifact_index: dict[str, Any],
) -> str:
    # Multiple distinct framework signatures → mixed attack surface
    if len(details) > 1:
        distinct_frameworks = {item["framework"] for item in details}
        if distinct_frameworks - {"React Native", "Expo (React Native)"}:
            return "mixed_hardened"

    # Packer or protection library presence → escalate regardless of primary framework
    native_lib_names = {
        Path(a["path"]).name.lower()
        for a in artifact_index["artifacts"]["native_libs"]
    }
    if any(pat in name for name in native_lib_names for pat in _PACKER_LIB_PATTERNS):
        return "mixed_hardened"

    if primary_framework == "Flutter":
        return "flutter_debug" if format_hints.get("flutter_mode") == "debug_or_recoverable" else "flutter_release_aot"

    if primary_framework in {"React Native", "Expo (React Native)"}:
        return "react_native_hermes" if format_hints.get("js_bundle_type") == "hermes" else "react_native_plain_js"

    if primary_framework == "Unity":
        return "unity_il2cpp" if format_hints.get("unity_backend") == "il2cpp" else "unity_mono"

    if primary_framework == "Xamarin":
        return "dotnet"

    if primary_framework == "Unreal Engine":
        return "unreal_native"

    if primary_framework in {"Cordova", "Capacitor", "Kony Visualizer"}:
        return "web_hybrid"

    route_key = FRAMEWORK_TO_ROUTE.get(primary_framework, "native_java_kotlin")

    container_count = sum(1 for count in artifact_index["counts"].values() if count > 0)
    if route_key == "native_java_kotlin" and container_count >= 4 and artifact_index["counts"]["js_bundle"] > 0:
        return "mixed_hardened"

    return route_key


def _containers_for_route(route_key: str, artifact_index: dict[str, Any]) -> tuple[str, list[str], list[str]]:
    if route_key == "native_java_kotlin":
        primary = "dex"
    elif route_key in {"flutter_release_aot", "unity_il2cpp", "unreal_native"}:
        primary = "native_libs"
    elif route_key == "flutter_debug":
        primary = "config"
    elif route_key in {"react_native_plain_js", "react_native_hermes"}:
        primary = "js_bundle"
    elif route_key == "web_hybrid":
        primary = "web_assets"
    elif route_key in {"dotnet", "unity_mono"}:
        primary = "managed_assemblies"
    else:
        # Prefer the richest non-empty bucket.
        for candidate in ("js_bundle", "web_assets", "managed_assemblies", "native_libs", "dex", "engine_assets", "config"):
            if artifact_index["counts"].get(candidate, 0) > 0:
                primary = candidate
                break
        else:
            primary = "dex"

    ordered = [primary]
    for candidate in ("js_bundle", "web_assets", "managed_assemblies", "native_libs", "engine_assets", "config", "dex"):
        if candidate != primary and artifact_index["counts"].get(candidate, 0) > 0 and candidate not in ordered:
            ordered.append(candidate)
    secondary = ordered[1:]
    return primary, secondary, ordered


def detect_framework(apk_path: str) -> dict[str, Any]:
    """Detect framework and dominant code container for an APK."""
    file_names = list_apk_file_names(apk_path)
    artifact_index = build_artifact_index(apk_path)
    details = _framework_details(file_names)

    if details:
        framework_names = [item["framework"] for item in details]
        primary_framework = framework_names[0]
        is_native = False
        analysis_guide = details[0]["analysis_guide"]
        build_technologies = list(dict.fromkeys(item["build_technology"] for item in details))
    else:
        base = _default_native_result(file_names, artifact_index)
        framework_names = base["all_detected"]
        primary_framework = base["primary_framework"]
        is_native = True
        analysis_guide = base["analysis_guide"]
        build_technologies = base["build_technologies"]

    format_hints = _infer_format_hints(apk_path, file_names, artifact_index)
    route_key = _choose_route_key(primary_framework, details, format_hints, artifact_index)
    primary_container, secondary_containers, code_containers = _containers_for_route(route_key, artifact_index)
    template = ROUTE_TEMPLATES[route_key]

    native_libs = [artifact["path"].split("/")[-1] for artifact in artifact_index["artifacts"]["native_libs"]]

    result: dict[str, Any] = {
        "primary_framework": primary_framework,
        "all_detected": framework_names,
        "is_native_android": is_native,
        "recommended_analysis_path": [
            "1. detect_framework — fingerprint packaging and code containers",
            "2. check_apk_tampering — lower confidence early if the APK is structurally suspicious",
            f"3. plan_static_analysis — follow the {template['title']} route",
        ],
        "apk_contents_summary": {
            "total_files": len(file_names),
            "dex_files": len(artifact_index["artifacts"]["dex"]),
            "native_libs_count": len(native_libs),
            "native_libs": native_libs[:20],
            "asset_files_count": len([name for name in file_names if name.startswith("assets/")]),
        },
        "analysis_guide": analysis_guide,
        "build_technologies": build_technologies,
        "code_containers": code_containers,
        "primary_container": primary_container,
        "secondary_containers": secondary_containers,
        "format_hints": format_hints,
        "support_level": _effective_support_level(route_key, format_hints),
        "artifact_roots": artifact_index["artifact_roots"],
        "route_key": route_key,
    }

    if details:
        result["detected_details"] = details
        result["hint"] = (
            f"This app uses {primary_framework}. Meaningful logic is most likely in "
            f"{primary_container.replace('_', ' ')} artifacts, not only the Android wrapper."
        )
    else:
        result["hint"] = (
            "This looks like a standard native Android app. DEX-centric analysis remains the primary path."
        )

    if primary_container != "dex":
        result["warning"] = (
            "Standard JADX/source-first analysis only covers wrapper or bridge code for this target. "
            "Follow the framework-aware static route before relying on DEX-centric outputs."
        )

    return result


def ensure_framework_metadata(session: AnalysisSession) -> dict[str, Any]:
    framework = session.metadata.get("framework")
    if framework:
        return framework

    apk_path = f"{session_workspace(session)}/app.apk"
    framework = detect_framework(apk_path)
    session.metadata["framework"] = framework
    return framework


def ensure_artifact_index(session: AnalysisSession) -> dict[str, Any]:
    artifact_index = session.metadata.get("artifact_index")
    if artifact_index:
        return artifact_index

    apk_path = f"{session_workspace(session)}/app.apk"
    artifact_index = build_artifact_index(apk_path)
    session.metadata["artifact_index"] = artifact_index
    return artifact_index


def build_static_route(
    session: AnalysisSession,
    framework: dict[str, Any] | None = None,
    artifact_index: dict[str, Any] | None = None,
    tampering: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build the actionable framework-aware static analysis route."""
    framework = framework or ensure_framework_metadata(session)
    artifact_index = artifact_index or ensure_artifact_index(session)
    tampering = tampering or session.metadata.get("tampering") or {}

    route_key = framework.get("route_key") or _choose_route_key(
        framework.get("primary_framework", "Native (Java/Kotlin)"),
        framework.get("detected_details", []),
        framework.get("format_hints", {}),
        artifact_index,
    )
    template = ROUTE_TEMPLATES[route_key]

    primary_container = framework.get("primary_container", "dex")
    secondary_containers = framework.get("secondary_containers", [])
    relevant_categories = [primary_container] + [item for item in secondary_containers if item in ARTIFACT_CATEGORIES]
    high_yield_artifacts: list[str] = []
    for category in relevant_categories:
        for artifact in artifact_index["artifacts"].get(category, [])[:5]:
            high_yield_artifacts.append(artifact["path"])

    ordered_steps = [
        "Run manifest and exported-component checks first to recover the cross-category attack surface.",
        template["primary_deep_analysis_step"],
        "Use list_static_artifacts to inventory the route-relevant containers and file roots.",
    ]

    if primary_container in {"js_bundle", "web_assets", "config", "managed_assemblies"}:
        ordered_steps.append("Use search_static_artifacts and read_static_artifact before relying on JADX output.")
    elif primary_container in {"native_libs", "engine_assets"}:
        ordered_steps.append("Prioritise native library strings, metadata, and engine assets before Java source.")
    else:
        ordered_steps.append("Use get_security_overview(scan_mode='both') and DEX decompilation for code triage.")

    verdict = ((tampering or {}).get("assessment") or {}).get("verdict", "UNKNOWN")
    confidence = "high"
    warnings: list[str] = []
    if verdict in {"SUSPICIOUS", "HIGHLY SUSPICIOUS"}:
        confidence = "low"
        warnings.append(
            "APK tampering was flagged as suspicious. Treat all static outputs as lower-confidence and prioritise dynamic confirmation."
        )
    elif route_key in {"flutter_release_aot", "react_native_hermes", "unity_il2cpp", "unreal_native", "mixed_hardened"}:
        confidence = "medium"

    route = {
        "route_key": route_key,
        "route_title": template["title"],
        "support_level": _effective_support_level(route_key, framework.get("format_hints", {})),
        "primary_framework": framework.get("primary_framework"),
        "build_technologies": framework.get("build_technologies", []),
        "primary_container": primary_container,
        "secondary_containers": secondary_containers,
        "analysis_focus": template["analysis_focus"],
        "primary_deep_analysis_step": template["primary_deep_analysis_step"],
        "ordered_steps": ordered_steps,
        "recommended_tools": template["recommended_tools"],
        "deprioritized_tools": template["deprioritized_tools"],
        "wrapper_only_tools": template["wrapper_only_tools"],
        "cross_category_checks": CROSS_CATEGORY_CHECKS,
        "high_yield_artifacts": high_yield_artifacts,
        "manual_followup": template["manual_followup"],
        "dynamic_hypotheses": template["dynamic_hypotheses"],
        "format_hints": framework.get("format_hints", {}),
        "artifact_roots": framework.get("artifact_roots", artifact_index.get("artifact_roots", {})),
        "confidence": confidence,
        "warnings": warnings,
    }
    session.metadata["static_route"] = route
    return route


def get_wrapper_only_warning(
    session: AnalysisSession,
    tool_name: str,
    scan_mode: str | None = None,
) -> str | None:
    """Return a warning when a DEX-centric tool only sees wrapper code."""
    if tool_name not in DEX_CENTRIC_WRAPPER_WARNING_TOOLS:
        return None

    framework = session.metadata.get("framework") or {}
    route = session.metadata.get("static_route") or {}
    primary_container = route.get("primary_container") or framework.get("primary_container")
    primary_framework = framework.get("primary_framework", "this")
    route_title = route.get("route_title") or framework.get("route_key", "framework-aware route")

    if not primary_container or primary_container == "dex":
        return None

    if tool_name == "get_security_overview" and scan_mode == "bytecode":
        return None

    if tool_name == "get_security_overview" and scan_mode == "both":
        return (
            f"Source-mode results only cover the Android wrapper for this {primary_framework} target. "
            "The bytecode half remains useful for bridge/native-call triage."
        )

    if tool_name == "get_security_overview" and scan_mode == "source":
        return (
            f"Source-mode security overview only covers wrapper code for this {primary_framework} target "
            f"because the dominant container is {primary_container.replace('_', ' ')}."
        )

    return (
        f"{tool_name} is DEX-centric and primarily covers wrapper/bridge code for this "
        f"{primary_framework} target because meaningful logic is in {primary_container.replace('_', ' ')}. "
        f"Prioritise the {route_title} route first."
    )


def normalize_scope(scope: str | None) -> str | None:
    if not scope:
        return None
    if scope not in ARTIFACT_CATEGORIES:
        raise ValueError(f"Unknown scope '{scope}'. Available: {', '.join(ARTIFACT_CATEGORIES)}")
    return scope


def blutter_script_path() -> Path:
    blutter_home = Path(os.environ.get("BLUTTER_HOME", "/opt/blutter"))
    return blutter_home / "blutter.py"


def extract_artifact_to_workspace(session: AnalysisSession, artifact_path: str) -> Path:
    """Extract a single APK artifact into the session workspace cache."""
    if ".." in artifact_path or artifact_path.startswith("/"):
        raise ValueError("Invalid artifact path")

    dest = ensure_session_artifact_path(session, "artifacts", "raw", artifact_path)
    if dest.exists():
        return dest

    apk_path = f"{session_workspace(session)}/app.apk"
    data = _read_apk_entry_bytes(apk_path, artifact_path)
    if data is None:
        raise FileNotFoundError(f"Artifact not found in APK: {artifact_path}")
    dest.write_bytes(data)
    return dest
