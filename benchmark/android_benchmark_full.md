# Android APK Vulnerability Benchmark Specification
## Ground-truth catalog for `allsafe-android` and `ostorlab_insecure_android_app`

---

## 1. Purpose

This document defines a practical benchmark specification for evaluating an automated APK vulnerability analysis tool against two intentionally vulnerable repositories:

- `t0thkr1s/allsafe-android`
- `Ostorlab/ostorlab_insecure_android_app`

The goal is to provide a clean, benchmarkable ground-truth set that lets you score:

- which vulnerabilities your tool correctly identifies
- which expected vulnerabilities it misses
- which findings it reports that do not belong in the expected set

This document is intended to be used as a manual benchmark reference and as a basis for a later machine-readable dataset such as CSV, JSON, or XLSX.

---

## 2. Scope

### Included
This benchmark includes:

- Allsafe: only the entries that are actual vulnerabilities
- Ostorlab Android-native module: the repo-listed vulnerability set
- Ostorlab Flutter module: the repo-listed vulnerability set

### Excluded
This benchmark excludes the following from the Allsafe denominator:

- Root detection bypass exercises
- Secure flag bypass exercises
- Certificate pinning bypass exercises
- Smali patching exercises
- Reverse-engineering-only tasks that are not clearly declared as app vulnerabilities

These excluded items can still be useful for training, but they should not count against a vulnerability scanner unless you explicitly create a second benchmark track for anti-analysis and exploitation exercises.

---

## 3. Important assumptions

1. Repository README content is treated as declared ground truth.
2. This is a benchmarking catalog, not a full source-code audit.
3. Not every repo-listed item is equally suitable for static analysis.
4. Family-level and instance-level scoring should be separated.
5. Flutter and native Android should be evaluated separately.
6. Ostorlab’s Flutter list includes a duplicated `InsecureSharedPreferences` mention in the README. For benchmarking, it should be treated as one vulnerability type unless the codebase is manually confirmed to contain multiple distinct instances.

---

## 4. How this benchmark should be used

### Recommended workflow

1. Run the tool against the APK or source-based build artifact.
2. Export the raw findings produced by the tool.
3. Normalize each finding into:
   - a specific finding label
   - a canonical vulnerability family
4. Compare the normalized findings against this document.
5. Mark each detection as one of:
   - true positive (instance)
   - true positive (family only)
   - false positive
   - false negative
6. Calculate performance metrics.

### Why normalization matters

Different tools will use different names for the same issue.

Examples:
- `AES/ECB insecure mode` and `weak block cipher mode` may refer to the same family.
- `unsafe dynamic code loading` may correspond to `DexClassLoaderCall`, `PathClassLoaderCall`, or `PackageContextLoadCall`.
- `exported component abuse` may correspond to an insecure broadcast or intent misuse.

Without normalization, semantically correct detections may be misclassified as misses.

---

## 5. Scoring model

### 5.1 Instance-level true positive
A finding is an instance-level true positive if it matches:

- the expected vulnerability type
- the implementation mechanism or sink
- the correct location or code path with reasonable specificity

### 5.2 Family-level true positive
A finding is a family-level true positive if it matches the general security class, even if the exact primitive or label differs.

### 5.3 False positive
A finding is a false positive if:

- it does not map to any declared vulnerability in this benchmark, and
- it cannot be justified through manual validation as a real issue in the benchmark target

### 5.4 False negative
A false negative is any benchmark entry that should have been reported under the tool’s claimed capabilities but was not found.

### 5.5 Recommended metrics

#### Instance recall
```text
instance_recall = instance_true_positives / total_expected_instances
```

#### Family recall
```text
family_recall = family_true_positives / total_expected_families
```

#### Precision
```text
precision = true_positives / total_reported_findings
```

#### Noise rate
```text
noise_rate = false_positives / total_reported_findings
```

Track at least these additional dimensions:

- static coverage
- dynamic coverage
- hybrid coverage
- native Android coverage
- Flutter coverage

---

## 6. Canonical families used in this benchmark

The following families are used to normalize findings:

- Sensitive Data Exposure
- Hardcoded Secrets
- Insecure Dynamic Loading / Code Loading
- IPC / Intent Abuse
- Deep Link Abuse
- SQL Injection
- Insecure WebView
- Weak Cryptography
- Weak Randomness
- Insecure Transport
- Weak TLS / SSL Configuration
- Insecure Local Storage / File Permissions
- Command Injection / Unsafe Command Execution
- Memory Corruption
- Path Traversal
- PendingIntent Misuse
- Risky Platform Misconfiguration

---

# 7. Allsafe benchmark set
## Filtered to actual vulnerabilities only

The Allsafe README lists 12 challenges, but only a subset are actual vulnerability benchmark targets. The following 7 should be included in the denominator.

### ALLSAFE-01 — Insecure Logging
**Repo label:** Insecure Logging  
**Benchmarkable:** Yes  
**Canonical family:** Sensitive Data Exposure  
**Expected detection mode:** Static and optionally dynamic  
**Description:** Sensitive information is written to application logs and can be recovered through `logcat`. This is an information disclosure issue because local logs may expose secrets, tokens, identifiers, or internal state that should not be observable.  
**What a good tool should detect:** Logging APIs used with sensitive values, secrets, tokens, credentials, or internal security material.  
**Minimum benchmark match:** Report of sensitive data written to logs.  
**Notes:** This is a strong benchmark item for static analysis and also easy to validate dynamically.

### ALLSAFE-02 — Hardcoded Credentials
**Repo label:** Hardcoded Credentials  
**Benchmarkable:** Yes  
**Canonical family:** Hardcoded Secrets  
**Expected detection mode:** Static  
**Description:** Credentials or other sensitive material are embedded directly in the application code or resources. Reverse engineering the APK reveals secrets that should never have been shipped client-side.  
**What a good tool should detect:** Hardcoded passwords, API keys, tokens, backend credentials, or authentication constants.  
**Minimum benchmark match:** Report of embedded credential-like or secret-like data in code/resources.  
**Notes:** This is a core static-analysis benchmark item.

### ALLSAFE-04 — Arbitrary Code Execution
**Repo label:** Arbitrary Code Execution  
**Benchmarkable:** Yes  
**Canonical family:** Insecure Dynamic Loading / Code Loading  
**Expected detection mode:** Static or hybrid  
**Description:** The application insecurely loads modules or functionality in a way that may be influenced or hijacked by a third-party application. That can lead to execution of attacker-controlled code in the app context.  
**What a good tool should detect:** Unsafe package context use, unsafe external code loading, classloader misuse, trust of third-party packages, or attacker-controlled load paths.  
**Minimum benchmark match:** Report of unsafe dynamic/module/package loading that could enable code execution or context hijack.  
**Notes:** Family-level matching is especially important here because tools may describe the issue using different terminology.

### ALLSAFE-07 — Insecure Broadcast Receiver
**Repo label:** Insecure Broadcast Receiver  
**Benchmarkable:** Yes  
**Canonical family:** IPC / Intent Abuse  
**Expected detection mode:** Static and optionally dynamic  
**Description:** The application contains a broadcast receiver that can be externally triggered with attacker-supplied data and insufficient protection. This can expose privileged behavior or hidden app functionality.  
**What a good tool should detect:** Exported receivers, insufficient permission protection, unsafe trust in incoming extras, or sensitive actions reachable over broadcasts.  
**Minimum benchmark match:** Report of an insecure, externally triggerable broadcast receiver.  
**Notes:** Manifest analysis plus sink analysis is typically enough to produce a meaningful detection.

### ALLSAFE-08 — Deep Link Exploitation
**Repo label:** Deep Link Exploitation  
**Benchmarkable:** Yes  
**Canonical family:** Deep Link Abuse  
**Expected detection mode:** Static and optionally dynamic  
**Description:** A deep link entry point accepts attacker-controlled parameters and trusts them too much. This may enable unauthorized actions, state changes, navigation abuse, or injection-style behavior.  
**What a good tool should detect:** Deep link intent filters, unsafe query parameter handling, dangerous action routing from URIs, or privileged flows triggered through external links.  
**Minimum benchmark match:** Report of unsafe deep link handling or exploitable external URI input.  
**Notes:** This is often found by combining manifest entrypoint discovery with dataflow analysis.

### ALLSAFE-09 — SQL Injection
**Repo label:** SQL Injection  
**Benchmarkable:** Yes  
**Canonical family:** SQL Injection  
**Expected detection mode:** Static and optionally dynamic  
**Description:** User-controlled input flows into SQL query construction without safe parameterization. This can allow authentication bypass, data disclosure, or manipulation of database queries.  
**What a good tool should detect:** String concatenation in SQL statements, unsafe raw query usage, lack of parameter binding, or attacker-controlled query fragments.  
**Minimum benchmark match:** Report of injectable SQL query construction.  
**Notes:** This is one of the clearest benchmark items in the set.

### ALLSAFE-10 — Vulnerable WebView
**Repo label:** Vulnerable WebView  
**Benchmarkable:** Yes  
**Canonical family:** Insecure WebView  
**Expected detection mode:** Static and optionally dynamic  
**Description:** The WebView configuration and/or content handling allows dangerous behavior such as JavaScript abuse, local file access, or script execution against sensitive content.  
**What a good tool should detect:** Dangerous WebView settings, untrusted content loading, local file access enabled with unsafe input, JavaScript interfaces, or WebView debugging risk depending on implementation.  
**Minimum benchmark match:** Report of dangerous WebView configuration or exploitable content handling.  
**Notes:** The exact sink may differ, so family-level matching can be useful when the tool identifies the WebView risk correctly but labels it slightly differently.

## Allsafe denominator
```text
Total Allsafe benchmarkable vulnerabilities: 7
```

---

# 8. Ostorlab Android-native benchmark set

The Ostorlab README presents a much more benchmark-oriented list. These entries are appropriate as declared test cases for your evaluation.

### OST-AND-01 — AESCipher
**Repo label:** AESCipher  
**Benchmarkable:** Yes  
**Canonical family:** Weak Cryptography  
**Expected detection mode:** Static  
**Description:** AES is used without securely specifying mode, which defaults to insecure ECB behavior according to the repo description.  
**What a good tool should detect:** AES usage with insecure defaults or ECB semantics.  
**Minimum benchmark match:** Report of insecure AES/ECB-style encryption usage.  
**Notes:** This overlaps conceptually with `ECBModeCipher`, so score instance-level and family-level separately.

### OST-AND-02 — ClearTextTraffic
**Repo label:** ClearTextTraffic  
**Benchmarkable:** Yes  
**Canonical family:** Insecure Transport  
**Expected detection mode:** Static and optionally dynamic  
**Description:** Traffic is sent without proper TLS protection, allowing interception and tampering.  
**What a good tool should detect:** Cleartext network configuration, HTTP usage for sensitive flows, or disabled transport protections.  
**Minimum benchmark match:** Report of plaintext or non-TLS transport.

### OST-AND-03 — CommandExec
**Repo label:** CommandExec  
**Benchmarkable:** Yes  
**Canonical family:** Command Injection / Unsafe Command Execution  
**Expected detection mode:** Static and hybrid  
**Description:** Attacker-controlled input can reach shell execution or command execution primitives.  
**What a good tool should detect:** `Runtime.exec`, `ProcessBuilder`, shell wrappers, or command sinks reachable from untrusted input.  
**Minimum benchmark match:** Report of unsafe command execution or command injection.

### OST-AND-04 — DexClassLoaderCall
**Repo label:** DexClassLoaderCall  
**Benchmarkable:** Yes  
**Canonical family:** Insecure Dynamic Loading / Code Loading  
**Expected detection mode:** Static or hybrid  
**Description:** The app loads jar/apk content from an insecure location, which can be hijacked for code execution or data access.  
**What a good tool should detect:** `DexClassLoader` usage loading from attacker-reachable storage or untrusted paths.  
**Minimum benchmark match:** Report of insecure dynamic code loading.

### OST-AND-05 — ECBModeCipher
**Repo label:** ECBModeCipher  
**Benchmarkable:** Yes  
**Canonical family:** Weak Cryptography  
**Expected detection mode:** Static  
**Description:** Explicit or effective use of ECB mode.  
**What a good tool should detect:** ECB mode selection or AES configuration indicating ECB usage.  
**Minimum benchmark match:** Report of insecure ECB mode.

### OST-AND-06 — HashCall
**Repo label:** HashCall  
**Benchmarkable:** Yes  
**Canonical family:** Weak Cryptography  
**Expected detection mode:** Static  
**Description:** The README does not expand the description in the visible list, but the case is declared as a vulnerability item related to hashing.  
**What a good tool should detect:** Weak, outdated, or unsafe hashing use; likely unsalted or inappropriate digest primitives depending on implementation.  
**Minimum benchmark match:** Report of weak hashing or unsafe digest usage.  
**Notes:** Keep this mapped conservatively because the README text is sparse.

### OST-AND-07 — InsecureCommands
**Repo label:** InsecureCommands  
**Benchmarkable:** Yes  
**Canonical family:** Insecure Local Storage / File Permissions  
**Expected detection mode:** Static  
**Description:** The README description associates this item with insecure storage of sensitive information through weak permissions or lack of encryption.  
**What a good tool should detect:** Sensitive data stored with weak protection, insecure permissions, or unencrypted storage reachable by other apps/users.  
**Minimum benchmark match:** Report of insecure storage or storage protection weakness.  
**Notes:** The label name is somewhat misleading relative to the visible description, so favor the repo text over the label wording.

### OST-AND-08 — InsecureFilePermissions
**Repo label:** InsecureFilePermissions  
**Benchmarkable:** Yes  
**Canonical family:** Insecure Local Storage / File Permissions  
**Expected detection mode:** Static  
**Description:** Files are handled with world-readable/world-writable permissions or through insecure external storage patterns.  
**What a good tool should detect:** External storage use for sensitive data, permissive file modes, or unsafe file-sharing practices.  
**Minimum benchmark match:** Report of insecure file permissions or external-storage exposure.

### OST-AND-09 — InsecureRandom
**Repo label:** InsecureRandom  
**Benchmarkable:** Yes  
**Canonical family:** Weak Randomness  
**Expected detection mode:** Static  
**Description:** A random number generator is seeded with a constant value, making output predictable.  
**What a good tool should detect:** Constant seeding, weak PRNG use in security-sensitive contexts, or deterministic randomness.  
**Minimum benchmark match:** Report of predictable random generation.

### OST-AND-10 — IntentCall
**Repo label:** IntentCall  
**Benchmarkable:** Yes  
**Canonical family:** IPC / Intent Abuse  
**Expected detection mode:** Static  
**Description:** Data is broadcast through an intent created from a hardcoded string. The README marks this item as `[TODO]`, but it is still a listed test case.  
**What a good tool should detect:** Broadcast misuse, unprotected intent communication, or insecure implicit messaging.  
**Minimum benchmark match:** Report of insecure broadcast/intent usage.  
**Notes:** Because the README labels it `[TODO]`, keep a note in your results that the case is repo-declared but may be less mature.

### OST-AND-11 — MemoryCorruption
**Repo label:** MemoryCorruption  
**Benchmarkable:** Yes  
**Canonical family:** Memory Corruption  
**Expected detection mode:** Hybrid or dynamic, possibly static with native heuristics  
**Description:** Generic memory corruption issues can lead to denial of service, information leak, arbitrary read/write, or code execution.  
**What a good tool should detect:** Unsafe native memory handling, risky JNI/native surfaces, or memory-corruption indicators if supported.  
**Minimum benchmark match:** Report of memory corruption or unsafe native memory handling.  
**Notes:** Do not penalize a purely static Java/Kotlin scanner too heavily here unless it claims native vulnerability coverage.

### OST-AND-12 — MobileOnlyDownloadManager
**Repo label:** MobileOnlyDownloadManager  
**Benchmarkable:** Yes  
**Canonical family:** Risky Platform Misconfiguration  
**Expected detection mode:** Static  
**Description:** The app forces downloads to occur only over mobile network. This is weaker than the other issues from a classic exploitation perspective, but it is still a declared insecure/risky behavior in the repo.  
**What a good tool should detect:** Risky or policy-unsafe download manager configuration.  
**Minimum benchmark match:** Report of risky DownloadManager configuration.  
**Notes:** Consider weighting this lower than injection or crypto flaws.

### OST-AND-13 — PathClassLoaderCall
**Repo label:** PathClassLoaderCall  
**Benchmarkable:** Yes  
**Canonical family:** Insecure Dynamic Loading / Code Loading  
**Expected detection mode:** Static or hybrid  
**Description:** The application loads jar/apk content from an insecure location using a different loading mechanism than `DexClassLoaderCall`, but the family is the same.  
**What a good tool should detect:** `PathClassLoader` use with unsafe source material or untrusted load path.  
**Minimum benchmark match:** Report of insecure dynamic code loading.

### OST-AND-14 — SQLiteDatabaseCall
**Repo label:** SQLiteDatabaseCall  
**Benchmarkable:** Yes  
**Canonical family:** SQL Injection  
**Expected detection mode:** Static and optionally dynamic  
**Description:** SQL queries are built unsafely and can lead to injection.  
**What a good tool should detect:** Unsafe query building, raw SQL with concatenated input, or missing parameter binding.  
**Minimum benchmark match:** Report of SQL injection or injectable SQLite query construction.

### OST-AND-15 — StaticIV
**Repo label:** StaticIV  
**Benchmarkable:** Yes  
**Canonical family:** Weak Cryptography  
**Expected detection mode:** Static  
**Description:** A non-random initialization vector is used, enabling known-plaintext or dictionary-style attacks depending on context.  
**What a good tool should detect:** Constant IVs, predictable IV generation, or reused IV material in symmetric crypto.  
**Minimum benchmark match:** Report of static or predictable IV usage.

### OST-AND-16 — TLSTraffic
**Repo label:** TLSTraffic  
**Benchmarkable:** Yes  
**Canonical family:** Weak TLS / SSL Configuration  
**Expected detection mode:** Static, dynamic, or configuration-aware  
**Description:** The endpoint or connection supports weak protocol/cipher combinations with known cryptographic weaknesses.  
**What a good tool should detect:** Deprecated TLS versions, weak cipher suites, or insecure SSL/TLS negotiation options.  
**Minimum benchmark match:** Report of weak TLS or SSL configuration.

### OST-AND-17 — WebviewInsecureSettings
**Repo label:** WebviewInsecureSettings  
**Benchmarkable:** Yes  
**Canonical family:** Insecure WebView  
**Expected detection mode:** Static  
**Description:** WebView debugging is enabled and exposed through the Chrome Debug Protocol over an abstract socket, making it reachable by other apps on the device.  
**What a good tool should detect:** WebView debugging enabled in non-debug contexts, risky WebView debug exposure, or unsafe WebView settings.  
**Minimum benchmark match:** Report of insecure WebView debugging/settings.

### OST-AND-18 — ParcelableMemoryCorruption
**Repo label:** ParcelableMemoryCorruption  
**Benchmarkable:** Yes  
**Canonical family:** Memory Corruption  
**Expected detection mode:** Hybrid or dynamic  
**Description:** Control over parcelable object data and payload can trigger memory corruption in native Android library code.  
**What a good tool should detect:** Dangerous parcelable-to-native flows, unsafe native deserialization surfaces, or memory corruption risk indicators.  
**Minimum benchmark match:** Report of parcelable-driven memory corruption risk.

### OST-AND-19 — SerializableMemoryCorruption
**Repo label:** SerializableMemoryCorruption  
**Benchmarkable:** Yes  
**Canonical family:** Memory Corruption  
**Expected detection mode:** Hybrid or dynamic  
**Description:** Control over serializable object data and payload can trigger memory corruption in native library handling.  
**What a good tool should detect:** Serializable-to-native unsafe flows or native deserialization corruption risk.  
**Minimum benchmark match:** Report of serializable-driven memory corruption risk.

### OST-AND-20 — Path Traversal Vulnerability
**Repo label:** Path Traversal Vulnerability  
**Benchmarkable:** Yes  
**Canonical family:** Path Traversal  
**Expected detection mode:** Static and optionally dynamic  
**Description:** Using `getLastPathSegment` on a crafted URI path can allow encoded traversal input such as `%2F..%2F..` to resolve to sensitive file paths.  
**What a good tool should detect:** Unsafe URI path extraction, traversal primitives, or file access based on insufficiently normalized path segments.  
**Minimum benchmark match:** Report of path traversal or unsafe URI-derived file path usage.

### OST-AND-21 — Implicit PendingIntent Vulnerability
**Repo label:** Implicit PendingIntent Vulnerability  
**Benchmarkable:** Yes  
**Canonical family:** PendingIntent Misuse  
**Expected detection mode:** Static  
**Description:** An implicit intent is wrapped in a `PendingIntent`, allowing hijack, denial of service, private data access, or privilege escalation.  
**What a good tool should detect:** Implicit `PendingIntent` creation, mutable dangerous `PendingIntent`s, or insufficiently constrained delegated intents.  
**Minimum benchmark match:** Report of insecure `PendingIntent` usage.

### OST-AND-22 — PackageContextLoadCall
**Repo label:** PackageContextLoadCall  
**Benchmarkable:** Yes  
**Canonical family:** Insecure Dynamic Loading / Code Loading  
**Expected detection mode:** Static or hybrid  
**Description:** A package is loaded from the package manager using a hardcoded prefix or package name in a way that can be hijacked for arbitrary code execution or access in the vulnerable app context.  
**What a good tool should detect:** Unsafe package-context loading, trust in package-name prefixes, or third-party package loading without strong validation.  
**Minimum benchmark match:** Report of insecure package loading or package-context hijack risk.

## Ostorlab Android-native denominator
```text
Total Ostorlab Android-native benchmarkable vulnerabilities: 22
```

---

# 9. Ostorlab Flutter benchmark set

This module should be benchmarked separately from the native Android set.

### OST-FLT-01 — ClearTextTraffic
**Repo label:** ClearTextTraffic  
**Benchmarkable:** Yes  
**Canonical family:** Insecure Transport  
**Expected detection mode:** Static and optionally dynamic  
**Description:** Flutter module traffic is not protected by TLS.  
**Minimum benchmark match:** Report of cleartext or insecure transport.

### OST-FLT-02 — CommandExec
**Repo label:** CommandExec  
**Benchmarkable:** Yes  
**Canonical family:** Command Injection / Unsafe Command Execution  
**Expected detection mode:** Static or hybrid  
**Description:** Untrusted input may reach shell or command execution.  
**Minimum benchmark match:** Report of unsafe command execution.

### OST-FLT-03 — ECBModeCipher
**Repo label:** ECBModeCipher  
**Benchmarkable:** Yes  
**Canonical family:** Weak Cryptography  
**Expected detection mode:** Static  
**Description:** Insecure ECB mode is used.  
**Minimum benchmark match:** Report of ECB usage.

### OST-FLT-04 — HashCall
**Repo label:** HashCall  
**Benchmarkable:** Yes  
**Canonical family:** Weak Cryptography  
**Expected detection mode:** Static  
**Description:** Hashing-related insecure behavior is declared in the repo.  
**Minimum benchmark match:** Report of weak hashing or unsafe digest use.

### OST-FLT-05 — InsecureCommands
**Repo label:** InsecureCommands  
**Benchmarkable:** Yes  
**Canonical family:** Insecure Local Storage / File Permissions  
**Expected detection mode:** Static  
**Description:** As with the native module, the visible README text ties this to insecure storage/protection rather than command execution.  
**Minimum benchmark match:** Report of insecure storage or weak storage protection.

### OST-FLT-06 — InsecureSharedPreferences
**Repo label:** InsecureSharedPreferences  
**Benchmarkable:** Yes  
**Canonical family:** Insecure Local Storage / File Permissions  
**Expected detection mode:** Static  
**Description:** Shared preferences are created with insecure permissions, exposing stored data to arbitrary read or write by a malicious app.  
**Minimum benchmark match:** Report of insecure SharedPreferences permissions.

### OST-FLT-07 — IntentCall
**Repo label:** IntentCall  
**Benchmarkable:** Yes  
**Canonical family:** IPC / Intent Abuse  
**Expected detection mode:** Static  
**Description:** Data is broadcast using an intent created from a hardcoded string.  
**Minimum benchmark match:** Report of insecure broadcast/intent usage.

### OST-FLT-08 — StaticIV
**Repo label:** StaticIV  
**Benchmarkable:** Yes  
**Canonical family:** Weak Cryptography  
**Expected detection mode:** Static  
**Description:** A non-random initialization vector is used.  
**Minimum benchmark match:** Report of static or predictable IV usage.

### OST-FLT-09 — TLSTraffic
**Repo label:** TLSTraffic  
**Benchmarkable:** Yes  
**Canonical family:** Weak TLS / SSL Configuration  
**Expected detection mode:** Static, dynamic, or configuration-aware  
**Description:** The endpoint or connection uses weak TLS/SSL characteristics.  
**Minimum benchmark match:** Report of weak TLS or SSL configuration.

### OST-FLT-10 — Path Traversal Vulnerability
**Repo label:** Path Traversal Vulnerability  
**Benchmarkable:** Yes  
**Canonical family:** Path Traversal  
**Expected detection mode:** Static and optionally dynamic  
**Description:** Unsafe handling of URI path segments can produce traversal into unintended file paths.  
**Minimum benchmark match:** Report of path traversal or unsafe URI-derived file access.

### OST-FLT-11 — InsecureRandom
**Repo label:** InsecureRandom  
**Benchmarkable:** Yes  
**Canonical family:** Weak Randomness  
**Expected detection mode:** Static  
**Description:** Randomness is seeded with a constant value and becomes predictable.  
**Minimum benchmark match:** Report of predictable randomness.

### OST-FLT-12 — SQLiteDatabaseCall
**Repo label:** SQLiteDatabaseCall  
**Benchmarkable:** Yes  
**Canonical family:** SQL Injection  
**Expected detection mode:** Static and optionally dynamic  
**Description:** SQLite query construction is unsafe and can lead to injection.  
**Minimum benchmark match:** Report of SQL injection or injectable SQLite query construction.

### OST-FLT-13 — WebviewInsecureSettings
**Repo label:** WebviewInsecureSettings  
**Benchmarkable:** Yes  
**Canonical family:** Insecure WebView  
**Expected detection mode:** Static  
**Description:** WebView debugging exposure creates a reachable debugging surface from other apps on the device.  
**Minimum benchmark match:** Report of insecure WebView debugging/settings.

## Ostorlab Flutter denominator
```text
Total Ostorlab Flutter benchmarkable vulnerabilities: 13
```

---

# 10. Matching guidance

## 10.1 Preferred benchmark fields
When you later convert this document into CSV or JSON, each row should contain at least:

- `repo`
- `module`
- `instance_id`
- `repo_label`
- `benchmarkable`
- `canonical_family`
- `expected_detection_mode`
- `minimum_match`
- `notes`

## 10.2 Example normalization map

| Tool output | Normalized family |
|---|---|
| hardcoded api key | Hardcoded Secrets |
| weak crypto | Weak Cryptography |
| aes ecb | Weak Cryptography |
| static iv | Weak Cryptography |
| exported broadcast abuse | IPC / Intent Abuse |
| insecure deep link | Deep Link Abuse |
| insecure webview debug | Insecure WebView |
| command injection | Command Injection / Unsafe Command Execution |
| dexclassloader unsafe path | Insecure Dynamic Loading / Code Loading |
| package context hijack | Insecure Dynamic Loading / Code Loading |
| predictable seed | Weak Randomness |
| path traversal | Path Traversal |

## 10.3 Deduplication guidance
You should track both:

- instance-level score
- family-level score

This matters because:

- `AESCipher` and `ECBModeCipher` are closely related but still distinct repo entries.
- `DexClassLoaderCall`, `PathClassLoaderCall`, and `PackageContextLoadCall` belong to the same family but represent different concrete mechanisms.
- `MemoryCorruption`, `ParcelableMemoryCorruption`, and `SerializableMemoryCorruption` are related but should not be collapsed for instance-level benchmarking.

---

# 11. Recommended reporting template for evaluation

Use this table per run:

| instance_id | expected_label | found_by_tool | tool_label | instance_match | family_match | comments |
|---|---|---:|---|---:|---:|---|
| ALLSAFE-01 | Insecure Logging | yes | sensitive data in logs | yes | yes | good match |
| ALLSAFE-04 | Arbitrary Code Execution | yes | insecure dynamic loading | no | yes | family correct, primitive not explicit |
| OST-AND-15 | StaticIV | no |  | no | no | false negative |

---

# 12. Benchmark summary

## By dataset

| Dataset | Included benchmarkable entries |
|---|---:|
| Allsafe (filtered) | 7 |
| Ostorlab Android-native | 22 |
| Ostorlab Flutter | 13 |

## Total included entries
```text
Total benchmarkable entries across both repositories: 42
```

---

# 13. Final practical guidance

### Use Allsafe carefully
Allsafe is useful, but it is a mixed training app. For objective benchmarking, only the 7 filtered vulnerabilities should count in the denominator.

### Use Ostorlab as the primary benchmark corpus
Ostorlab is better suited for systematic measurement because the repository is explicitly framed as a vulnerable application for testing static and dynamic analysis.

### Keep framework scores separate
Do not merge:

- Android-native coverage
- Flutter coverage

A tool that performs well on Java/Kotlin bytecode but poorly on Flutter artifacts should not receive a single blended score without explanation.

### Be honest about capability boundaries
If your tool is primarily static, the following should be core expectations:

- crypto
- storage
- WebView
- SQL injection
- intent misuse
- deep links
- dynamic loading

But:
- memory corruption
- some runtime-only exploitability questions
- network handshake weakness validation

may need hybrid or dynamic support.

---

# 14. Suggested next conversion formats

This markdown is designed so it can be converted directly into:

- CSV benchmark sheet
- JSON ground-truth file
- XLSX scoring workbook
- automated scoring harness input
