# Test suites

Four complementary layers. The lower two run on the build host; the upper two need a
rooted Android device (regressions were validated on Android 14 / Android 16 /
Android 17 arm64). The exact Android 17 build and results are recorded in
[android17.md](../docs/android17.md).

| Layer | Entry | Device | Covers |
| --- | --- | --- | --- |
| Rust unit tests | `cargo test --manifest-path cli/Cargo.toml` | no | CLI argument/protocol/ring/monitor logic against mocks |
| Host C++ unit tests | `zsh test/build-art-api.sh` | no | `hook_record`, `dex_store`, `hook_gate`, `hook_versions` invariants |
| Isolated-process integration | `zsh test/build-android.sh` | yes | carrier/payload lifecycle, ptrace remote-call smoke |
| Device regressions | `zsh test/build-<feature>.sh` + `python3 test/run-<feature>.py` | rooted device | every Hook flavor, JSON Java calls, inline hooks, eBPF monitor, real-APK AOT |

Shared scaffolding lives in `test/lib.py` (Python regressions), `test/lib.sh` (build
recipes), `test/fixture_base.h` (C++ fixture harness) and `test/adb_root.py` (su
wrapping). Fixture processes boot through `test/java/org/ij2art/test/FixtureMain.java`;
its third argv entry (`ctor`/`sync`/`binding`/`update`) selects the fixture side and
doubles as the READY prefix the runner greps for.

## Host only

```sh
cargo test --manifest-path cli/Cargo.toml --offline --locked
SDK=/path/to/android-sdk zsh test/build-art-api.sh   # also runs the four host C++ tests
```

`build-art-api.sh` additionally compiles the SDK BoundaryTest against
`out/ij2art-hook-api.jar`, cross-builds `out/art-api-jni.so` and produces the DEX
artifacts every device regression consumes.

## Device regressions

Every `run-*.py` takes `--serial DEVICE [--adb PATH]`; the hook-family scripts also
take `--mode jit|no-jit|debuggable|aot` (four ART runtime shapes per feature).

| Script | Feature | Build first |
| --- | --- | --- |
| `run-art-api.py` | SDK/CLI API boundary on a fresh CheckJNI app_process | `build-art-api.sh` |
| `run-constructors.py` | `<init>` hooks | `build-art-api.sh` (+ `build-apk.sh --aot` for `--mode aot`) |
| `run-synchronized.py` | synchronized methods | same as constructors |
| `run-native-binding.py` | JNI register/unregister guard | same as constructors |
| `run-hook-update.py` | live callback replacement | same as constructors |
| `run-hook-replace.py` | strict-install admission (staticcopy-v1) | `build-art-api.sh` |
| `run-aot-demo.py` | real-APK hooks on OAT quick code | `build-art-api.sh` + `build-apk.sh --aot`, then sign `out/aot-apktest-aligned.apk` as `out/aot-apktest-aligned-signed.apk` |
| `run-java-calls.py` | JSON Java method calls (`--apk`, `--no-main` variants) | `./build.sh`, `build-art-api.sh`, `build-java-calls.sh` |
| `run-inline.py` | inline-hook engine (`--mode art` runs it under ART) | `./build.sh`, `build-inline.sh` |
| `run-static-jni.py` | one-shot JNI ABI / logical-disable fixtures (`--original` needs a specific libart build) | `build-jni-abi.sh` / `build-logical-disable.sh` / `build-static-original.sh` |
| `run-monitor.py` | eBPF monitor check + 50k-event wrap | `build-monitor.sh` |
| `run-injection.py` | production zygote carrier path, two APK cold launches, targets/clear, fd loading and ART replacement; requires an uninjected zygote | `build-art-api.sh`, `build-inline.sh`, `build-apk.sh --aot`, then sign the APK as for `run-aot-demo.py` |
| `build-android.sh` | `lifecycle-test` + `remote-smoke` binaries | `./build.sh` |

Each script prints a final `PASS:` line and creates a unique
`/data/local/tmp/ij2art-*` directory that is removed afterwards; failures dump the
fixture log tail and logcat. Nothing touches zygote or an existing app except through
the documented `inject` flow.

Run APK suites sequentially: they share `org.ij2art.aottest`. `run-injection.py`
uses the production injector with only that package selected and with self-loading
disabled. It verifies unchanged zygote/system_server PIDs and SELinux mode after
clear. An abnormal remote-call failure preserves matching artifacts for inspection
and never automatically retries or resumes the affected process.

## Dynamic ART discovery

Production no longer consumes per-build symbol/RVA manifests. See
[ART compatibility](../docs/art-compatibility.md) for version/protocol limits and
[中文版](../docs/art-compatibility_zh.md). After pulling the device ELF, run the
production discovery logic on the host, including unknown-ID, relocated-address,
missing/ambiguous-symbol and malformed-input regressions:

```sh
python3 test/run-art-discovery.py out/libart-device.so --api 37
```

Then rebuild `test/build-art-api.sh`, `test/build-logical-disable.sh` and
`test/build-apk.sh --aot` before running the ART device matrix. Native fixture
libraries also resolve their own ART symbols dynamically and link the existing
ShadowHook/xDL archive for compressed debug-symbol support.
