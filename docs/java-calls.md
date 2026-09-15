# JSON Java method calls

`ctl java call` accepts a method-call description; it never parses or compiles Java source.
The executor reuses the built-in `InMemoryDexClassLoader`, whose parent is the ClassLoader the
app explicitly registered; when `--dex-id` is given, it uses the InMemoryDexClassLoader of
that uploaded DEX instead. Neither `hook init` nor matching ART's private ABI is required.
The complete argument reference is also available offline on the device through
`ij2art help java`.

*Chinese version: [java-calls_zh.md](java-calls_zh.md)*

## Enabling WebView debugging

```sh
ij2art ctl --pkg com.example.app --json java call --thread main --request \
  '{"calls":[{"class":"android.webkit.WebView","method":"setWebContentsDebuggingEnabled","args":[{"type":"boolean","value":true}]}]}'
# Poll with the returned id until state is SUCCEEDED or FAILED.
ij2art ctl --pkg com.example.app --json java query 1
ij2art ctl --pkg com.example.app java del 1
```

This call uses Android's public
[WebView.setWebContentsDebuggingEnabled](https://developer.android.com/reference/android/webkit/WebView#setWebContentsDebuggingEnabled(boolean))
API. It needs app runtime readiness and a running main Looper; no DEX upload is needed for
this particular call.

Readiness requires no cooperation from the app: when app threads deliver no readiness signal
through the SDK, the first command that needs an env bootstraps automatically on the control
worker thread — it obtains the JavaVM through the public JNI Invocation API and attaches,
then gets the app loader through
`ActivityThread.currentApplication().getClassLoader()` (falling back to the system
ClassLoader when that is blocked). If the Application has not been created yet,
bootstrapping fails and stays NOT_READY, and the next command retries automatically.
`--thread main` uses
[Handler.post](https://developer.android.com/reference/android/os/Handler#post(java.lang.Runnable))
to run the whole call sequence on the main Looper. `--thread new` creates a new daemon
thread for the request and does not create a Looper.

`--request` and `--file /path/calls.json` are mutually exclusive. The file path belongs to
the device running the CLI. `--json` is a CLI output switch and is unrelated to the input
format: the input is always JSON.

## Methods, arguments, and return values

```json
{
  "calls": [
    {"class": "java.util.Locale", "method": "getDefault", "save": "locale"},
    {"class": "java.util.Locale", "method": "getLanguage", "receiver": {"ref": "locale"}}
  ]
}
```

Every call needs `class` and `method`; `args` may be omitted when there are no arguments.
Every argument must be written as `{"type": "declared type", "value": value}`, and the exact
type selects the overload. Primitive types, full wrapper class names, strings, `null` for
reference types, arrays, and `{ "ref": "an earlier save name" }` are supported. Integers must
be within the range of their type; `long` also accepts a decimal string so JSON clients cannot
lose precision. `char` is one UTF-16 unit and floating-point inputs must be finite; arrays are
written as `int[]`, `java.lang.String[]`, and so on. Reference arguments must conform to the
declared type; Java objects are never constructed automatically from JSON objects.

Omitting `receiver` means a static call. An instance call must reference a return value saved
earlier in the same request. `save` does not create a cross-task object handle — object
references are released when the task ends. Class loading delegation is parent-first by
default, so a class in a custom DEX with the same name as a parent-loader class does not
override the parent. During execution the thread context ClassLoader is set temporarily and
restored on return or exception. Class initialization also happens on the selected thread.

Constructors, `<clinit>`, field reads and writes, expressions, branches, and loops are not
accepted; unknown or duplicate JSON fields, duplicate `save` names, and forward references are
rejected. Standard JSON is parsed with Android strict-mode `JsonReader` — no custom Java/JSON
structure parser is implemented. Additional character checks reject unknown escapes, raw
control characters, and mixed-case boolean/`null` literals that
[AOSP JsonReader](https://android.googlesource.com/platform/frameworks/base/+/refs/heads/main/core/java/android/util/JsonReader.java)
strict mode would still let through. Reflection attempts to reach non-public methods, but it
does not bypass Android hidden API restrictions. The call format is not a permission sandbox:
called methods can produce ordinary app side effects.

## Asynchronous tasks and lifecycle

`call` does not wait for Java execution to finish. The returned `id` is valid only inside the
current executor of this process, with states `QUEUED`, `RUNNING`, `SUCCEEDED`, and `FAILED`.
`java list` lists every retained task. `ok:true` in the `--json` envelope and exit code 0 mean
the submit/query succeeded; **whether the Java execution succeeded must be read from
`data.state`**. A timeout or a dropped connection does not cancel the call and there is no
automatic retry; query existing tasks first to avoid duplicate side effects.

A successful `query` example:

```json
{"ok":true,"data":{"id":1,"dex_id":null,"thread":"main","state":"SUCCEEDED","results":[{"index":0,"type":"void","value":null}],"results_truncated":false}}
```

An exception stops the sequence; `error` gives the zero-based call `index` and the exception
`type`/`message`, keeps the preceding `results`, and does not roll back side effects that
already happened. Scalar return values provide `type`/`value`, `long` is returned as a decimal
string, and non-finite floating-point values are returned as strings. Objects and arrays only
provide `class`/`opaque` — their `toString()` is not called and their fields are not read
automatically. Returned strings are at most 512 UTF-16 units, and result truncation is
flagged with `truncated`, `omitted`, and `results_truncated`. `dex_id` is an unsigned decimal
string, or `null` for the default loader.

At most 16 tasks are retained per process; `java del ID` releases a completed record and does
not cancel or interrupt a queued or running method. A request is at most 3992 UTF-8 bytes,
32 calls, 16 levels of JSON nesting, and 8-dimensional array types. A long method on the main
thread still blocks the UI, and a method on a new thread can also run for a long time; the
control worker only ever manages tasks and never waits for the target method.

Queued and running tasks hold strong Java references to the selected loader, so `dex del`
checks the tasks and returns BUSY; `hook_refs` still counts only hook callbacks and does not
include Java tasks. A completed task keeps only a result snapshot and no longer blocks DEX
deletion. Objects the app itself retains, or threads created inside a task, still follow the
JVM's normal GC lifecycle, and deleting a DEX does not force them to unload. `shutdown` first
closes admission for new tasks and can only shut down the control worker after existing tasks
complete; after BUSY you can keep using query/list and retry shutdown once the tasks finish.

## Verification

```sh
SDK=/path/to/android-sdk zsh build.sh
SDK=/path/to/android-sdk zsh test/build-art-api.sh
SDK=/path/to/android-sdk zsh test/build-java-calls.sh
python3 test/run-java-calls.py --adb /path/to/adb --serial SERIAL
python3 test/run-java-calls.py --adb /path/to/adb --serial SERIAL --no-main
# After the test APK is built and signed, add real WebView debugging endpoint checks:
python3 test/run-java-calls.py --adb /path/to/adb --serial SERIAL --apk
```

The tests cover type ranges and overloads, UTF-8/NUL/emoji, primitives and arrays, object
references, private methods, exception abort, return-value truncation, task slot recycling,
main-thread queuing, new-thread parallelism, the thread on which class initialization runs,
loader isolation and restoration, DEX deletion protection, and shutdown drain. The standalone
`app_process` uses CheckJNI, and APK mode verifies that the WebView debugging socket appears
and disappears under a real app UID. None of the tests install an ART hook.

Verification results for this revision: the CheckJNI call tests passed on Android 14 P1_EVB
and Android 16 PLC110; the WebView debugging socket switch passed inside a normal Android 16
app; and the rejection path for a missing main Looper passed. The 49 CLI tests, the SDK Bridge
test, and the existing Android 14 hook hot-update regression all passed.
