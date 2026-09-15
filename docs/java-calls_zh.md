# JSON Java 方法调用

`ctl java call` 接受方法调用描述，不解析或编译 Java 源码。执行器复用内置
`InMemoryDexClassLoader`，其父加载器是 App 显式注册的 ClassLoader；指定
`--dex-id` 时使用该上传 DEX 的 InMemoryDexClassLoader。无需 `hook init`
或匹配 ART 私有 ABI。完整参数说明也可以在设备离线执行 `ij2art help java` 查看。

*英文版：[java-calls.md](java-calls.md)*

## 开启 WebView 调试

```sh
ij2art ctl --pkg com.example.app --json java call --thread main --request \
  '{"calls":[{"class":"android.webkit.WebView","method":"setWebContentsDebuggingEnabled","args":[{"type":"boolean","value":true}]}]}'
# 用返回的 id 查询，直到 state 为 SUCCEEDED 或 FAILED。
ij2art ctl --pkg com.example.app --json java query 1
ij2art ctl --pkg com.example.app java del 1
```

此调用使用 Android 的 [WebView.setWebContentsDebuggingEnabled](https://developer.android.com/reference/android/webkit/WebView#setWebContentsDebuggingEnabled(boolean))
公开 API。需要 App runtime readiness 和已运行的主 Looper；不需要为这一调用上传 DEX。

readiness 无需 App 配合：App 线程未通过 SDK 递送就绪信号时，首个需要 env 的命令会在
控制 worker 线程上自动自举——经公开 JNI Invocation API 取 JavaVM 并 attach，再经
`ActivityThread.currentApplication().getClassLoader()` 取 App 加载器（受阻时回退系统
ClassLoader）。Application 尚未创建时自举失败保持 NOT_READY，下次命令自动重试。
`--thread main` 使用 [Handler.post](https://developer.android.com/reference/android/os/Handler#post(java.lang.Runnable))，
将整个调用序列放到主 Looper 执行。`--thread new` 则为请求创建一个新的 daemon 线程，不创建 Looper。

`--request` 和 `--file /path/calls.json` 二选一。文件路径属于运行 CLI 的设备。
`--json` 是 CLI 输出开关，与输入格式无关：输入始终是 JSON。

## 方法、参数和返回值

```json
{
  "calls": [
    {"class": "java.util.Locale", "method": "getDefault", "save": "locale"},
    {"class": "java.util.Locale", "method": "getLanguage", "receiver": {"ref": "locale"}}
  ]
}
```

每个调用需要 `class` 和 `method`；无参数时可省略 `args`。每个参数必须写为
`{"type":"声明类型","value":值}`，使用精确类型选择重载。支持基本类型、完整包装类名、
字符串、引用类型的 `null`、数组以及 `{ "ref": "此前的 save 名称" }`。
整数必须在类型范围内，`long` 也支持十进制字符串以避免 JSON 客户端损失精度。
`char` 是一个 UTF-16 单元，浮点输入必须有限；数组写作 `int[]`、`java.lang.String[]` 等。
引用参数必须符合声明类型；不通过 JSON 对象自动构造 Java 对象。

省略 `receiver` 表示静态调用。实例调用必须引用同一请求中先前 `save` 的返回值。
`save` 不会创建跨任务对象句柄，任务结束即释放对象引用。默认使用 parent-first 类加载委托，
因此自定义 DEX 中与父加载器同名的类不会覆盖父类。执行时临时设置线程 context ClassLoader，
在返回或异常时恢复。类初始化也发生在所选线程。

不接受构造器、`<clinit>`、字段读写、表达式、分支或循环；拒绝未知/重复 JSON 字段、
重复 `save` 和前向引用。使用 Android 严格模式的 `JsonReader` 解析标准 JSON，没有自行实现
Java/JSON 结构解析器；另做字符检查，拒绝 [AOSP JsonReader](https://android.googlesource.com/platform/frameworks/base/+/refs/heads/main/core/java/android/util/JsonReader.java)
严格模式仍会放行的未知转义、原始控制字符和大小写混写的布尔/null 字面量。
反射会尝试访问非 public 方法，但不会绕过 Android hidden API 限制。
调用格式不是权限沙箱，被调用方法可以产生正常的 App 副作用。

## 异步任务与生命周期

`call` 不等待 Java 执行完成。返回的 `id` 只在本进程当前执行器内有效，状态为
`QUEUED`、`RUNNING`、`SUCCEEDED` 或 `FAILED`。`java list` 列出所有保留的任务。
`--json` 信封中的 `ok:true` 和退出码 0 表示提交/查询成功；**Java 执行是否成功要检查
`data.state`**。超时或断开连接不会取消调用，也没有自动重试；先查询已有任务，避免重复副作用。

成功的 `query` 示例：

```json
{"ok":true,"data":{"id":1,"dex_id":null,"thread":"main","state":"SUCCEEDED","results":[{"index":0,"type":"void","value":null}],"results_truncated":false}}
```

异常使序列停止，`error` 给出从 0 开始的调用 `index`、异常 `type/message`，保留此前的
`results`，不回滚已发生的副作用。返回值为标量时提供 `type/value`，`long` 返回十进制字符串，
非有限浮点返回字符串。对象和数组只提供 `class/opaque`，不自动调用它们的 `toString()` 或读取字段。
返回的字符串最多 512 个 UTF-16 单元，结果截断会标记 `truncated`、`omitted` 和
`results_truncated`。`dex_id` 是无符号十进制字符串，默认加载器则为 `null`。

每进程最多保留 16 个任务；`java del ID` 释放已完成记录，不会取消或中断排队/执行中的方法。
请求最多 3992 个 UTF-8 字节、32 次调用、16 层 JSON 嵌套、8 维数组类型。
主线程上的长方法仍会阻塞 UI，新线程方法也可能长时间运行；控制 worker 始终只管理任务，
不等待目标方法。

队列中和运行中的任务持有选中加载器的 Java 强引用，`dex del` 会检查任务并返回 BUSY；
`hook_refs` 仍然只统计 Hook 回调，不含 Java 任务。完成任务只保存结果快照，不再阻止 DEX 删除。
App 自己保留的对象或任务内部新建的线程仍遵循 JVM 的正常 GC 生命周期，DEX 删除不强制卸载它们。
`shutdown` 首先关闭新任务准入，待已有任务完成后才能关闭控制 worker；BUSY 后可继续 query/list，
待任务结束再重试 shutdown。

## 验证

```sh
SDK=/path/to/android-sdk zsh build.sh
SDK=/path/to/android-sdk zsh test/build-java-calls.sh
python3 test/run-java-calls.py --adb /path/to/adb --serial SERIAL
python3 test/run-java-calls.py --adb /path/to/adb --serial SERIAL --no-main
# 测试 APK 构建和签名后，增加真实 WebView 调试端点校验：
python3 test/run-java-calls.py --adb /path/to/adb --serial SERIAL --apk
```

测试覆盖类型范围和重载、UTF-8/NUL/emoji、基本类型和数组、对象引用、私有方法、异常中止、
返回值截断、任务槽回收、主线程排队、新线程并行、类初始化所在的线程、加载器隔离和恢复、
DEX 删除保护及 shutdown 排空。独立 `app_process` 使用 CheckJNI，APK 模式验证真实 App UID
下 WebView 调试 socket 的出现与关闭。测试均不安装 ART Hook。

本次验证：Android 14 P1_EVB、Android 16 PLC110 的 CheckJNI 调用测试均通过；
Android 16 普通 App 中的 WebView 调试 socket 开关通过；缺少主 Looper 时的拒绝路径通过。
49 项 CLI 测试、SDK Bridge 测试及 Android 14 现有 Hook 热更新回归通过。
