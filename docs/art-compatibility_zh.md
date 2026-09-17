# ART 动态兼容

当前采用类似 LSPlant 的兼容方式：按版本约束、符号能力和运行时探测选择实现。
`libart` 的 GNU build-id 不再是 Hook 白名单；它只用于诊断，以及核对磁盘 ELF
与进程中加载的库是否为同一文件。CLI/carrier/payload 之间的产物身份校验仍然保留。

## 初始化过程

1. 从已加载的 `libart.so` 定位实际文件，解析 `.dynsym`、`.symtab` 和
   `.gnu_debugdata`。按完整 ABI 签名尝试候选符号；允许 LLVM 的 `.__uniq.` / `.llvm.`
   后缀变化，同名候选若对应不同地址则拒绝。函数地址和入口字节均取自当前 ELF。
2. 根据 zombie 记录、入口写入函数和锁能力选择回收协议。zombie 记录与额外的
   `jit_mutator_lock_` 分开判断：Android 15 仅用 `jit_lock_` 保护这些集合。
   所有必需入口齐全后才继续。
3. 用有界 ARM64 数据流解析检查 Runtime、JIT、线程池、ClassLinker、代码缓存和
   栈遍历器的字段访问。不调用伪造 ART 对象上的函数，不为探测修改目标方法。
   JIT 字段通过代码缓存/选项的访问关系区分，ClassLinker 优先从
   `IsImagePointerSize` 探测；不假设大型函数只读取一个 Runtime 指针字段。
   解析器识别 GPR 到浮点寄存器的移动、局部指针栈暂存和库内标准 PLT 尾调用。
   栈覆盖、分支来源冲突和向被调函数暴露栈地址会使暂存来源失效。
4. 通过 `Throwable` 的多个真实构造方法探测 ArtMethod 间距与 accessFlags，校验
   quick entry、声明类和 ART 自身访问这些字段的位置。兼容 opaque JNI method ID。
5. 检查真实 Runtime 对象关系，包含 Runtime/Jit 对同一代码缓存的引用。地址范围
   检查识别 Android 的带标签堆指针。再核对内存入口字节，最后安装入口保护。

首次成功后缓存不可变的解析结果，并释放完整 ELF 和调试符号数据。SmallPatternMatcher
的常驻入口按已知函数族动态收集，不再保存每个构建的 RVA 数组。

代码入口：`payload/art_discovery.h`、`payload/art_profile.cpp`、`payload/art_symbols.inc`。
`payload/art_profiles/` 仅保留历史审计记录，生产代码不再包含其中的表。

## 覆盖边界

这次迁移的是兼容策略，保留了项目原有的严格安装检查、JIT/OSR/CHA 回收、原方法调用、
并发更新和入口保护协议。它不意味着已经获得 LSPlant 全部 Android 版本的覆盖。

- 当前版本约束为 API 34–37 / arm64，使用 Android 14–17 审计形成的两类回收协议
  和四组内部布局规则。API 范围内的设备仍必须通过全部符号与布局检查。
- Runtime 的线程列表、JIT、ClassLinker、调试状态、回调，ArtMethod 布局、线程池字段和
  StackVisitor 存储范围由探测确定。Instrumentation、CHA 和部分代码缓存字段仍使用
  有指令访问证据的布局规则。内部 STL 布局、访问标志和锁语义也是协议的一部分；这些
  改变时仍需要扩展规则，不能仅凭版本号或“符号都存在”认定兼容。
- 验证目标包括一加 PLC110 / Android 16、CIX P1_EVB / Android 14 和 AOSP Android 15
  ARM64 模拟器，均为 4 KiB 页。初版动态后端曾在 Pixel 7 / Android 17 验证；下述
  探测修复后尚未重跑该设备。其他 Android 15 ROM 和 16 KiB 设备尚未验证。
- `ENTRY_ONLY` 和逻辑删除语义保持不变，已经内联的调用点仍不在拦截范围内。

符号裁剪、歧义、指令形式未知或布局不匹配会返回 `replacement:false` 和
`unsupported_reason`，保留 DEX/方法查询能力。成功结果带有
`compatibility:"symbols-probes-v1"` 和所选后端名称。已加载 ELF 与磁盘文件身份不符也会拒绝。

## 验证

无需改系统库即可验证 build-id 与地址不再绑定：

```sh
adb pull /apex/com.android.art/lib64/libart.so out/libart-device.so
python3 test/run-art-discovery.py out/libart-device.so --api 37
```

主机测试运行与生产相同的 ELF 解析器、指令分析和 ABI 选择逻辑，覆盖：

- 真实设备 ELF；重复的同地址符号可接受，歧义 LTO 候选与必需符号缺失会拒绝。
- 仅更换 build-id 后仍可发现；整个 ELF 的符号、段、重定位和代码地址平移 16 KiB
  后仍正确发现所有入口。这是模拟新构建的回归，不是另一台设备或 16 KiB 页大小验证。
- 删除关键字段访问、截断 ELF 或破坏节表边界时拒绝。
- 有符号加载、寄存器重命名、未知写入和控制流来源冲突的探测回归。
- GPR/浮点寄存器分离；跨调用栈暂存及成对读写；部分覆盖、未知地址写入、
  暴露给被调函数的栈地址和分支冲突均不能保留指针来源。

设备矩阵和生产 zygote 注入验证使用 [test/README.md](../test/README.md) 中的脚本。
Android 14/16 重测证据保存在 `out/art-compat-recheck-20260917/`，初版迁移使用
`out/art-dynamic/`；初次 Android 17 适配记录见
[android17_zh.md](android17_zh.md)。

参考策略来自 [LSPlant](https://github.com/LSPosed/LSPlant)：符号解析回调、按版本分支和
ArtMethod 运行时布局探测。这里的解析器、ABI 探测和后端集成由本项目实现。

## Android 15 模拟器（2026-09-17）

已创建可复用 AVD `ij2art_api35_root`，使用
`system-images;android-35;default;arm64-v8a` 修订 2 和 Emulator 36.6.11。
无需安装 Android Studio；AOSP 镜像可直接 `adb root`，参见
[官方说明](https://developer.android.com/studio/run/managing-avds?hl=en)。
本次设备序列号为 `emulator-5554`，API 35、4096 字节页、SELinux Enforcing。

- Fingerprint：`Android/sdk_phone64_arm64/emu64a:15/AE3A.240806.019/12368160:userdebug/test-keys`。
- ART build-id：`05bfa63ad29b97d7dde4e764ce193f37`。
- 后端：`arm64-zombie-code-jit-lock-dynamic`。

原产物因没有匹配的私有布局规则而正确拒绝该 ART。Android 15 已维护 zombie 和
processed-zombie 代码集合，但仅用 `jit_lock_`，Instrumentation 也仍直接内嵌于
Runtime。现将这些能力拆开判断，释放代码前清除两组记录，仅在存在额外锁时获取它。
协议依据为 AOSP 的 [JIT 缓存声明](https://android.googlesource.com/platform/art/+/refs/heads/android15-release/runtime/jit/jit_code_cache.h)
和 [回收实现](https://android.googlesource.com/platform/art/+/refs/heads/android15-release/runtime/jit/jit_code_cache.cc)。

新增布局规则仍须实际 ELF 指令佐证。ZygoteMap 查询被内联时，需同时核对两个 ArrayRef
字段和独立方法中的访问。测试夹具补充该 ART 的 STL 内部函数符号，用真实 ART 分配器
写入 CHA 和 processed-zombie 记录。负向测试验证缺失集合删除操作、协议符号歧义会
拒绝；删除 Android 15 zombie 特征符号后也不能悄悄降级到无 zombie 的后端。

| 布局证据 | 偏移 / 大小 |
| --- | --- |
| Runtime 线程列表 / linker / Jit / cache | `0x248 / 0x258 / 0x280 / 0x288` |
| 内嵌 Instrumentation / callbacks / debug | `0x328 / 0x688 / 0x554` |
| ClassLinker CHA / class status | `0x260 / 0x70` |
| 线程池 started / waiting / threads | `0x78 / 0x80 / 0x88` |
| Saved entries / zygote map / collecting | `0x328 / 0x3d0 / 0x408` |
| Zombie / processed-zombie 集合 | `0x370 / 0x3a0` |
| StackVisitor / GC critical section | `0x1f0 / 0x18` 字节 |

| Android 15 验证 | 结果 |
| --- | --- |
| 主机发现与负向回归 | 8 组通过 |
| ART / Java 设备矩阵 | 26/26 |
| Native / ART inline Hook | 2/2 |
| 生产注入 | 1/1，包含两次冷启动 |
| 设备用例合计 | 29/29 |
| 入口保护 / 常驻模式入口 | 8 / 412 |
| 最终状态 | 注入已清除，测试 APK 已卸载，zygote/system_server 和 boot-id 不变 |

矩阵覆盖 JIT/OSR 回收、CHA 和 processed-zombie 清理、callOriginal、构造方法、
synchronized 与 JNI 方法、回调更新以及真实 APK AOT。生产注入还验证了 targets
关闭/恢复和 clear。SELinux 全程保持 Enforcing；root 模拟器保留运行，已解锁并保持亮屏。

同一批重建产物也在一加 Android 16 和局域网 Android 14 上复测，两台最终均为
29/29，主机发现测试各 8 组通过。局域网首次运行在 `constructors-aot` 中出现
`no ready control ring matching the current CLI layout found`；独立诊断复测和
续跑矩阵均通过该项。原因尚未定位，CLI 未加入重试或行为修改，首次失败日志与成功
复测记录一并保留。三台结束时均已清除注入并卸载测试 APK，本轮矩阵期间
zygote/system_server PID、boot-id 和 SELinux 状态均不变。

证据和实际启动命令保存在 `out/android15-validation-20260917/`。后续启动该 AVD，
等待 `sys.boot_completed=1`，执行 `adb -s emulator-5554 root` 并解锁，即可使用此
序列号运行测试。该 AVD 独立创建，原有虚拟机未复用。
该目录的 `verification.json` 关联了源码和产物哈希、逐项结果、失败证据及最终状态。
Rust 单测 55/55，两组 Java SDK 和四组 C++ 边界/并发测试均通过。

## Android 14/16 重测（2026-09-17）

两台设备最初都因 `ART Runtime getter/field probe unavailable or ambiguous` 拒绝
replacement。本次修复了 Jit 与 JitOptions 字段区分、ClassLinker 专用探测、被抽成独立
函数的清理逻辑和 zombie 集合访问，以及指针栈暂存、浮点移动和 PLT 转发的来源跟踪。
未恢复 build-id 白名单，也未加入按构建硬编码的函数地址。

| 验证 | 一加 PLC110 | 局域网 CIX P1_EVB |
| --- | --- | --- |
| 设备 / Android | `3B65A80052F00000` / 16，API 36 | `192.168.9.127:10000` / 14，API 34 |
| ART build-id | `7bf2886127ae5230f6030d2e8fa42561` | `1baa085e52462906909d6dfe1b6332e2` |
| 动态后端 | zombie-code | locked-code |
| 主机发现与负向回归 | 8 组通过 | 8 组通过 |
| ART / Java 真机矩阵 | 26/26 | 26/26 |
| Native / ART inline Hook | 2/2 | 2/2 |
| 生产注入 | 1/1，按目标实际父进程选择 | 1/1 |
| 真机用例合计 | 29/29 | 29/29 |
| 入口保护 / 常驻模式入口 | 9 / 412 | 8 / 412 |
| 页大小 / SELinux | 4096 / Enforcing | 4096 / Disabled（原状态） |

真机矩阵覆盖 JIT、无 JIT、可调试/opaque JNI ID 和真实 APK AOT，包含构造方法、
synchronized、native 绑定、回调更新、callOriginal 和逻辑删除。生产注入验证关闭
自加载后的两次冷启动、上传库加载/卸载、targets 关闭/恢复和 clear；一加还覆盖了
现存 USAP 补注。Rust 单测 55/55，两组 Java SDK 和四组 C++ 边界/并发测试均通过。

一加原有另一构建的旧版 `ebpf4art` carrier，身份校验正确拒绝操作；经用户明确授权
重启后清除，并完成解锁和保持亮屏设置。该 ROM 有两个 zygote，测试 APK 实际来自
主实例，而 CLI 对未运行目标的启发式选择落在副实例。回归脚本现先预启动测试 APK
确定实际父进程，再固定该 PID 验证注入后的两次冷启动。手动使用时应先启动目标再
`inject --targets`，或明确指定已确认的 `--pid`；未运行目标的自动选择仍是一个限制，
与 ART 动态探测无关。

局域网设备的 WebView 断言也已修正：`userdebug` ROM 上，Chromium 会在收到关闭调用
后继续保留 devtools。测试等待 socket 状态稳定后按平台策略检查；依据是 Chromium 119
的 [SharedStatics](https://chromium.googlesource.com/chromium/src/+/119.0.6045.141/android_webview/glue/java/src/com/android/webview/chromium/SharedStatics.java)
和 [BuildInfo](https://chromium.googlesource.com/chromium/src/+/119.0.6045.141/base/android/java/src/org/chromium/base/BuildInfo.java)。

结束时两台均已清除注入并卸载测试 APK，SELinux 状态保持不变。一加在授权重启后，
注入测试期间 zygote/system_server PID 不变；局域网设备全程 PID 和 boot-id 不变。
汇总 `out/art-compat-recheck-20260917/verification.json` 关联了产物哈希、每台设备的
`matrix-results.json`、发现结果、失败证据和最终状态。

## 较早的 Android 17 验证（2026-09-17）

Pixel 7 / Android 17 / API 37，ART `4259bc018250195dc006f2b6cf330eb1`：

| 验证 | 结果 |
| --- | --- |
| 主机发现与负向回归 | 6 组通过，包括未知 build-id 和全地址重定位 |
| Java SDK / C++ 边界与并发测试 | 全部通过 |
| ART / Java 真机矩阵 | 26/26，通过 JIT、无 JIT、可调试、真实 APK AOT |
| 入口保护 / 常驻模式入口 | 9 个保护 Hook；动态识别 412 个常驻入口 |
| 生产 zygote 链路 | 两次冷启动，Hook/callOriginal/逻辑删除、targets 切换及 clear 通过 |
| 测试后状态 | 注入已清除；zygote/system_server PID 不变；SELinux Enforcing |

最终产物、哈希和逐项证据：`out/art-dynamic/verification.json`、
`matrix-results.json`、`discovery.log`、`injection.log`。
