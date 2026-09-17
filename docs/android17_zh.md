# Android 17 适配与真机验证

*English: [android17.md](android17.md)*

> 本文记录初次按精确构建进行的适配。ART Hook 随后已迁移到[动态兼容](art-compatibility_zh.md)，下文的白名单与逐构建 RVA 选择不再用于生产；原始测量保留为审计依据。

2026-09-17 在本机连接、已 root 的 Pixel 7 上完成验证。ART 方法替换仅对下述
精确构建启用，不根据 Android 版本号直接选择适配配置。

| 项目 | 已验证值 |
| --- | --- |
| 设备 / ABI | Google Pixel 7（`panther`），arm64 |
| Android | 17，API 37，`CP41.260814.003.A2` |
| 系统指纹 | `google/panther_beta/panther:17/CP41.260814.003.A2/16182618:user/release-keys` |
| ART GNU build ID | `4259bc018250195dc006f2b6cf330eb1` |
| 内核 | `6.12.81-android16-6-g86553c53da31-ab15878525-4k` |
| 页大小 / SELinux | 4096 字节 / 全程 Enforcing |
| 构建工具 | NDK 28.1.13356709、build-tools 36.0.0、JDK 17 |

## 修改内容

- 新增 `android17-arm64-zombie-code`，包含精确的符号 RVA、指令序言、对象布局，
  以及 412 个常驻 SmallPatternMatcher 入口。未知 ART build ID 仍拒绝方法替换，
  不按 API 级别回退猜测。
- StackVisitor 存储扩展至 `0x208`，采用新的 WalkStack 模板签名。
  Android 14/16 配置保留原有布局。
- Android 17 增加 fast 编译层级，测试夹具的 OSR/baseline/optimized 参数调整为
  `0/2/3`。被内联的 STL/CHA 测试操作改用该构建中经审计的 ART 内部分配辅助函数。
- 远程调用返回哨兵改为规范、非对齐地址 `1`。旧地址带有高位标签，在该设备上被
  符号扩展，正常返回因而被误判为异常。仍严格匹配 PC，并保留上下文恢复和异常停止
  规则。参见内核的[标签指针说明](https://www.kernel.org/doc/html/latest/arch/arm64/tagged-pointers.html)。
- carrier 注入、子进程 payload 加载和上传库加载统一使用 `android_dlopen_ext` 的
  `ANDROID_DLEXT_USE_LIBRARY_FD`。原路径通过 `/proc/self/fd` 重新打开 memfd 时，
  zygote 遭到 SELinux `{ open }` 拒绝。直接传入已有描述符后可正常加载，仍接受
  SELinux 的 mmap/execute 权限检查，无需修改策略。参见
  [NDK 接口](https://android.googlesource.com/platform/bionic/+/refs/heads/main/libc/include/android/dlext.h)。
  注入失败时增加远端链接器的 `dlerror` 诊断。
- carrier 和独立测试程序静态链接 C++ 运行库，移除未部署的 `libc++_shared.so`
  依赖。修正测试中的 SDK 符号名和 APK Java 调用的日志读取。

## ART 审计

以设备拉取的 `/apex/com.android.art/lib64/libart.so` 及其 `.gnu_debugdata`
为依据。符号审计在 18,346 个 ELF 符号中核对了 52 个非空配置项。对象布局和调用
约定另经反汇编检查；仅找到符号不能证明兼容。

| 对象 | 已审计偏移 / 大小 |
| --- | --- |
| Runtime | threads `0x240`、linker `0x250`、JIT `0x278`、cache `0x280`、instrumentation 指针 `0x328`、debuggable `0x3d4`、callbacks `0x508` |
| ClassLinker / Class | CHA `0x248`、class status `0x68` |
| JIT 线程池 | started `0x78`、waiting `0x80`、threads `0x88` |
| JIT 代码缓存 | saved entries `0x328`、zombie code `0x370`、zygote map `0x3b8`、collecting `0x410`、processed zombies `0x428` |
| StackVisitor / GC critical section | `0x208` / 24 字节 |
| ArtMethod | 32 字节；flags `4`、data `16`、quick entry `24` |

安装的九个入口保护 Hook 覆盖代码选择器、入口写入、native 绑定和注销。
该构建的 `InitializeMethodsCode` 和外层 `UpdateMethodsCode` 没有独立符号，
已检查其内联路径与受保护写入函数的关系。zombie-code 回收协议核对了
`RemoveMethodLocked`、saved entry 发布和代码收集路径。运行时回归覆盖私有
JIT/OSR 回收、CHA 依赖、代码 GC、活跃栈帧拒绝、类初始化和入口写入。

## 验证结果

| 验证项 | 结果 |
| --- | --- |
| Rust 主机测试 | 55 项通过，含带标签 PC 的返回回归 |
| 主机 C++ / Java SDK 边界测试 | 全部通过 |
| carrier/payload 生命周期 | 20 次加载/枚举/卸载；READY/PING/CALL/MODS/SHUTDOWN、工作线程退出通过 |
| 隔离 ptrace 测试 | 正常调用、无效文件名配合 fd 加载、上下文恢复、超时 SIGSTOP 通过；测试子进程已回收 |
| ART / Java 矩阵 | 26 组脚本配置通过 |
| 构造函数、同步方法、native 绑定、回调更新 | JIT、无 JIT、debuggable、真实 APK AOT 四种模式通过 |
| 安装条件 / callOriginal | JIT、无 JIT、debuggable 通过；AOT demo 的 verify 和 speed 编译通过 |
| Java 调用 / JNI | app_process、真实 APK/WebView、无主线程、静态 JNI、逻辑删除通过 |
| Native inline Hook | Native 与 ART 进程通过：19 个 Hook、并发调用、原函数调用、删除、库上传/卸载、JSON/batch/overview |
| eBPF | 三轮自检；50,000 对调用、200,000 条事件、五轮 ring 环绕，无重复、无丢失 |
| 生产 zygote 路径 | 注入/重复注入、两次关闭自加载后的冷启动、延迟 JNI 就绪、上传库加载/卸载、Hook/callOriginal/删除、targets 关闭/恢复及 clear 通过 |

生产路径测试仅选择 `org.ij2art.aottest`。zygote 和 system_server 的 PID 保持
不变；结束后 zygote 为未注入状态，测试 App 已停止。USAP 池为空，因此未覆盖
已有 USAP 的修复。本设备使用 4 KiB 页，本轮不代表完成 16 KiB 硬件验证。
未重新运行 Android 14/16 真机回归。ART 能力仍为 `ENTRY_ONLY`，Hook 删除仍是
逻辑删除，已内联的调用方不在覆盖范围内。

本地证据位于 `out/android17/`：`matrix-results.json`、各脚本日志、
`injection.log`、`lifecycle.log`、`inline-*.log`、`monitor.log`、
`profile-audit.log` 及反汇编审计文件。构建产物与证据按项目约定不纳入 Git。

## 复现

将 `ANDROID_SERIAL` 设为测试设备序列号，并确认 `adb shell su -c id` 返回 root。
使用专用测试设备：APK 测试会替换 `org.ij2art.aottest`。构建与脚本列表见
[test/README.md](../test/README.md)。

```sh
zsh test/build-art-api.sh
zsh test/build-android.sh
zsh test/build-inline.sh
zsh test/build-java-calls.sh
zsh test/build-jni-abi.sh
zsh test/build-logical-disable.sh
zsh test/build-monitor.sh
zsh test/build-apk.sh --aot
```

使用本地测试密钥将 `out/aot-apktest-aligned.apk` 签名为
`out/aot-apktest-aligned-signed.apk`，重复测试时保持签名密钥一致。随后执行：

```sh
python3 test/run-art-api.py --serial "$ANDROID_SERIAL"
for mode in jit no-jit debuggable; do
  python3 test/run-hook-replace.py --serial "$ANDROID_SERIAL" --mode "$mode"
done
for mode in jit no-jit debuggable aot; do
  for feature in constructors synchronized native-binding hook-update; do
    python3 "test/run-$feature.py" --serial "$ANDROID_SERIAL" --mode "$mode"
  done
done
python3 test/run-aot-demo.py --serial "$ANDROID_SERIAL"
python3 test/run-java-calls.py --serial "$ANDROID_SERIAL"
python3 test/run-java-calls.py --serial "$ANDROID_SERIAL" --apk
python3 test/run-java-calls.py --serial "$ANDROID_SERIAL" --no-main
python3 test/run-static-jni.py --serial "$ANDROID_SERIAL"
python3 test/run-static-jni.py --serial "$ANDROID_SERIAL" --logical-disable
python3 test/run-inline.py --serial "$ANDROID_SERIAL" --mode native
python3 test/run-inline.py --serial "$ANDROID_SERIAL" --mode art
python3 test/run-monitor.py --serial "$ANDROID_SERIAL"
# Requires an initially uninjected zygote; do not run beside other APK suites.
python3 test/run-injection.py --serial "$ANDROID_SERIAL"
```

隔离生命周期和远程调用测试见主 README。OTA 或 ART 更新后，重新审计设备 ELF：

```sh
adb pull /apex/com.android.art/lib64/libart.so out/libart-device.so
python3 tools/art-profile.py out/libart-device.so \
  --manifest payload/art_profiles/symbols17.inc \
  --build-id 4259bc018250195dc006f2b6cf330eb1
```

build ID 不同就需要重新完成布局、ABI、入口保护审计和真机测试；仅替换 build ID
字符串或符号偏移并不足够。
