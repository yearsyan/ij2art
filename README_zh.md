# ij2art

Android app 调试工具。基于 ptrace zygote 实现：CLI 将 carrier 加载到 zygote，
目标进程经 fork 继承，在特化阶段加载内嵌 payload；切域成功后，payload 建立共享内存控制通道。

项目处于原型阶段，仅维护当前实现。需要有 ptrace、进程内存和 pidfd_getfd 权限的
root 环境；构建目标为 AArch64 / Android API 31。

ART Hook 已改为[动态符号解析与运行时 ABI 探测](docs/art-compatibility_zh.md)，不再使用 libart build-id 白名单。

已完成 Pixel 7 上的 Android 17 适配与验证；精确 ART 构建、测试结果和覆盖边界见
[docs/android17_zh.md](docs/android17_zh.md)。

*英文版：[README.md](README.md)*

## 生命周期

```text
ij2art inject
    └─ 暂停 zygote 全部线程
       ├─ 登记临时 scratch / memfd / dlopen handle
       ├─ dlopen carrier（构造函数只初始化，不挂钩）
       ├─ 校验 GNU build-id → setup 配置并安装 GOT hook
       └─ 关闭临时 fd、释放 scratch → 恢复线程
             └─ fork / USAP 特化
                ├─ 还原本进程的 GOT
                ├─ 命中目标时加载 payload
                └─ 原 setcontext 成功返回 → 启动控制环 worker
```

- carrier 和 payload 保留 linker 注册信息：不摘 r_map/solist，不擦除 dynstr，不直接
  munmap 已加载的库；子进程特化后保留 carrier 映射直到进程退出。
- `clear` 暂停父 zygote 及其现存 USAP，确认 GOT 全部还原后经 `dlclose` 正常注销
  carrier；卸载失败会报告错误并保留映射。
- 注入失败执行事务清理：关闭 fd、解除已挂 hook、dlclose、释放 scratch。`targets`
  先停进程再原子发布完整配置，写失败回滚旧配置。
- 现存 USAP 单独补注，新 USAP 从父 zygote 继承；再次 `inject` 检查缺失成员并报告
  部分失败。

`common/hide_self.*`、`cli/src/hide.rs` 和 `carrier/teardown_stub.S` 是历史实验代码，
当前构建不使用它们。

### 远程调用的恢复规则

等待使用单调时钟截止时间和 `waitpid(WNOHANG)`，不依赖 SIGALRM。保存/恢复通用寄存器、
FP/SIMD、可用的 SVE 状态和信号掩码；不支持的 SME 状态在执行前拒绝。只有函数正常返回
哨兵地址（可能产生 SIGSEGV/SIGBUS，两者均要求 PC 精确匹配）后才恢复原执行上下文；
恢复失败不能报告成功。

远程函数崩溃、执行超时或恢复失败时，禁止后续远程调用，并在 detach 前给目标保留
SIGSTOP 停止态——此时不能用 SIGCONT 或重新 inject「恢复」，需检查现场，必要时在维护
窗口重启目标。CLI 被 SIGKILL 等无法执行清理的情况不具备自动恢复保证。

## 构建

```sh
./build.sh
```

工具链定位统一由 `sdk.env.sh` 完成，仓库内不硬编码本机路径：优先 `SDK` / `NDK` /
`BUILD_TOOLS` 或 `ANDROID_HOME` / `ANDROID_SDK_ROOT` / `ANDROID_NDK_HOME` 环境变量，
其次探测 `~/Library/Android/sdk`、`~/Android/sdk` 标准位置；NDK 与 build-tools 默认取
锁定版本（28.1.13356709 / 36.0.0），缺失时回退到已安装的最高版本。需要 Rust 的
`aarch64-linux-android` 目标；交叉 linker 由 `sdk.env.sh` 导出的
`CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER` 提供，单独在 `cli/` 下构建时先
`source ../sdk.env.sh`。

产物：`out/ij2art`、`out/carrier.so`（内嵌 payload）、`out/payload.so`。
匹配本地产物与远端实例时使用 GNU build-id，不能混用不同构建。
Hook SDK 构建还需要 JDK；`out/ij2art-hook-api.jar` 供替换逻辑编译使用。

## 功能与文档

- **ART 方法 Hook**：上传替换 DEX，Hook 普通方法、`<init>` 构造函数、synchronized
  和已绑定 native 方法的入口；支持 `callOriginal`、逻辑删除、运行中 `hook update`
  更换回调，以及带 OAT quick code 的方法。覆盖级别 `ENTRY_ONLY`。
- **Native inline hook**：`ctl inline` 使用内嵌的 ShadowHook v2.0.1，支持 arm64 函数
  入口替换、原函数跳板、查询和删除；`ctl lib load` 可经控制环把 `.so` 传入目标进程
  memfd 后 dlopen，不依赖磁盘路径。
- **JSON Java 方法调用**：`ctl java call` 在 App 主线程或新线程执行 JSON 描述的
  方法调用（如开启 WebView 调试），异步任务，无需 ART Hook。见
  [java-calls.md](docs/java-calls.md)。
- **eBPF 被动观测**：`monitor` 子命令（P0：raw_syscalls），需要内核 ≥ 5.10；CLI 静态
  编入 libbpf v1.7.0 ringbuf。见 [ebpf-monitor.md](docs/ebpf-monitor.md)。

### 文档约定

文档与代码注释默认使用英文，每份文档另存一份中文版 `*_zh.md` 并排维护，两版需同步更新：

| 英文（默认） | 中文 |
|---|---|
| [README.md](README.md) | [README_zh.md](README_zh.md) |
| [docs/ebpf-monitor.md](docs/ebpf-monitor.md) | [docs/ebpf-monitor_zh.md](docs/ebpf-monitor_zh.md) |
| [docs/java-calls.md](docs/java-calls.md) | [docs/java-calls_zh.md](docs/java-calls_zh.md) |
| [docs/android17.md](docs/android17.md) | [docs/android17_zh.md](docs/android17_zh.md) |

## 使用

```sh
adb push out/ij2art out/carrier.so /data/local/tmp/ij2art/
adb shell
su
cd /data/local/tmp/ij2art
chmod +x ij2art

./ij2art inject --carrier ./carrier.so --targets com.example.target
./ij2art status
./ij2art launch com.example.target
./ij2art targets --targets com.a,com.b
./ij2art targets --none
./ij2art clear
```

也可用 `--all`（默认）匹配 `uid % 100000` 在 `[10000,20000)` 的进程；这不是 SELinux
域判定。名单是对特化参数中进程名的精确匹配，独立进程如 `com.example.target:remote`
需另行列入。多 zygote ROM（如 OPPO/ColorOS 的 `zygote_ocomp`）上 CLI 按目标自动选择
实例，依据打印到 stderr，`--pid` 显式覆盖；目标横跨多个 zygote 时报错，需分次注入。

只影响注入后启动的进程。`clear` 不卸载已运行 App 中的 carrier/payload，重启对应 App
后清除。CLI、carrier 和 payload 应使用同一套构建产物；替换产物前需结束注入会话并
重启相关进程。

## 控制环

payload 建立 64 KiB memfd，共享命令/响应槽并使用共享 futex 唤醒；CLI 经 pidfd_getfd
复制 fd 并映射同一文件。仅实现一套协议，不提供历史兼容或版本协商；头部 `version`
只用于严格校验当前布局。

- CLI 对环 fd 持有进程级 `fcntl` 排他写锁，其他 CLI 会得到占用错误。
- 每次连接递增独立的 64 位会话号，响应同时验证会话、请求序号和命令类型。
- `cmd_seq != rsp_seq` 表示旧请求仍在途；超时或重连不取消它，也不能覆盖命令槽。
- worker 先复制命令快照再执行，初始化完成后才发布 READY。
- CLI 默认 5 秒超时；WRITE 单次最多 3992 字节，READ 响应最多 16344 字节。

```sh
./ij2art ctl --pid P ping
./ij2art ctl --pid P mods
./ij2art ctl --pid P read 0xADDRESS 32
./ij2art ctl --pid P write 0xADDRESS deadbeef
./ij2art ctl --pid P call --in /libc.so getpid
./ij2art ctl --pid P shutdown
```

SHUTDOWN 响应表示请求已确认，worker 随后关闭 fd、解除共享映射并退出；payload 库保持
加载。CALL 只支持最多 8 个整数/指针参数，其函数本身的异常会影响 App；CLI 超时不代表
该函数已取消。

### 脚本 / agent 友好接口

`ctl` 及 status/inject/targets/clear/launch 支持 `--json`：结果以
`{"ok":true,"data":...}` / `{"ok":false,"error":{...}}` 信封输出到 stdout，提示性信息
留在 stderr。`ctl overview` 单连接返回 payload 身份 + 全部注册表快照；`ctl batch`
从 stdin 读 JSON Lines 批量执行；`launch --wait N` 与 `ctl --pkg P --wait N` 等待进程
出现。完整语法与输出契约见 `ij2art help` / `help ctl` / `help agent`。

## 回归测试

```sh
# 宿主机单元/共享映射/跨进程文件锁测试
cargo test --manifest-path cli/Cargo.toml --offline --locked

# 构建 Android 隔离测试程序
./test/build-android.sh
```

`lifecycle-test <carrier.so> <payload.so>` 在自己的进程内执行 20 次 carrier
加载/枚举/卸载，以及实际 payload 的 READY、PING、CALL、MODS、SHUTDOWN 测试。
`remote-smoke <lifecycle-test>` 只 ptrace 自己启动的子进程，验证正常调用与超时后的
停止行为，并在结束时终止、回收该子进程。两者都不接管 zygote 或现有 App。
