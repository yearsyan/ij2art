# eBPF 被动观测设计 v2：系统调用 / Binder IPC / Native→Java JNI

设计稿（v2，评审修订版）。为 CLI 引入 `monitor` 子命令：用 eBPF 在内核侧对目标 App
做被动的行为观测，与现有 payload 注入路径（ART hook / inline hook）解耦、互为补充。

*英文版：[ebpf-monitor.md](ebpf-monitor.md)*

**v2 变更**（相对 v1，来自评审）：

1. JNI uprobe 探针改为**显式开启的可选特性**，如实披露其在目标代码页写入断点字节；
   撤回"零介入/固定开销"的承诺。
2. syscall 观测改用 **raw tracepoint**（`bpf_raw_tracepoint_open`），perf tracepoint
   的 `trace_event_raw_sys_enter` 没有 `regs` 字段；PC 归因降级为帧指针链 best-effort。
3. 进程发现重写：zygote 模型下 `:remote`/USAP/isolated 不是"主 App 的子进程"，
   fork 跟踪只是补充；线程退出不得误删整个进程（tgid/tid 纪律）。
4. Binder 解析修正：BC 命令字为 **4 字节**、无 8 字节对齐头；Android 12 parcel
   前缀含 StrictMode/WorkSource/SYST-VNDR 字段，token 不在首 4 字节，按锁定版本的
   协议表解码。
5. Binder 两层事件放弃"tid+最近时间"合并，改为**位置对位队列**，关联不上输出
   未关联状态，不猜测。
6. syscall 策略表升级为**逐调用参数描述符**（参数索引/长度来源/解码类型）；
   修正 aarch64 编号：sendto=206、sendmsg=211。
7. 自研 loader 定义明确的 **ELF 子集契约**（map 定义格式、仅 R_BPF_64_64、未知
   重定位拒绝），不再描述为"扫描伪 fd 模式"。
8. JNI 符号按 API 级别维护候选表（Android 12 为 `JNI<true/false>` 模板实例），
   vaddr→**文件偏移**经 PT_LOAD 换算，uprobe 按跟踪到的 pid 逐进程挂载。
9. 事件头修正为 48 字节并增加 status 位；大事件经 ringbuf reserve 组装，不超栈限制。
10. 丢弃统计改为内核侧**分类计数 map**（ringbuf `-EBUSY` 时累加），CLI 直读。
11. fd 表按 tgid 维护（线程共享），覆盖 dup/dup3/close/close_range 与继承。
12. 内核支持下限统一为 **5.10**（消除 v1 D2/D3 矛盾），事件通道随之改用 ringbuf。
13. 分期收敛：P0 只做 `--pid` + syscall，先证明数据准确性。

## 1. 目标与非目标

目标：

- **系统调用画像**：按目标 pid 记录 openat / execve / connect / sendto / mmap /
  mincore / ptrace 等，含参数解码与调用点 best-effort 归因。
- **Binder IPC 观察**：记录事务对端、code、flags、interface token，位置对位关联，
  关联不确定时明确标注。
- **Native→Java JNI 观察（可选，默认关）**：uprobe 挂 libart 的 JNI 表函数，
  解码 `RegisterNatives` 恢复动态注册的 native 方法。**该探针会在目标进程代码页
  写入软件断点指令**，内存完整性自检可见，见 §7。

非目标：

- 不经 payload 控制环传输事件（控制环是单在途命令/响应语义，且 payload 只存在于
  注入后的进程，观测要求覆盖注入前与非目标进程）。
- 不承诺对目标进程零介入：syscall/binder 特性被动无痕；JNI 特性有代码页修改。
- 不做 Java 方法级语义、网络载荷抓包、改写类操作。

## 2. 总体架构与数据流

```text
                 ┌─ kernel ──────────────────────────────────────────────┐
   raw_tp        │  raw_syscalls sys_enter / sys_exit  (ctx: regs, id)   │
   perf_tp       │  binder/binder_transaction           (format 解析偏移)│
   perf_tp       │  sched/sched_process_fork / sched_process_exit        │
   kprobe        │  binder_ioctl(entry)                                  │
   uprobe(可选)  │  libart.so JNI 函数文件偏移, 按跟踪 pid 逐进程 perf 挂 │
                 │      │  BPF 程序 (cfg map 偏移 + tracked/uid map 过滤) │
                 │      └─> BPF ringbuf ──(满: 分类 drop 计数 map)───────│
                 └────────────┬──────────────────────────────────────────┘
                              │ ringbuf mmap (consumer pos 页 + epoll)
   ij2art monitor (Rust CLI, root)
      ├─ loader: ELF 子集解析 → 建图 → R_BPF_64_64 重定位改写 → BPF_PROG_LOAD
      │          → raw_tp / perf_event_open(tracepoint|kprobe|uprobe) 挂载
      ├─ 发现: packages.list→uid, /proc 轮询, 特化期 setresuid 捕获, fork 补充
      ├─ 富化: pid→进程名, pc→(lib,off) 帧链 best-effort, fd 表(tgid),
      │        sockaddr/parcel-token/RegisterNatives 解码
      └─ 输出: 文本 或 --json JSONL; 退出时打印分类事件数与丢弃数
```

过滤在内核（tracked pid HASH + 关注 uid HASH），富化在用户态；ringbuf 满/读失败
不静默，一律计数可查。

## 3. 设计决策

**D1 观测路径与 payload 解耦。** eBPF 侧不注入、不用控制环，独立可用；覆盖注入前
窗口与 App 全部进程；syscall/binder 特性不改目标进程任何字节。

**D2 内核下限统一为 5.10，事件通道用 ringbuf。** v1 的 perf_event_array 是为 5.4
兼容，但无 BTF 方案依赖 `bpf_probe_read_user/kernel`（5.5+）与有界循环（5.3+），
实际下限已是 5.10，两者矛盾；统一后改用 ringbuf（5.8+）：单缓冲、无 per-CPU 环、
ringbuf 预留失败时，可在内核侧按事件类别精确累加丢弃
计数（perf 通道的 PERF_RECORD_LOST 无法归因到类别，v1 的 lost[kind] 承诺不成立）。

**D3 无 BTF / 无 CO-RE，按挂载点分类取偏移。**

| 挂载点 | ctx 形态 | 偏移来源 |
|---|---|---|
| raw_tp sys_enter/exit | `(pt_regs *regs, long id)` 数组 | arm64 用户 pt_regs 固定布局（x0..x5@0..40、fp@232、pc@256），进 cfg map |
| perf_tp binder/sched | trace_event_raw_* | 运行时解析 tracefs `format`，字段缺失即拒载该特性（fail-closed） |
| kprobe binder_ioctl | 内核 pt_regs | x2@16 固定；binder 结构偏移由 vendor uapi 头宿主编译期计算 + 静态断言 |
| uprobe JNI | 用户 pt_regs | 参数寄存器固定偏移；符号→文件偏移见 §7 |

**D4 自研 loader 的 ELF 子集契约。** 支持范围显式收紧，出界即拒绝加载：

- 节：`.text`（全部程序）、`maps`（地图定义节）、`.symtab`/`.strtab`/`.rel.text`；
  出现 `.rodata`/全局数据/BTF 段依赖一律拒绝（源码纪律：常量只走 cfg map）。
- map 定义：仓库自定义 `struct bpf_map_def { type, key_size, value_size,
  max_entries, flags }`（定义在 `bpf/common.h`，加载器按符号切分 `maps` 节）。
- 重定位：**只接受 `.rel.text` 中指向 `maps` 符号的 `R_BPF_64_64`**，加载器将目标
  `ld_imm64` 的 src_reg 置 `BPF_PSEUDO_MAP_FD`、imm 置真实 fd。其余重定位类型
  （R_BPF_64_ABS64/32、跨节调用、ksym/kfunc）一律 fail-closed。
- 程序间不调用（单 `.text` 内调用由链接期解析）；程序类型与挂载参数由 CLI 侧
  配表指定，.o 不携带元数据。
- license 固定 "GPL"（probe_read 系 helper 是 gpl-only）。

若契约实现中验证器/loader 兼容问题消耗过大，降级为 vendor AOSP external/libbpf。

**D5 内核过滤 + 分类计数。** tracked（pid→特性位）与关注 uid 两个 HASH 由 CLI
维护；每个特性程序持一个 ARRAY 计数 map（发射数/丢弃数），CLI 周期性与退出时
直读，输出 `emitted[kind]/dropped[kind]`，无静默丢失。

**D6 事件头 48 字节，含状态位；大事件经 ringbuf reserve 组装。**

```c
struct ev_hdr {          // 48 B
    u32 magic; u16 kind; u16 len;
    u32 cpu, pid, tid;
    u32 status;          // bit0 TRUNCATED, bit1 READ_FAIL, bit2 UNASSOC, bit3 UNDECODED
    u64 ts_ns;           // bpf_ktime_get_ns
    u64 pc;              // syscall 特性: 用户态调用点; jni: uprobe 目标地址
    u64 aux;             // nr / binder code / sym_id …
};
```

事件先 `bpf_ringbuf_reserve`（按该类事件的最大长度，统一 256 B 上限），字段与
字符串直接填入保留区后 commit；不在 BPF 栈上组装大结构。字符串读失败置
READ_FAIL 并保留已得字段，截断置 TRUNCATED——**不猜、不丢整条**。

**D7 进程发现与生命周期（zygote 模型）。** 见 §4.1。

**D8 归因与关联的诚实性原则。** 任何关联（binder 对端、pc 归属库、fd 路径）
不确定时输出明确的未知状态，禁止用最近邻等启发式填充。

## 4. 公共基础设施

### 4.1 目标发现与生命周期

Android 进程现实：App 进程由 **zygote** fork，`:remote` 是 zygote 的直接子进程
（不是主 App 进程的子进程）；USAP 是**特化前**预 fork 的池成员，特化不产生新
fork；isolated 进程使用独立 uid（99000+），进程名 `<pkg>:sandboxed_processN`。
因此发现是**多机制组合**，fork 只是其中一环：

1. **初始/周期扫描**（权威来源）：`--pkg` → `/data/system/packages.list` 得 uid →
   周期扫 `/proc/<pid>/status`(uid) + `/proc/<pid>/cmdline`。isolated 进程按
   cmdline 前缀 `<pkg>:` 匹配（覆盖 `:remote`、`:sandboxed_process*`、WebView
   renderer）。周期 500ms，同时兜底所有其他机制的遗漏。
2. **特化期即时捕获**（缩短空窗）：`setresuid/setreuid/setuid/setresgid` 等少数
   nr **不做 tracked 前置过滤**，全局检查参数 uid 是否落在关注 uid HASH——命中即
   在内核把该 pid 加入 tracked 并发事件。zygote/USAP 特化必然经过这里，从特化
   时刻起即被跟踪，不等轮询。
3. **fork 补充**：`sched_process_fork` 仅处理"父 tgid ∈ tracked"的真子进程
   （App 自己 fork 的 `Runtime.exec` 等）；zygote 的 fork 不在此列，交给机制 1/2。
4. **退出与线程纪律**：`sched_process_exit` 对**每个退出任务**触发，ctx 只有
   tid。处理器用 `bpf_get_current_pid_tgid()` 取 tgid：`tid != tgid` 是线程退出，
   **不动 tracked**（只发 NOTE）；`tid == tgid` 才删除并发 PROC_EXIT。exec 不移出
   跟踪，仅刷新进程名。

### 4.2 事件通道

- ringbuf（默认 8 MiB），CLI 静态链接固定版本 **libbpf v1.7.0** 的原版 ringbuf
  模块；`ring_buffer__new/consume_n/free` 负责容量查询、mmap、回绕与内存序。
  在 libbpf 提供的 epoll fd 上等待，每次最多消费 4096 条，保证持续洪泛时仍能
  检查 `--secs`/SIGINT 并刷新输出。
  容量从 map 信息获取，不依赖 CLI 常量；集成边界见
  [libbpf vendoring](../third_party/libbpf/README.md)。
- 输出统一走 `bpf_ringbuf_reserve` → 填充 → commit（见 D6）。
- 解码错误（magic、kind、实际长度/头部长度、data_len）立即明确报错并非零退出。
  正常退出先摘除探针，再读完缓冲余量，汇总 `received` 与内核 emitted/dropped。

### 4.3 cfg map

ARRAY map，槽位在 `bpf/common.h` 与 `cli/src/monitor/mod.rs` 双侧同步（纪律同
common/proto.h，无协商）。内容：arm64 用户 pt_regs 偏移、tracefs format 解析出的
binder/sched 字段偏移、vendor uapi 编译期算出的 binder 结构偏移、全局开关。

### 4.4 CLI 侧富化

- **pc 归因（best-effort，如实标注）**：syscall 的用户 PC 几乎总落在 libc 的
  `svc` 包装函数，不等于业务发起库。归因流程：pc 经 maps 定位（libc+off）；再从
  保存的 fp(x29) 走帧指针链（≤8 帧，校验单调递增与地址合法性，逐帧
  `bpf_probe_read_user`），取第一个位于 libc/vDSO 之外的帧作为发起库。arm64 系统
  库普遍保留帧指针，第三方 .so 视编译选项；解析失败输出 `libc+0xoff (caller 未知)`，
  不臆测。
- **fd 表**：按 **tgid** 维护（线程共享 fd 表）。openat/openat2 出口(ret≥0)、
  dup(23)/dup3(24)(ret)、close(57)、close_range(438) 维护 `fd→path`；fork 时子进程
  继承副本；fd 重用直接覆盖；best-effort，查不到标未知。
- **解码**：nr→名称；sockaddr 按 family 定长（IPv4 16B、IPv6 28B，长度上限取
  `min(addrlen, 128)`）；parcel token 与 RegisterNatives 见 §6/§7。

## 5. 特性一：系统调用观察

**挂载点**：raw tracepoint `sys_enter` / `sys_exit`（`bpf_raw_tracepoint_open`，
程序类型 RAW_TRACEPOINT；perf 版 tracepoint 的 ctx 无 `regs`，不使用）。
ctx 为参数数组：`args[0]=pt_regs*, args[1]=id(ret)`。

**策略表升级为逐调用描述符**（ARRAY map，CLI 参数可覆盖）：

```c
struct sys_policy {
    u8  action;        // DROP / HEAD(仅参数) / DECODE
    u8  arg_idx;       // 解码目标的参数下标
    u8  len_src;       // 0=定长 / n=args[n] 为长度 / 0xff=NUL 结尾字符串
    u8  decoder;       // PATH / SOCKADDR / NONE
    u16 fixed_len;     // 定长时的字节数
};
```

默认表（aarch64 编号，修正版）：

| nr | 调用 | 解码 |
|----|------|------|
| 56/437 | openat / openat2 | PATH @ **args[1]**（execve 是 args[0]，不共用） |
| 221/281 | execve / execveat | PATH @ args[0] / args[1]（AT_EMPTY_PATH 跳过） |
| 203 | connect | SOCKADDR @ args[1]，长度 args[2]，≤128B（容纳 IPv6/unix） |
| 206/211 | sendto / **sendmsg** | sendto: SOCKADDR @ **args[4]**，长度 args[5]；sendmsg 需追 msghdr(args[1]→msg_name)，P1 可选 |
| 232 | mincore | HEAD（args[0..1] 即扫描窗口，反扫描情报） |
| 117 | ptrace | HEAD（args[0] 含 PEEKDATA 等请求码） |
| 222/226 | mmap / mprotect | HEAD（PROT_EXEC 与 RWX 判定在 CLI 侧） |
| 279 | memfd_create | PATH @ args[0] |
| 270/271 | process_vm_readv/writev | HEAD（remote iovec = args[3]，P1 解码扫描区间） |
| 147/145/146/149/143/159 | uid/gid 族 | 全局通道（发现机制 2，§4.1） |
| 57/23/24/438 | close/dup 族 | HEAD（fd 表维护，§4.4） |

其余 DROP；`--sys all` 全开自担流量。`sys_exit` 只对 DECODE/HEAD 类 nr 发射，
携带 ret（fd/错误码）。

**渲染示例**：

```text
[sys] 14:02:11.302 pid=12345 openat("/proc/self/status") ret=12 pc=libc.so+0x9a1c caller=<fp链未知>
[sys] 14:02:11.477 pid=12345 connect(AF_INET6 [2001:db8::1]:443) pc=libc.so+0x9c40 caller=libcronet.so+0x9f3d
[sys] 14:02:12.008 pid=12345 mprotect(0x7b2e000000,0x4000,PROT_READ|WRITE|EXEC) pc=libun8.so+0x11d4
```

## 6. 特性二：Binder IPC 观察

### 6.1 tracepoint `binder/binder_transaction`

在发送方任务上下文触发。format 运行时解析字段：`debug_id, target_node, to_proc,
to_thread, reply, flags, code`，全部进事件；**debug_id 保留在事件里**供宿主机
离线对账。to_proc 由 CLI 解析为进程名。本层只消费 tracepoint 已暴露字段，
不依赖 `binder_transaction()` 函数签名。

### 6.2 kprobe `binder_ioctl`（parcel 头捕获）

`binder_ioctl(file, cmd, arg)`：x1=cmd、x2=用户 `binder_write_read*`。修正后的
write_buffer 布局处理：

- **命令字 4 字节**，紧跟命令专属载荷，无 8 字节对齐头（v1 错误）。
- 解析从 `write_buffer` 起、以 `write_size` 为界，按 **BC 命令长度表**推进
  （BC_TRANSACTION/BC_REPLY 载荷 = `sizeof(binder_transaction_data)`，由 vendor
  uapi + build.rs 静态断言；其余 BC_* 用长度表跳过）。有界展开 ≤8 条命令，
  更深则计数进 NOTE（批量罕见，损失文档化）。
- 命中 BC_TRANSACTION / BC_REPLY：读 `binder_transaction_data` 的
  `code/flags/data_size/data.ptr.buffer`，再读 parcel 前 `min(data_size, 96)` 字节。
  三次定长 `bpf_probe_read_user`，无循环。BC_REPLY 标记应答方向。

### 6.3 parcel 前缀解码（协议表，锁定版本）

Java Binder 事务的 parcel 前缀随 Android 版本变化；**Android 12（本项目目标）的
请求 parcel 在 interface token 之前还有 StrictMode policy、WorkSource uid、
SYST/VNDR 版本标头字段**（v1"前 4B 即长度"错误）。处理规则：

- 解码表按 Android 版本锁定（A12 条目：上述前缀 → UTF-16 长度 → UTF-16LE token），
  表驱动、新增版本加条目；
- BC_REPLY 的 parcel 布局不同（无 interface token），单独条目；
- 前缀不匹配（native binder 无 token / 未来布局变化）→ status 置 **UNDECODED**，
  原样输出前 32 字节 hex，不输出猜测的 token。

### 6.4 两层事件的关联（位置对位，不猜对端）

一个 ioctl 可携带多条事务：kprobe 在入口一次抓整批，驱动随后逐条处理、
tracepoint 逐条触发。`debug_id` 由驱动分配，**写不进 kprobe 侧事件**，因此：

- CLI 按 tid 维护两个 FIFO：kprobe 侧"批内事务序列"（write_buffer 顺序）与
  tracepoint 侧"事务事件序列"（驱动处理顺序 = 同一顺序）；
- 按位置对位合并；两侧数量不一致（事件丢失 / 驱动中途失败 / 超时未齐）时，
  消费到能对齐的位置，剩余条目标 **UNASSOC**（"对端未关联"）；
- 30s 未配对的队列条目直接以 UNASSOC 落盘，不与后续批次混对。

```text
[binder] 14:02:13.88 pid=12345 -> system_server(1879) code=54 oneway=n dbg_id=8123
         token="android.app.IActivityManager"
[binder] 14:02:13.91 pid=12345 -> <对端未关联> code=55 oneway=y token=<UNDECODED>
```

## 7. 特性三：Native→Java JNI 观察（可选，默认关闭）

**侵入性披露（v2 修正）**：uprobe 通过 `uprobe_write_opcode` 把目标地址的首指令
**替换为软件断点**（arm64 为 BRK），即目标进程的代码页字节会被修改，进程内
内存完整性自检（CRC/特征码扫描，含普通 load 自读）**可以发现**。这不同于
syscall/binder 特性的无痕被动；因此本特性必须 `--features jni` 显式开启。

**挂载方式**：按**跟踪到的 pid 逐进程** `perf_event_open(PERF_TYPE_PROBE, uprobe,
pid=<目标>)`，而非 pid=-1 全局挂——未跟踪进程零断点、零开销（v1 全局挂+BPF 过滤
会把开销摊给所有进程，包括 Call* 热点的每次命中）。跟踪集合变化时增量补挂/摘除。

**符号与偏移（v2 修正）**：

- Android 12 的 JNI 实现是 `art::(anonymous)::JNI<true/false>` 模板实例
  （kEnableIndexIds 两态），内部 C++ 混名**不构成稳定 ABI**。候选符号表按 API
  级别维护，加载时对实际 libart 文件逐一解析验证（沿用磁盘节头优先、远端
  PT_DYNAMIC 回退的解析链，但候选表独立维护，不与 ADAPTER_SYMBOLS 混用），
  解析不到就跳过并在启动摘要报告。
- uprobe 需要的是**文件偏移**而非 vaddr：sym_vaddr 返回 ELF 虚拟地址、MemElf
  返回运行时地址，两者都必须经 PT_LOAD(vaddr↔offset) 换算后再挂载。
- `RegisterNatives` 在真机 libart 上的可挂载性（前导指令是否适合 uprobe 替换）
  作为 P2 的**入门验证门槛**，过不了则本特性降级为仅低频符号或放弃。

**默认符号集**（低频）：FindClass, GetObjectClass, GetMethodID, GetStaticMethodID,
GetFieldID, GetStaticFieldID, RegisterNatives, DefineClass, NewStringUTF。
`Call<type>*` 一族默认关；`--jni-calls` 打开后也仅按 (pid, sym) 聚合计数，不做
逐条事件（断点开销随每次命中发生，聚合只省流量不省开销，文档如实说明）。

**RegisterNatives 解码**（核心产出）：`JNINativeMethod{name*, sig*, fnPtr}` 有界
读前 8 项，两条 `bpf_probe_read_user_str` + fnPtr；fnPtr 经运行时地址→lib+off 归因
（复用 §4.4 的 maps 缓存），落在匿名可执行映射时标注"疑似动态生成代码"。

## 8. 加载器与构建

```text
bpf/                 # common.h(事件头/map定义/cfg槽位), sys.c, binder.c, jni.c, track.c
third_party/binder-uapi/   # binder.h 等少数头, build.rs 编译期算偏移+静态断言
cli/src/monitor/
  ├ mod.rs / loader.rs / attach.rs / events.rs / enrich.rs / offsets.rs
out/monitor.bpf.o    # NDK clang -target bpfel-unknown-none -O2 -mcpu=v2; include_bytes! 嵌入
```

- loader 按第 D4 契约实现；raw_tp 用 `bpf_raw_tracepoint_open`，perf_tp/
  kprobe/uprobe 用 `perf_event_open`（tracepoint 需先读 tracefs 取 event id）。
- build.rs 生成 offsets.rs（binder 结构/命令常量 + 静态断言），与 cfg 槽位表一起
  双侧同步。

## 9. `monitor --check`

当前 P0 是 **arm64 syscall 端到端自检**：root、内核 ≥5.10、加载正式
sys_enter/sys_exit 程序、通过 libbpf 映射实际事件 map，再挂载 raw tracepoint。
仅将自身 TGID 加入 tracked，并仅开放 openat 策略；读取 `/dev/null` 不修改文件。

默认用 64 KiB（至少一页）ringbuf 连续产生 1024 对 enter/exit。每次 openat 使用
不同的 mode 标记（无 O_CREAT，该参数不影响文件），核对 PID/TID、nr、路径、参数、
返回值、时间戳及用户 PC 所属可执行映射；累计数据越过缓冲区 7 次以上。
5 秒内没有收到完整事件对即失败；额外/重复/损坏事件或内核计数不匹配同样失败。
这同时验证 map 容量查询、回绕和用户态解码。所有退出路径均释放探针与 map。

后续 P1/P2 的 binder/sched/kprobe/uprobe 能力应分别增加对应的端到端自检，
当前 `--check` 通过只代表已实现的 syscall 通道通过，不能证明 Binder/JNI 能力。

复现：`zsh test/build-monitor.sh`，然后
`python3 test/run-monitor.py --serial <设备序列号>`。该脚本重复自检 3 次，并启动独立
fixture 产生 50,000 次 openat/close，在正式 8 MiB ringbuf 上校验全部 200,000 条
JSON 事件的顺序、唯一标记和计数。日志保存在 `out/monitor-validation-*`。
设备侧 Rust 测试还可用 `monitor:: --include-ignored --test-threads=1` 验证故障路径：
故意破坏 magic 应立即失败；将 submit 改为 discard 后应超时失败。

**tracefs 瞬态挂载纪律**（无痕性的一部分）：raw_tp 不依赖 tracefs；kprobe 在 5.10
经 `PERF_TYPE_PROBE` 直挂、不需 kprobe_events 常驻；仅 perf tracepoint 需要 tracefs
取 event id/format——默认未挂载的设备上挂载会出现在 `/proc/mounts`。因此流程固定为
"挂载 → 读 id/format → perf_event_open → 卸载"，perf event 存活不依赖挂载点，
不给目标留下可枚举的 mounts 差异。

## 10. 风险与降级

| 风险 | 缓解 |
|------|------|
| 厂商内核 binder/sched tracepoint 字段漂移 | 偏移运行时 format 解析，缺失拒载该特性，不影响 sys（raw_tp 不依赖 format） |
| binder 结构/parcel 前缀跨版本变化 | uapi+build.rs 静态断言；parcel 按版本协议表，未知置 UNDECODED 不猜 |
| 位置对位在事件丢失下错位 | 两侧计数一致才配对，不一致消费至对齐点，余量 UNASSOC；超时落盘 |
| 帧指针链缺失致 caller 归因失败 | best-effort + 明确标注"caller 未知"，不臆测 |
| uprobe 断点被自检发现 / 热点开销 | 特性默认关、逐 pid 挂载、Call* 仅聚合并披露开销语义 |
| loader 契约外输入 | 未知节/重定位类型 fail-closed；备选 vendor AOSP libbpf |
| ringbuf 洪泛 | 内核侧默认丢噪声类 nr；分类 emitted/dropped 计数必达 |
| /proc/mounts 暴露 tracefs 挂载 | 瞬态挂载（取 id/format 后卸载）；kprobe 走 PERF_TYPE_PROBE；raw_tp 无依赖 |
| 时序侧信道：全局挂载点开销理论上可被统计性测量 | 分析窗口制挂载；默认策略丢高频 nr；开销为百 ns~µs 级，与 ptrace 停顿不同量级 |
| monitor 进程/root 环境被进程枚举类检测发现 | 与 Frida server 同级的环境痕迹，非观测机制引入；不在本项目范围内消除 |
| 特化捕获遗漏（厂商改特化路径） | 周期 /proc 扫描兜底（权威来源），空窗 ≤500ms 有界 |

## 11. 测试计划

设备侧 `test/run-monitor.py`（fixture App 扩展）+ 宿主 `cargo test`：

2026-09-16 libbpf 消费者回归记录：OnePlus PLC110 / Android 16 /
`6.6.118-android15-8-ge58033dc8ea6-abogki498046332-4k`，页大小 4096。
宿主 38 项测试、设备 12 项 monitor 测试通过（含真实 BPF 对象解析及两项故障注入）。
`--check` 连续 3 次通过，每次 2048 条事件、64 KiB ringbuf 回绕 7 轮以上。
正式 8 MiB ringbuf 接收 200,000 条事件，回绕 5 轮，唯一标记/顺序/内核计数均一致，
无重复、无丢弃。额外无节流洪泛验证中，`--secs 1` 约 1.2 秒返回，
received=230433=emitted_enter+emitted_exit，溢出由 dropped 计数汇报。

- **数据准确性（P0 验收核心）**：openat/execve/connect(IPv4+IPv6)/sendto 参数解码
  与预期一致；ret/fd 关联正确；mincore/process_vm_readv 反扫描情报字段正确。
- **冷启动/USAP**：`am start` 与 USAP 特化两条路径下，首个事件晚于特化
  setresuid 的间隔 ≤ 一次轮询周期；`:remote` 与 isolated 进程被发现并跟踪。
- **线程退出**：fixture 起停 100 线程，tracked 不误删、无 PROC_EXIT 误报。
- **批量 Binder**：单 ioctl 多事务的 fixture，位置对位逐条正确；人为丢一路事件，
  对应条目 UNASSOC 而非错配。
- **token 解码 golden**：真实 A12 事务（如 `service call` 触发）与已知接口名比对。
- **主动丢包**：1 MiB ringbuf + 压测，dropped[kind] 与重放计数一致，无静默丢失。
- **RegisterNatives**：真机 libart 上试挂 + fixture 动态注册，三元组
  （名字/签名/lib+off）正确。
- 稳定性：10 分钟 RSS 有界、maps 缓存有界、丢失计数为 0（默认策略）。

## 12. 分期（评审版）

- **P0**：loader + cfg/tracked + ringbuf + `--check` + **仅 `--pid` 的 syscall 特性**。
  验收 = §11 数据准确性各条；在此之前不开 `--pkg`。
  实现状态：已落地并完成真机验证（OnePlus 13 / Android 16 / 内核 6.6.118 GKI，
  2026-09）：`--check` 全过；ringbuf 数据区基址(+1 页)、arm64 pt_regs 偏移、
  帧链 caller 归因、fd 表关联(openat/dup3)、sockaddr 三族(IPv4/IPv6/AF_UNIX)、
  多线程覆盖、丢包计数均验证正确。原消费者洪水基线：默认策略 5s/197 万事件零丢失；
  `--sys all` 单进程 ~1M 事件/s，ring 溢出经 dropped 计数如实汇报。
  修复记录：sys_exit 的 tid→nr 条目改为消费即删（否则未放行调用的出口会冒名发事件）。
  消费者现已改为 libbpf v1.7.0；本轮验收数据与自检覆盖范围见 §9、§11。
- **P1a**：进程发现（uid/cmdline/特化捕获/生命周期）+ `--pkg`。
- **P1b**：binder 路由（tracepoint + debug_id + to_proc 富化）。
- **P1c**：binder_ioctl kprobe + parcel 协议表 + 位置对位关联。
- **P2**：JNI 可选探针（默认关；RegisterNatives 真机挂载为门槛）。
- **P3（候选）**：syscall 聚合画像模式、process_vm_readv/mincore 扫描区间解码、
  `do_page_fault` 缺页探测、读观察点哨兵（`--watch`）、BR_REPLY 抓取、
  mprotect/memfd 事件联动 `ctl read` 自动 dump。
