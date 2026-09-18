# 指令观察点

`ctl probe` 观察 **arm64 某条指令执行前的寄存器状态**。它使用已注入 payload
内的 ShadowHook 指令拦截器，无需替换库、DEX 或 eBPF。拦截器会修改目标指令，
记录快照后继续执行原有逻辑。它记录指定观察点的命中，不提供连续分支轨迹。

*英文版：[instruction-probes.md](instruction-probes.md)*

## 命令

```sh
# 进程当前实例中的绝对运行时地址。
./ij2art ctl --pid P probe add --target 0x7123456010 --max-hits 100

# 函数入口后 16 字节；模块路径后缀必须唯一匹配。
./ij2art ctl --pid P probe add --target target_function --in /libexample.so --offset 0x10

# ELF 虚拟地址 + 模块加载偏移，不是文件偏移或可执行映射起点的偏移。
./ij2art ctl --pid P probe add --in /libexample.so --offset 0x12340

# 可选：限定 Linux 线程及寄存器精确值。
./ij2art ctl --pid P probe add --target target_function --in /libexample.so \
    --tid T --when x0=0x42 --max-hits 20

./ij2art ctl --pid P --json probe list
./ij2art ctl --pid P --json probe query 1
./ij2art ctl --pid P --json probe read 1 --after 0 --limit 48
# 用上一条响应的 data.next_seq 继续读取。
./ij2art ctl --pid P --json probe read 1 --after 48

# 先让所有目标调用者静止，包括正在执行拦截回调的线程。
./ij2art ctl --pid P probe del 1
```

`--target` 接受 `0x` 绝对地址或符号。符号需要 `--in`；绝对地址不能同时指定
`--in`。有 target 时，`--offset` 加到 target 上；没有 target 时，必须同时提供
`--in` 和 `--offset`。偏移及最终地址均须按 4 字节对齐。模块选择器也支持
`ctl lib load` 返回的完整 `module`，包括标记为 deleted 的 memfd 路径。

`--tid 0`（默认）匹配任意线程。非零 TID 必须当前属于目标进程；它匹配 Linux
数值 TID，线程退出后应停止观察，避免后续 TID 复用。`--when xN=VALUE` 支持
x0..x30，值为无符号 64 位十进制或十六进制数；省略则不限制寄存器。
过滤先于命中计数。

`--max-hits 0`（默认）不限制次数；正数表示匹配命中尝试的上限，包括因竞争而
丢弃的命中。达到上限后停止采集，但指令补丁保留到 `del`。添加成功返回观察点
ID；超时后先用 `list/query` 查询，再决定是否重试安装。

## 记录和游标

每个观察点有独立的进程内缓冲区，保留最近 256 条快照。回调不等待 CLI 或缓冲区
锁，遇到竞争时丢弃并计数。只有执行 `read` 时，才经控制环传输有界批次。
读取不消费记录，单批最多 48 条。

| 字段 | 含义 |
| --- | --- |
| `probe` | 配置、状态、原始指令字和累计计数 |
| `events[].seq` | 本观察点的发布序号，从 1 开始，用作游标 |
| `events[].hit` | 匹配命中尝试序号；多线程时可能与发布顺序不同 |
| `events[].ts_ns` | 回调内采集的 `CLOCK_MONOTONIC` 时间，不是指令完成时间 |
| `events[].tid` | 命中线程 |
| `events[].pc`, `sp` | 原指令地址和栈指针 |
| `events[].nzcv` | 条件标志，**不是完整 PSTATE** |
| `events[].regs` | 原始 x0..x30；x29 为 FP，x30 为 LR，保留指针认证位 |
| `events[].clock_failed` | 时间戳采集失败，此时 `ts_ns` 为零 |
| `next_seq` | 下次读取的排他游标 |
| `more` | 取快照时，本批之后还有记录 |
| `lost` | 请求游标之后已被覆盖、无法再读取的记录数 |

`hits` 为接受的匹配命中次数，`captured` 为已发布快照数，`dropped` 为竞争丢弃数，
`overwritten` 为从滚动窗口中淘汰的快照数。调用者静止后满足
`hits = captured + dropped`；实时计数可能包含尚未完成的回调。被覆盖的记录可能
已经被读取，因此覆盖与丢弃分别统计。判断覆盖率时同时检查 `lost` 和 `dropped`。

从 `--after 0` 开始，用返回的 `next_seq` 向后读取。可以重复使用同一游标，
但其间旧记录可能已被覆盖。超过 `captured` 的游标会被拒绝。`-75` 表示写者正
占用缓冲区，可以使用原游标重试。序号仅表示该观察点的发布顺序，不代表所有
观察点或线程的全局顺序。支持标准 `--json` 信封、`ctl batch` 和 `ctl overview`。

## 生命周期和执行边界

- 状态为 `ACTIVE`、`LIMITED`、`REMOVED`、`ERROR`。`LIMITED` 停止采集但仍保留
  补丁；关闭控制环或卸载上传的目标库前必须删除已安装观察点。
- `del` 物理恢复指令，成功后可重复调用。与 `inline del` 相同，删除前需让目标
  调用者静止，包括已进入拦截回调的线程。后端安装或删除失败记录为 `ERROR`，
  失败不证明代码已经还原，因此保留 ELF 引用并要求重启进程，不能复用后端已消费
  的句柄。
- ID 和缓冲区不复用，每个进程生命周期最多安装 64 次，每个约 76 KiB 快照空间。
  删除后仍可读取记录。文件库的加载引用保留到进程退出；上传库可以在删除观察点
  且调用者静止后卸载。
- 目标必须是已加载 ELF 可读可执行映射中的有效指令，且位于 payload 之外。
  不支持匿名/JIT 代码和 payload 内部。用户 inline hook 与观察点不能使用同一
  目标地址。不做反汇编来判断对齐地址是否真的是代码，不能指向内嵌数据或
  exclusive-load/store 指令序列内部。
- 回调保留通用寄存器、NZCV 和 FPSIMD 状态，不修改传入上下文。向量寄存器仅
  保存恢复，不输出；不保证 SVE/SME 状态或 exclusive monitor 状态。
- 插桩改变代码字节和执行时序，热点位置应限制命中次数。快照位于指令执行前，
  后续异常或信号仍可能阻止这条指令完成。

## 验证

```sh
zsh test/build-probe.sh
python3 test/run-probe.py --serial DEVICE
```

构建脚本运行宿主机并发缓冲区回归，并构建真实 payload、CLI 和 native fixture。
设备测试使用全新独立进程，覆盖函数内部指令的 GPR/NZCV、活跃 SIMD 状态保留、
地址/符号/模块偏移解析、过滤、上限、多线程采集、覆盖和游标、物理恢复及上传库
的生命周期。
