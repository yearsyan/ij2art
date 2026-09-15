# kernel uapi headers (vendored)

来源: torvalds/linux **v5.10** 的 uapi 头, 仅含 BPF 程序编译所需的最小 include 链。
用于两处:

- `bpf/` 源码编译(`-nostdinc -I third_party/kernel-uapi/include -D__EXPORTED_HEADERS__`);
- `cli/src/monitor/` 的常量核对(bpf_attr 布局、helper ID、map/prog 类型编号)。

文件清单(均为原样拷贝, 除注明外):

```text
include/linux/{bpf.h, bpf_common.h, types.h, posix_types.h, stddef.h}
include/asm-generic/{types.h, int-ll64.h, bitsperlong.h, posix_types.h}
include/asm/{posix_types.h, bitsperlong.h}      # arch/arm64 uapi
```

手工维护的两个文件:

- `include/asm/types.h` —— arm64 内核经 `generic-y += types.h` 使用 asm-generic 版,
  v5.10 树里没有对应文件, 此处为等价转发头 `#include <asm-generic/types.h>`。
- `include/linux/compiler_types.h` —— 空 stub。uapi 链中仅 `stddef.h` 引用它,
  且只为 `__always_inline` 回退定义(自带), 本树无宏实际使用; 真实文件会拉入
  compiler-*.h 全家桶, 无 vendor 必要。

辅助核对(已对 v5.10 头逐项验证, 改动本目录后必须重跑):

```sh
sed -n '/#define __BPF_FUNC_MAPPER(FN)/,/^$/p' include/linux/bpf.h \
  | grep -o 'FN([a-z_0-9]*)' | sed 's/FN(//;s/)//' | awk '{printf "%d %s\n", NR-1, $0}'
# bpf/bpf_helpers.h 中的 helper ID 与此输出一致:
#   1 map_lookup_elem  2 map_update_elem  3 map_delete_elem  5 ktime_get_ns
#   8 get_smp_processor_id  14 get_current_pid_tgid
#   112 probe_read_user  113 probe_read_kernel  114 probe_read_user_str
#   131 ringbuf_reserve  132 ringbuf_submit  133 ringbuf_discard
```
