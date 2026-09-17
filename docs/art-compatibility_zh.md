# ART 动态兼容

当前采用类似 LSPlant 的兼容方式：按版本约束、符号能力和运行时探测选择实现。
`libart` 的 GNU build-id 不再是 Hook 白名单；它只用于诊断，以及核对磁盘 ELF
与进程中加载的库是否为同一文件。CLI/carrier/payload 之间的产物身份校验仍然保留。

## 初始化过程

1. 从已加载的 `libart.so` 定位实际文件，解析 `.dynsym`、`.symtab` 和
   `.gnu_debugdata`。按完整 ABI 签名尝试候选符号；允许 LLVM 的 `.__uniq.` / `.llvm.`
   后缀变化，同名候选若对应不同地址则拒绝。函数地址和入口字节均取自当前 ELF。
2. 根据 `jit_mutator_lock`、入口写入函数等能力，选择 locked-code 或 zombie-code
   回收协议。所有必需入口齐全后才继续。
3. 用有界 ARM64 数据流解析检查 Runtime、JIT、线程池、ClassLinker、代码缓存和
   栈遍历器的字段访问。不调用伪造 ART 对象上的函数，不为探测修改目标方法。
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

- 当前版本约束为 API 34–37 / arm64，使用原 Android 14、16、17 审计形成的两类协议
  和三组内部布局规则。API 范围内的设备仍必须通过全部符号与布局检查。
- Runtime 的线程列表、JIT、ClassLinker、调试状态、回调，ArtMethod 布局、线程池字段和
  StackVisitor 存储范围由探测确定。Instrumentation、CHA 和部分代码缓存字段仍使用
  有指令访问证据的布局规则。内部 STL 布局、访问标志和锁语义也是协议的一部分；这些
  改变时仍需要扩展规则，不能仅凭版本号或“符号都存在”认定兼容。
- 现在仅对 Pixel 7 / Android 17 完成本次动态后端真机回归。Android 14/16 的历史结果
  不等于新解析器已在这些设备重测，Android 15、其他厂商 ROM、16 KiB 设备尚未验证。
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

设备矩阵和生产 zygote 注入验证使用 [test/README.md](../test/README.md) 中的脚本。
本次证据保存在 `out/art-dynamic/`；初次 Android 17 适配记录见
[android17_zh.md](android17_zh.md)。

参考策略来自 [LSPlant](https://github.com/LSPosed/LSPlant)：符号解析回调、按版本分支和
ArtMethod 运行时布局探测。这里的解析器、ABI 探测和后端集成由本项目实现。

## 本次结果（2026-09-17）

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
