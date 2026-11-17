# 逆向一个 exe：可执行的路线图

目标：拿到一个 `xxx.exe`，搞清楚它做了什么、关键判断在哪、必要时用自己写的代码复现同样的功能。

> 边界：只用于你拥有或获授权分析的程序。不针对 DRM、登录校验、反作弊做绕过。

---

## 第 0 步：先分诊，别急着上反编译器

```powershell
python pe_triage.py .\target.exe            # 概览
python pe_triage.py .\target.exe --strings  # 附字符串样本
python pe_triage.py .\target.exe --json     # 交给 agent 读
```

它回答四个问题：

1. **架构**：x86 / x64 / ARM64 → 决定用 32 还是 64 位工具链
2. **是不是托管代码**（.NET）→ 如果是，这条路最短，直接跳到第 2 步的 B 分支
3. **有没有壳**（UPX / VMProtect / Themida）→ 有壳必须先脱，否则反编译出来是乱码
4. **是什么造的**（Qt / Electron / PyInstaller / Go / Rust / Unity / Unreal）→ 每种都有专门打法

熵值参考：节区熵 > 7.2 基本就是压缩或加密了。

---

## 第 1 步：按分诊结果走对应路线

| 分诊结果 | 直接可用的工具 | 说明 |
|---|---|---|
| `.NET` 托管 | **dnSpyEx** / **ILSpy** | 几乎等同源码，还能改完回编译 |
| **PyInstaller** | `pyinstxtractor.py` → `pycdc`/`pycdas` | 拆出 .pyc 再反编译，比啃机器码轻松一个量级 |
| **Electron / CEF** | `npx asar extract app.asar out` | 里面就是 JS，直接读，不用反编译 |
| **Go** | `go tool nm`、`strings` 里找 `main.xxx` | Go 符号多，函数名基本都在 |
| **Rust** | Ghidra/IDA + `cargo-auditable` 信息 | 调试符号通常被 strip，靠字符串和 panic 消息定位 |
| **Qt / C++** | Ghidra（免费）/ IDA Pro | 虚表 `_ZTV` 在就能恢复出类结构 |
| **Unity IL2CPP** | **Il2CppDumper** + Ghidra | 先导 `global-metadata.dat` 恢复方法名再啃代码 |
| **Unreal** | **FModel** / UE4SS | 资源和蓝图优先，纯 C++ 部分才需要反编译 |
| **UPX 壳** | `upx -d target.exe` | 一行脱完 |
| **VMProtect / Themida** | x64dbg + ScyllaHide 动态脱壳 | 别硬刚，先跑起来看内存 |
| **原生、无壳、无符号** | **Ghidra** → 伪 C | 主力路线，见第 2 步 |

---

## 第 2 步：主力路线（原生二进制）

### A. 静态：Ghidra 出伪 C

1. 装 Ghidra（需 JDK 21，本机已有 `jdk-21.0.11`）
2. 新建项目 → Import `target.exe` → 双击打开 → 自动分析（默认选项即可）
3. 三个入口点依次看：
   - **Symbol Tree → Exports**：`main` / `WinMain` 起点
   - **Imports**：先看它调了什么 API，这就是它的能力清单
     - `RegOpenKey` → 读注册表
     - `InternetOpen` / `WinHttp` → 有联网
     - `CreateFileW` + `WriteFile` → 落盘行为
     - `IsDebuggerPresent` / `NtQueryInformationProcess` → 反调试
   - **Defined Strings**（`Window → Defined Strings`）：错误提示、URL、格式串，是恢复逻辑最快的线索
4. 反编译窗口右键函数 → `Rename` 起名，边读边标，产出可读的伪 C

### B. 动态：x64dbg 看它实际干什么

静态读不懂的分支，跑起来看：

- 断在 `MessageBoxW` / `RegQueryValue` / `send` 等关键 API 上
- 配合 **Process Monitor**（文件/注册表）和 **Wireshark**（网络）先摸清行为轮廓
- 有反调试就先上 **ScyllaHide** 插件

---

## 第 3 步：交给 AI agent（这是「反代」那批新工具的价值）

### REA（取证型，需 Ghidra/IDA）

```powershell
npx rea-agents setup        # 注册 MCP 到 Claude Code / Codex / Cursor
```

然后直接问：

```
用 REA 分析 D:\path\target.exe，找出它校验注册码的那个函数，
给出伪代码和证据，并说明我漏掉了哪些还没确认的部分。
```

它返回带证据和置信度的结构化结果，不会瞎编。

### Craft Anything（重建型，Rust，有 Windows 安装包）

装好后选 **Deep 模式**（允许读程序内部），让它：

- Study：反汇编 + 字符串 + 调用图
- Build：按你的要求用 C#/Rust/Python 写一个等价实现
- Check：把新实现的行为和原程序比对，列出不一致项

适合「我不只是想懂，我还想要一个能跑的替代品」。

---

## 第 4 步：验收

- [ ] 关键函数都起了名，伪 C 能讲通主流程
- [ ] 用 x64dbg 验证过至少一条关键分支（静态推断 ≠ 实际行为）
- [ ] 重建版的输入输出与原程序一致（同输入同输出跑一遍）
- [ ] 记录未确认项，别把猜测当结论

---

## 本机现状

| 工具 | 状态 |
|---|---|
| Python 3.10 | ✅ `E:\soft\python310\python.exe` |
| JDK 21（Ghidra 需要） | ✅ `C:\Program Files\Java\jdk-21.0.11` |
| .NET SDK | ✅ `C:\Program Files\dotnet\dotnet.exe` |
| Node / npm / npx | ✅ |
| Ghidra | ❌ 未安装 |
| IDA Pro | ❌ 未安装（商业授权） |
| x64dbg / dnSpyEx | ❌ 未安装（免费，可随时装） |
