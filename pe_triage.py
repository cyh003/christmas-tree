#!/usr/bin/env python3
"""pe_triage.py - 纯标准库 PE 静态分诊，判断一个 exe 该怎么逆。

用法:
    python pe_triage.py <file.exe>            # 概览
    python pe_triage.py <file.exe> --strings  # 附字符串样本
    python pe_triage.py <file.exe> --json     # 机器可读

只读文件，不执行目标程序。
"""
import argparse
import hashlib
import json
import math
import struct
import sys
from pathlib import Path

MACHINES = {
    0x014C: "x86 (32-bit)",
    0x8664: "x64 (64-bit)",
    0x01C0: "ARM",
    0x01C4: "ARMv7 (Thumb-2)",
    0xAA64: "ARM64",
    0x0200: "IA64",
}
MAGIC = {0x10B: "PE32", 0x20B: "PE32+"}
SUBSYSTEM = {1: "Native", 2: "GUI (Windows)", 3: "Console", 9: "Windows CE", 10: "EFI"}

# 已知签名 -> (说明, 建议工具)
SIGNATURES = [
    (b"UPX0", "UPX 压缩壳", "先 upx -d 脱壳，再拖进反编译器"),
    (b"UPX1", "UPX 压缩壳", "先 upx -d 脱壳，再拖进反编译器"),
    (b".vmp0", "VMProtect 虚拟化壳", "强壳：动态脱壳(Frida/x64dbg)再分析"),
    (b".vmp1", "VMProtect 虚拟化壳", "强壳：动态脱壳(Frida/x64dbg)再分析"),
    (b"ASPack", "ASPack 壳", "带壳分析或先脱壳"),
    (b"Themida", "Themida 壳", "强壳：需专门脱壳脚本"),
    (b"MEI\x0c\x0b\x0a\x0b\x0e", "PyInstaller 打包", "pyinstxtractor 拆包 -> pycdc/pycdas 反编译 .pyc"),
    (b"PYZ-00.pyz", "PyInstaller 归档", "pyinstxtractor 拆包 -> 反编译 .pyc"),
    (b"_MEIPASS2", "PyInstaller 运行时", "pyinstxtractor 拆包 -> 反编译 .pyc"),
    (b".gopclntab", "Go 编译 (带符号表)", "go tool nm / objdump，或 strings 找 main.* 直接读逻辑"),
    (b"Go buildinf", "Go 编译", "go version -m 读取模块信息"),
    (b"rustc", "Rust 编译", "cargo-auditable 信息 + 常规反编译"),
    (b"Nuitka", "Nuitka 打包 Python", "按 C 程序逆向，但保留大量 Python 字符串线索"),
    (b"electron.asar", "Electron 应用", "解 asar 直接读 JS，无需反编译"),
    (b"node_modules\\electron", "Electron 应用", "解 asar 直接读 JS，无需反编译"),
]

STRINGS_HINT = [
    (b"libcef.dll", "CEF 内嵌浏览器 (很可能是 Electron/CEF 应用)"),
    (b"Chrome/1", "内嵌 Chromium"),
    (b"Qt6Core.dll", "Qt6 框架"),
    (b"Qt5Core.dll", "Qt5 框架"),
    (b"QApplication", "Qt 框架 (C++)"),
    (b"_ZTV", "C++ 虚表符号 (未 strip 的 C++)"),
    (b"mscoree.dll", ".NET 运行时"),
    (b"Py_Initialize", "内嵌 CPython 解释器"),
    (b"IL2CPP", "Unity IL2CPP (游戏)"),
    (b"mono-2.0", "Unity Mono (游戏)"),
    (b"GodotEngine", "Godot 引擎 (游戏)"),
    (b"UnityPlayer", "Unity 引擎 (游戏)"),
    (b"UE4Game", "Unreal Engine 4 (游戏)"),
    (b"UE5", "Unreal Engine 5 (游戏)"),
    (b"NSIS", "NSIS 安装器"),
    (b"Inno Setup", "Inno Setup 安装器"),
    (b"WiX", "MSI/WiX 安装器"),
]


def shannon(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts if c)


def u16(b, o):
    return struct.unpack_from("<H", b, o)[0]


def u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def parse(path: Path):
    raw = path.read_bytes()
    info = {
        "path": str(path),
        "size": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "md5": hashlib.md5(raw).hexdigest(),
        "errors": [],
        "sections": [],
        "imports": [],
        "signatures": [],
        "hints": [],
    }

    if raw[:2] != b"MZ":
        info["errors"].append("不是 MZ 开头，可能不是 Windows PE（或已被加壳/损坏）")
        return info, raw

    e_lfanew = u32(raw, 0x3C)
    if raw[e_lfanew:e_lfanew + 4] != b"PE\0\0":
        info["errors"].append("缺少 PE 签名")
        return info, raw

    coff = e_lfanew + 4
    machine = u16(raw, coff)
    nsec = u16(raw, coff + 2)
    timestamp = u32(raw, coff + 4)
    opt_size = u16(raw, coff + 16)
    characteristics = u16(raw, coff + 18)
    opt = coff + 20
    magic = u16(raw, opt)

    info.update({
        "machine": MACHINES.get(machine, hex(machine)),
        "format": MAGIC.get(magic, hex(magic)),
        "timestamp": timestamp,
        "is_dll": bool(characteristics & 0x2000),
        "is_dotnet": False,
        "subsystem": None,
        "entry": None,
        "image_base": None,
        "directories": {},
    })

    if magic in (0x10B, 0x20B):
        is64 = magic == 0x20B
        info["entry"] = u32(raw, opt + 16)
        info["image_base"] = struct.unpack_from("<Q" if is64 else "<I", raw, opt + 24 if not is64 else opt + 24)[0]
        info["subsystem"] = SUBSYSTEM.get(u16(raw, opt + 68), u16(raw, opt + 68))
        dd_off = opt + (112 if is64 else 96)
        ndd = u32(raw, opt + (108 if is64 else 92))
        names = ["export", "import", "resource", "exception", "certificate", "base_reloc",
                 "debug", "arch", "global_ptr", "tls", "load_config", "bound_import",
                 "iat", "delay_import", "com_descriptor"]
        for i, nm in enumerate(names):
            if i >= ndd:
                break
            rva, sz = u32(raw, dd_off + i * 8), u32(raw, dd_off + i * 8 + 4)
            if rva or sz:
                info["directories"][nm] = {"rva": rva, "size": sz}
        info["is_dotnet"] = "com_descriptor" in info["directories"]

    # 节表
    sec_off = opt + opt_size
    for i in range(min(nsec, 96)):
        off = sec_off + i * 40
        if off + 40 > len(raw):
            break
        name = raw[off:off + 8].rstrip(b"\0").decode("latin-1", "replace")
        vsize = u32(raw, off + 8)
        vaddr = u32(raw, off + 12)
        rawsize = u32(raw, off + 16)
        rawptr = u32(raw, off + 20)
        chars = u32(raw, off + 36)
        blob = raw[rawptr:rawptr + rawsize] if rawsize else b""
        info["sections"].append({
            "name": name,
            "vaddr": hex(vaddr),
            "vsize": vsize,
            "rawsize": rawsize,
            "entropy": round(shannon(blob), 2),
            "executable": bool(chars & 0x20000000),
            "writable": bool(chars & 0x80000000),
        })

    # 导入表
    imp = info["directories"].get("import")
    if imp:
        secs = []
        for i in range(min(nsec, 96)):
            off = sec_off + i * 40
            secs.append((u32(raw, off + 12), max(u32(raw, off + 16), u32(raw, off + 8)), u32(raw, off + 20)))

        def off_of(rva):
            for va, sz, ptr in secs:
                if va <= rva < va + sz:
                    return rva - va + ptr
            return None

        p = off_of(imp["rva"])
        seen = 0
        while p and p + 20 <= len(raw) and seen < 300:
            name_rva = u32(raw, p + 12)
            if not name_rva:
                break
            no = off_of(name_rva)
            if no:
                end = raw.find(b"\0", no)
                info["imports"].append(raw[no:end].decode("latin-1", "replace"))
            p += 20
            seen += 1

    # 签名与线索
    for sig, desc, action in SIGNATURES:
        if sig in raw:
            info["signatures"].append({"desc": desc, "action": action})
    for sig, desc in STRINGS_HINT:
        if sig in raw:
            info["hints"].append(desc)

    # overlay（节区之后的数据）
    last_end = max((s["rawsize"] + u32(raw, sec_off + i * 40 + 20) for i, s in
                    enumerate(info["sections"])) if info["sections"] else [0])
    info["overlay_bytes"] = max(0, len(raw) - last_end)

    return info, raw


def extract_strings(raw: bytes, minlen=6, limit=200):
    out, cur = [], bytearray()
    for b in raw:
        if 32 <= b < 127:
            cur.append(b)
        else:
            if len(cur) >= minlen:
                out.append(cur.decode("latin-1"))
                if len(out) >= limit:
                    return out
            cur = bytearray()
    if len(cur) >= minlen and len(out) < limit:
        out.append(cur.decode("latin-1"))
    return out


def verdict(info):
    """给出下一步建议"""
    v = []
    packed = [s["desc"] for s in info["signatures"] if "壳" in s["desc"] or "压缩" in s["desc"]]
    high_ent = [s["name"] for s in info["sections"] if s["entropy"] > 7.2]
    if packed:
        v.append(f"检测到壳/打包: {', '.join(packed)}")
    if high_ent:
        v.append(f"高熵节区(疑似压缩/加密): {', '.join(high_ent)}")
    if info["is_dotnet"]:
        v.append("这是 .NET 程序 -> 直接用 dnSpyEx / ILSpy 打开，几乎等同源码")
    elif info["signatures"]:
        v.append("优先按上面 signatures 的 action 走")
    else:
        v.append("原生二进制 -> Ghidra（免费）或 IDA 反编译；先跑 strings 找功能蛛丝马迹")
    if info["overlay_bytes"] > 1024:
        v.append(f"尾部有 {info['overlay_bytes']} 字节附加数据（可能是自解压/资源/安装器）")
    if info["machine"] and "x64" in str(info["machine"]):
        v.append("64 位")
    return v


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("target")
    ap.add_argument("--strings", action="store_true")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--limit", type=int, default=60)
    a = ap.parse_args()

    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

    path = Path(a.target)
    if not path.is_file():
        print(f"文件不存在: {path}", file=sys.stderr)
        return 2

    info, raw = parse(path)
    if a.json:
        print(json.dumps(info, ensure_ascii=False, indent=2))
        return 0

    print(f"文件      {info['path']}")
    print(f"大小      {info['size']:,} 字节")
    print(f"SHA256    {info['sha256']}")
    if info["errors"]:
        for e in info["errors"]:
            print(f"警告      {e}")
    print(f"架构      {info.get('machine')} / {info.get('format')} / 子系统 {info.get('subsystem')}")
    print(f"类型      {'DLL' if info.get('is_dll') else 'EXE'}"
          f"{' / .NET 托管' if info.get('is_dotnet') else ' / 原生'}")
    print(f"入口 RVA  0x{info.get('entry') or 0:x}   ImageBase {hex(info.get('image_base') or 0)}")

    if info["sections"]:
        print("\n节区:")
        print(f"  {'名称':<10}{'RVA':>10}{'原始大小':>12}{'熵':>7}  属性")
        for s in info["sections"]:
            attr = ("X" if s["executable"] else "-") + ("W" if s["writable"] else "-")
            print(f"  {s['name']:<10}{s['vaddr']:>10}{s['rawsize']:>12,}{s['entropy']:>7}  {attr}")

    if info["imports"]:
        print(f"\n导入 DLL ({len(info['imports'])}):")
        print("  " + ", ".join(info["imports"][:40]))
    else:
        print("\n导入 DLL  无（无导入表常见于加壳程序）")

    if info["signatures"]:
        print("\n命中签名:")
        for s in info["signatures"]:
            print(f"  - {s['desc']}  ->  {s['action']}")
    if info["hints"]:
        print("\n框架线索: " + ", ".join(info["hints"]))

    print("\n判断:")
    for line in verdict(info):
        print(f"  * {line}")

    if a.strings:
        ss = extract_strings(raw, limit=a.limit)
        print(f"\n字符串样本 (共提取 {len(ss)} 条):")
        for s in ss:
            print(f"  {s}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
