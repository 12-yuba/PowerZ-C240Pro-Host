#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Power-Z C240 Pro 协议解码器（协议来自 HCI 抓包实测，见 .workbuddy/memory/2026-10-21.md）

报文类型（notify，纯 ASCII，\\n 分隔）:
  T:时:分:秒 W:能量        计时/能量头行
  A:V,A                    单采样（mV, mA）
  C:V,A,V,A,...            批量采样（10 对/帧）
  B:V,A,...                第二路批量采样
  P,方向,序号,时:分:秒.毫秒,电压mV,55,字节数,hex字节...,gc,...   PD 原始报文流
"""
import re
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any

# ---------------------------------------------------------------- 遥测

NUM = r"(-?\d+)"

@dataclass
class Sample:
    v: float      # mV
    a: float      # mA
    @property
    def volt(self) -> float: return self.v / 1000.0
    @property
    def amp(self) -> float: return self.a / 1000.0
    @property
    def watt(self) -> float: return abs(self.volt * self.amp)

def parse_pairs(text: str) -> List[Sample]:
    """'5220,-38,5221,-37,' -> [Sample(5220,-38), Sample(5221,-37)]"""
    vals = [x for x in text.strip().rstrip(',').split(',') if x]
    out = []
    for i in range(0, len(vals) - 1, 2):
        try:
            out.append(Sample(float(vals[i]), float(vals[i + 1])))
        except ValueError:
            pass
    return out

RE_T = re.compile(r"T:(\d+):(\d+):(\d+)\s+W:(-?\d+)")

def parse_header(line: str) -> Optional[Dict[str, Any]]:
    m = RE_T.search(line)
    if not m:
        return None
    h, mm, ss, w = m.groups()
    return {"elapsed": f"{h}:{mm}:{ss}", "seconds": int(h) * 3600 + int(mm) * 60 + int(ss),
            "energy": int(w)}

# ---------------------------------------------------------------- PD

PD_MSG = {1: "Source_Capabilities", 2: "Request", 3: "BIST", 4: "Sink_Capabilities",
          5: "Battery_Status", 6: "Alert", 15: "Vendor_Defined", 16: "Soft_Reset"}

def _u32(bs: bytes, i: int) -> int:
    return int.from_bytes(bs[i:i + 4], "little")

def decode_fixed(v: int) -> Dict[str, Any]:
    mv = ((v >> 10) & 0x3FF) * 50
    ma = (v & 0x3FF) * 10
    return {"kind": "Fixed", "kind_raw": v >> 30, "volt": mv / 1000, "amp": ma / 1000, "raw": f"0x{v:08X}"}

def decode_apdo(v: int) -> Dict[str, Any]:
    maxv = ((v >> 17) & 0xFF) * 100
    minv = ((v >> 8) & 0xFF) * 100
    ma = (v & 0x7F) * 50
    return {"kind": "APDO(PPS)", "kind_raw": 3, "volt_min": minv / 1000, "volt_max": maxv / 1000,
            "amp": ma / 1000, "raw": f"0x{v:08X}"}

def decode_pdo(v: int) -> Dict[str, Any]:
    kind = v >> 30
    if kind == 3:
        return decode_apdo(v)
    if kind in (0, 1, 2):
        return decode_fixed(v)
    return {"kind": f"type{kind}", "kind_raw": kind, "raw": f"0x{v:08X}"}

LATENCY = ["<10ns (~1m)", "10ns-20ns (~2m)", "20ns-30ns (~3m)", "30ns-40ns (~4m)",
           "40ns-50ns (~5m)", "50ns-60ns (~6m)", "60ns-70ns (~7m)", ">70ns"]

def decode_passive_cable(v: int) -> Dict[str, Any]:
    """Passive Cable VDO（位定义来自小程序源码 53803-53815）"""
    idx = (v >> 13) & 15
    return {"raw": f"0x{v:08X}",
            "hwVersion": (v >> 28) & 15,
            "fwVersion": (v >> 24) & 15,
            "vdoVersion": f"1.{(v >> 21) & 7}",
            "latency": LATENCY[idx - 1] if 1 <= idx <= 8 else "Reserved",
            "cableTerminationType": ["VCONN not required", "VCONN required", "Reserved", "Reserved"][(v >> 11) & 3],
            "maxVbusVoltage": ["20V", "30V", "40V", "50V"][(v >> 9) & 3],
            "vbusCurrentHandlingCapability": ["Reserved", "3A", "5A", "Reserved"][(v >> 5) & 3],
            "usbHighestSpeed": ["USB 2.0", "USB 3.2 Gen1", "USB 3.2/USB4 Gen2", "USB4 Gen3", "Reserved"][7 & v],
            "eprModeCapable": bool((v >> 17) & 1)}

def decode_vdm(objs: List[int], raw: bytes = b"") -> Optional[Dict[str, Any]]:
    """VDM Discover Identity ACK → eMarker 信息（位定义来自小程序源码 53760-53830）
    注意：C240 Pro 的抓包流会在 VDO 之间插入 0x00 填充字节，故按字节对齐扫描还原真实 VDO。"""
    if len(objs) < 5:
        return None
    vh, j, cert = objs[0], objs[1], objs[2]
    if (vh & 31) != 1 or ((vh >> 6) & 3) != 1:      # 必须 command=1 且 ACK
        return None
    # 在原始字节里定位 ID Header 之后的字段：跳过插入的 0x00，试 0..3 字节对齐
    prod, cable, off = objs[3], objs[4], 0
    if raw:
        base = raw.find(bytes([j & 0xFF, (j >> 8) & 0xFF, (j >> 16) & 0xFF, (j >> 24) & 0xFF]))
        if base >= 0:
            best = None
            for cand in range(0, 4):
                p = base + 4 + 4 + cand          # ID Header + CertStat + 对齐偏移
                c = p + 4
                if c + 4 > len(raw):
                    continue
                pv = int.from_bytes(raw[p:p + 4], "little")
                cv = int.from_bytes(raw[c:c + 4], "little")
                if pv == 0:
                    continue
                # 被动线缆 VDO 的 [31:21] 为保留位必须为 0，用这条剔除 0x00 填充造成的错位
                if cv >> 21 != 0:
                    continue
                if (cv >> 5) & 3 in (0, 1, 2) and cv & 7 <= 4:
                    best = (pv, cv, cand)
                    break
            if best:
                prod, cable, off = best[0], best[1], best[2]
    ptype = (j >> 27) & 7
    info = {"svid": f"0x{(vh >> 16) & 0xFFFF:04x}",
            "vendorId": f"0x{j & 0xFFFF:04x}",
            "idHeaderRaw": f"0x{j:08X}",
            "usbHostCapable": bool((j >> 31) & 1),
            "usbDeviceCapable": bool((j >> 30) & 1),
            "modalOperationSupported": bool((j >> 26) & 1),
            "connectorType": ["Reserved", "Reserved", "USB Type-C Receptacle", "USB Type-C Plug"][(j >> 21) & 3],
            "certStat": f"0x{cert:08X}",
            "productRaw": f"0x{prod:08X}",
            "alignOffset": off,
            "usbProductId": f"0x{(prod >> 16) & 0xFFFF:04x}",
            "bcdDevice": f"0x{prod & 0xFFFF:04x}",
            "cableType": "Passive Cable" if ptype == 3 else ("Active Cable" if ptype == 4 else f"type{ptype}")}
    if ptype == 3:
        info["passiveCableVdo"] = decode_passive_cable(cable)
    return info

def decode_rdo(v: int, pdo_list: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    """解码 RDO（Request Data Object）——下游实际请求的档位。
    位定义依 PD 规范：Fixed 与 PPS(APDO) 的 RDO 布局不同。"""
    pos = (v >> 28) & 0xF                    # 请求的 PDO 序号（1 起）
    kind = None
    if pdo_list and 1 <= pos <= len(pdo_list):
        kind = pdo_list[pos - 1].get("kind")
    out = {"pdo_index": pos, "pdo_kind": kind or "unknown",
           "giveback": bool((v >> 27) & 1),
           "capability_mismatch": bool((v >> 26) & 1),
           "usb_comm_capable": bool((v >> 25) & 1),
           "no_usb_suspend": bool((v >> 24) & 1),
           "raw": f"0x{v:08X}"}
    # 关键：RDO 的位布局取决于「请求的是哪种 PDO」，必须由该 PDO 的真实类型决定。
    # 类型未知时**绝不猜测**——同时给出两种解并标记 ambiguous，界面会明确提示。
    if kind and kind.startswith("APDO"):     # PPS 请求（20mV / 50mA 单位）
        out["volt"] = ((v >> 9) & 0xFFF) * 0.02
        out["amp"] = (v & 0x1FF) * 0.05
        out["unit"] = "PPS(20mV/50mA)"
    elif kind:                                # Fixed 请求（10mA 单位）
        out["op_current"] = ((v >> 10) & 0x3FF) * 0.01
        out["max_current"] = (v & 0x3FF) * 0.01
        out["unit"] = "Fixed(10mA)"
    else:
        out["ambiguous"] = True
        out["unit"] = "unknown(需先拿到 Source_Capabilities 判定该档类型)"
        out["if_fixed"] = {"op_current": ((v >> 10) & 0x3FF) * 0.01,
                           "max_current": (v & 0x3FF) * 0.01}
        out["if_pps"] = {"volt": ((v >> 9) & 0xFFF) * 0.02,
                         "amp": (v & 0x1FF) * 0.05}
    return out


def decode_pd_message(raw: bytes, src_pdos: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    """解码一条 PD 报文：2 字节头(小端) + n 个 4 字节对象。
    注意：PD 字节从索引 0 开始（0x8F 是 PD 头低字节，不是多余前缀）。"""
    if len(raw) < 2:
        return {"error": "过短"}
    h = int.from_bytes(raw[0:2], "little")
    nobj = (h >> 12) & 0x7
    mtype = h & 0x1F
    objs = [_u32(raw, 2 + i * 4) for i in range(nobj) if 2 + (i + 1) * 4 <= len(raw)]
    out = {"header": f"0x{h:04X}", "type": mtype,
           "type_name": PD_MSG.get(mtype, f"?{mtype}"), "n_objects": nobj, "raw": raw.hex().upper()}
    if mtype == 1:  # Source_Capabilities
        out["pdos"] = [decode_pdo(v) for v in objs]
    elif mtype == 2 and objs:   # Request → RDO（下游实际请求）
        out["rdo"] = decode_rdo(objs[0], src_pdos)
        out["rdo_raw"] = objs[0]
    elif mtype == 15:  # Vendor_Defined → 可能是 VDM Discover Identity ACK
        vdm = decode_vdm(objs, raw)
        if vdm:
            out["emarker"] = vdm
        else:
            out["objects_raw"] = [f"0x{v:08X}" for v in objs]
    else:
        out["objects_raw"] = [f"0x{v:08X}" for v in objs]
    return out

# 电压后的字段是变量（实测 49/55 都出现过，疑为温度或信号质量），不能写死
RE_P = re.compile(r"^P,(\d+),(\d+),(\d+):(\d+):(\d+)\.(\d+),(-?\d+),(\d+),([0-9A-Fa-f]{2})?,?(.*)$")

def pd_note(pd: Dict[str, Any]) -> Dict[str, str]:
    """给 PD 帧生成 lapower 风格的 Note（解码摘要）与 VI（电压/电流）列"""
    t = pd.get("type_name", "?")
    note, vi = "", ""
    if "pdos" in pd:
        fixed = [f"{p['volt']:.1f}V/{p['amp']:.2f}A" for p in pd["pdos"] if p.get("kind") == "Fixed"]
        pps = [f"{p['volt_min']:.1f}-{p['volt_max']:.1f}V/{p['amp']:.2f}A"
               for p in pd["pdos"] if p.get("kind") != "Fixed"]
        note = "Fixed: " + " ".join(fixed) if fixed else ""
        if pps:
            note += (" | " if note else "") + "PPS: " + " ".join(pps)
    if "rdo" in pd:
        r = pd["rdo"]
        if r.get("ambiguous"):
            note = f"Pos:{r['pdo_index']} 类型未确认"
        elif r.get("pdo_kind", "").startswith("APDO"):
            note = f"Position:{r['pdo_index']} PPS:{r['volt']:.2f}V,{r['amp']:.2f}A"
            vi = f"{r['volt']:.3f}V/{r['amp']:.2f}A"
        else:
            note = f"Position:{r['pdo_index']} {r['op_current']:.2f}A"
    if "emarker" in pd:
        e = pd["emarker"]
        c = e.get("passiveCableVdo") or {}
        note = f"{e.get('vendorName') or e.get('vendorId', '')} {c.get('usbHighestSpeed') or ''}".strip()
    if t == "GoodCRC":
        note = "CRC 正确（协议噪声，可隐藏）"
    elif t == "Accept":
        note = "请求已被电源接受"
    elif t == "PS_RDY":
        note = "电源就绪，输出已切换"
    elif t == "Get_Sink_Cap":
        note = "电源询问下游能力"
    elif t == "EPR_Mode":
        note = "进入/退出 EPR 模式"
    elif not note and pd.get("objects_raw"):
        note = " ".join(pd["objects_raw"][:3])
    return {"note": note, "vi": vi}


def parse_p_frame(line: str, src_pdos=None) -> Optional[Dict[str, Any]]:
    """解析 P, 帧。PD 字节流中含 gc（goodCRC）分隔标记。"""
    m = RE_P.match(line.strip())
    if not m:
        return None
    direction, seq, hh, mm, ss, ms, volt, meta, nbytes, payload = m.groups()
    toks = [t.strip() for t in payload.split(',') if t.strip()]
    raw_hex, gc_at = [], None
    for t in toks:
        if t.lower() == 'gc':
            gc_at = len(raw_hex)
            continue
        if re.fullmatch(r"[0-9A-Fa-f]{2}", t):
            raw_hex.append(t.upper())
    raw = bytes(int(x, 16) for x in raw_hex)
    pd = decode_pd_message(raw, src_pdos) if len(raw) >= 2 else {"error": "无 PD 载荷"}
    nv = pd_note(pd)
    return {"kind": "pd", "direction": int(direction), "seq": int(seq), "meta": int(meta),
            "time": f"{hh}:{mm}:{ss}.{ms}", "volt": int(volt) / 1000,
            "bytes": len(raw), "raw_hex": raw_hex, "gc_at": gc_at, "pd": pd,
            "note": nv["note"], "vi": nv["vi"]}

# ---------------------------------------------------------------- 主入口

@dataclass
class Snapshot:
    volt: float = 0.0
    amp: float = 0.0
    watt: float = 0.0
    elapsed: str = ""
    energy: int = 0
    samples: List[Sample] = field(default_factory=list)     # 主通道
    samples_b: List[Sample] = field(default_factory=list)   # 第二通道
    pdos: List[Dict[str, Any]] = field(default_factory=list)
    rdo: Optional[Dict[str, Any]] = None
    rdo_raw: Optional[int] = None
    new_samples: List[Sample] = field(default_factory=list)   # 本次报文里的新采样点
    new_pd: List[Dict[str, Any]] = field(default_factory=list)  # 本次报文里的新 PD 帧
    pd_log: List[Dict[str, Any]] = field(default_factory=list)

def handle_text(text: str, snap: Snapshot) -> Snapshot:
    """处理一帧 notify（可能含多行），更新快照"""
    snap.new_samples = []
    snap.new_pd = []
    for line in text.split('\n'):
        line = line.strip()
        if not line:
            continue
        head = parse_header(line)
        if head:
            snap.elapsed, snap.energy = head["elapsed"], head["energy"]
            continue
        if line.startswith('P,'):
            pf = parse_p_frame(line, snap.pdos)
            if pf:
                snap.pd_log.append(pf)
                snap.new_pd.append(pf)          # 供会话记录/导出使用
                if len(snap.pd_log) > 2000:
                    snap.pd_log = snap.pd_log[-2000:]
                if pf.get("pd", {}).get("rdo"):
                    snap.rdo = pf["pd"]["rdo"]
                    snap.rdo_raw = pf["pd"].get("rdo_raw")
                pdos = pf.get("pd", {}).get("pdos")
                if pdos:
                    snap.pdos = pdos     # 最新一次 Source_Capabilities
                    # RDO 常常先于 Source_Capabilities 到达，那时类型未知；PDO 一到就用
                    # 权威类型重算（协议依据，不是猜测），避免界面长期显示"类型未知"
                    if snap.rdo_raw is not None:
                        snap.rdo = decode_rdo(snap.rdo_raw, snap.pdos)
                continue
        m = re.match(r"^([ABC]):(.*)$", line)
        if m:
            ch, payload = m.group(1), m.group(2)
            pairs = parse_pairs(payload)
            if not pairs:
                continue
            if ch == 'B':
                snap.samples_b.extend(pairs)
                snap.samples_b = snap.samples_b[-600:]
            else:
                snap.samples.extend(pairs)
                snap.samples = snap.samples[-4000:]
                snap.new_samples = pairs          # 一帧 10 对全给前端，曲线才会真的"变快"
                last = pairs[-1]
                snap.volt, snap.amp = last.volt, last.amp
                snap.watt = last.watt
    return snap
