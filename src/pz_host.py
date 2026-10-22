#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Power-Z C240 Pro PC 上位机（Windows）

设计要点（量产兼容）：
  * 设备识别**一律走 GATT 服务 UUID**，绝不依赖 MAC / 蓝牙名
  * 同名产品（不同 MAC）自动识别；支持用户从扫描列表手选任意设备后校验
用法:
  python pz_host.py              # 启动：扫描 -> 连接 -> 本地网页 http://127.0.0.1:31416/
  python pz_host.py scan         # 只扫描
"""
import asyncio, json, sys, os, threading, time, re
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from typing import Optional, List

from bleak import BleakScanner, BleakClient
from bleak.backends.characteristic import BleakGATTCharacteristic

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pz_protocol import Snapshot, handle_text   # noqa: E402

# ---- 协议常量（来自 HCI 实测）----
SERVICE_UUID = "0000af00-0000-1000-8000-00805f9b34fb"
DATA_CHAR_PREFIX = "0000af01"      # 遥测 / PD 报文通知
CTRL_CHAR_PREFIX = "0000af02"      # 命令写入 + ACK 通知
CMD_HEADER = 0xC4
CMD_SET_RATE = b"11"
CMD_RATE = {"1": "1SPS", "2": "10SPS", "3": "20SPS"}
# 冻结(PyInstaller)环境下：资源在 sys._MEIPASS，日志写在 exe 旁边
if getattr(sys, "frozen", False):
    BASE_DIR = os.path.dirname(sys.executable)
    RES_DIR = getattr(sys, "_MEIPASS", BASE_DIR)
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    RES_DIR = BASE_DIR
WEB_DIR = os.path.join(RES_DIR, "web")
LOG_PATH = os.path.join(BASE_DIR, "pz_raw.log")
LOG_PATH_FILE = os.path.join(BASE_DIR, "pz_host.log")
PORT = 31416

snap = Snapshot()

# ============ 会话记录（导出用）============
# 时间轴基准：time.monotonic()（不受系统校时跳变影响），起点记 0
SESSION = {
    "t0": None,          # monotonic 起点
    "rdo_wall": None,    # 最后一次收到 RDO 的本地时刻
    "wall0": None,       # 对应的本地绝对时间
    "last_t": None,      # 上一帧到达的 monotonic 时间（用于帧内插值）
    "samples": [],       # [相对秒, 本地时间, 设备T, 电压V, 电流A, 功率W]
    "pd": [],            # [相对秒, 本地时间, 方向, 序号, 类型, 对象数, 原始hex]
    "cap": 500000,       # 上限约 7 小时 @20SPS
}


def _session_start(now):
    if SESSION["t0"] is None:
        SESSION["t0"] = now
        SESSION["wall0"] = time.time()
        SESSION["last_t"] = now


def record_samples(points, dev_t):
    """points: [(mV, mA), ...]，把一帧内的点按到达间隔均匀插值，得到 0 起的连续时间轴"""
    now = time.monotonic()
    _session_start(now)
    prev = SESSION["last_t"] or now
    k = max(len(points), 1)
    span = now - prev
    # 首帧没有前一帧可插值：按 20SPS 标称 50ms 间距铺开，避免 10 个点全挤在 0 秒
    if span <= 0:
        span = k * 0.05
    wall = time.strftime("%Y-%m-%d %H:%M:%S")
    for i, (mv, ma) in enumerate(points):
        rel = (prev - SESSION["t0"]) + span * (i + 1) / k
        v, a = mv / 1000.0, ma / 1000.0
        # 电流按仪器习惯记绝对值，方向单独一列（原始符号不丢）
        SESSION["samples"].append((round(rel, 3), wall, dev_t, round(v, 4),
                                   round(abs(a), 4), round(abs(v * a), 4),
                                   "正向" if a >= 0 else "反向"))
    SESSION["last_t"] = now
    if len(SESSION["samples"]) > SESSION["cap"]:
        drop = len(SESSION["samples"]) - SESSION["cap"]
        del SESSION["samples"][:drop]


def record_pd(frames):
    now = time.monotonic()
    _session_start(now)
    wall = time.strftime("%Y-%m-%d %H:%M:%S")
    rel = round(now - SESSION["t0"], 3)
    for f in frames:
        pd = f.get("pd", {})
        SESSION["pd"].append((rel, wall,
                              "RX" if f.get("direction") == 1 else "TX",
                              f.get("seq"), pd.get("type_name", "?"),
                              pd.get("n_objects", 0), pd.get("raw", "")))
    if len(SESSION["pd"]) > 20000:
        del SESSION["pd"][:-20000]
state = {"connected": False, "device": "", "rssi": None, "rate": "3",
         "log": [], "services": []}
ui_clients: List[asyncio.Queue] = []


def log(msg: str):
    line = f"{time.strftime('%H:%M:%S')} {msg}"
    state["log"].append(line)
    state["log"] = state["log"][-200:]
    try:
        if sys.stdout is not None:                 # 无控制台模式下 stdout 可能为 None
            print(line, flush=True)
    except Exception:
        pass
    try:                                            # 同时落盘，便于无界面模式排查
        with open(LOG_PATH_FILE, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
    except Exception:
        pass


# ----------------------------------------------------------------- 扫描
async def scan(seconds: float = 8.0) -> list:
    found = {}

    def cb(dev, adv):
        found[dev.address] = {"address": dev.address,
                              "name": dev.name or adv.local_name or "",
                              "rssi": adv.rssi,
                              "uuids": [u.lower() for u in adv.service_uuids]}
    sc = BleakScanner(detection_callback=cb)
    await sc.start(); await asyncio.sleep(seconds); await sc.stop()
    return sorted(found.values(), key=lambda d: (SERVICE_UUID not in d["uuids"], -(d["rssi"] or -99)))


def is_target(info: dict) -> bool:
    return SERVICE_UUID in info["uuids"]


# ----------------------------------------------------------------- 连接
class Device:
    def __init__(self, address: str):
        self.address = address
        self.client = BleakClient(address, disconnected_callback=self._on_disconnected)
        self.data_char: Optional[BleakGATTCharacteristic] = None
        self.ctrl_char: Optional[BleakGATTCharacteristic] = None

    def _on_disconnected(self, _client):
        state["connected"] = False
        state["disconnects"] = state.get("disconnects", 0) + 1
        log(f"!! 设备断开 #{state['disconnects']}（{self.address}）")

    async def connect(self):
        await self.client.connect()
        # 用 GATT 服务确认这是 Power-Z（不靠 MAC / 名字）
        svcs = self.client.services
        target = None
        for s in svcs:
            if s.uuid.lower().startswith(SERVICE_UUID[:8]):
                target = s
                break
        if target is None:
            raise RuntimeError("该设备没有 AF00 服务，不是 Power-Z")
        state["services"] = [f"{s.uuid}" for s in svcs]
        for c in target.characteristics:
            u = c.uuid.lower()
            if u.startswith(CTRL_CHAR_PREFIX):
                self.ctrl_char = c
            elif u.startswith(DATA_CHAR_PREFIX):
                self.data_char = c
        if self.data_char is None and self.ctrl_char is None:
            raise RuntimeError("未找到 AF01/AF02 特征")
        if self.data_char is None:
            self.data_char = self.ctrl_char
        if self.ctrl_char is None:
            self.ctrl_char = self.data_char
        # 小程序两个特征都订阅：遥测在 AF01，PD 报文流/命令 ACK 在 AF02
        if self.data_char is not None:
            await self.client.start_notify(self.data_char, self._on_notify)
        if self.ctrl_char is not None and self.ctrl_char.uuid != self.data_char.uuid:
            await self.client.start_notify(self.ctrl_char, self._on_notify)
        state["reconnects"] = state.get("reconnects", 0) + 1
        log(f">> 已连接 #{state['reconnects']} {self.address}，数据={self.data_char.uuid[:8]} 控制={self.ctrl_char.uuid[:8]}")

    def _on_notify(self, _ch, data: bytearray):
        raw = bytes(data)
        # ① 先做原始落盘 + ACK 判定（0xC5 不是 ASCII，必须在 decode 之前处理）
        with open(LOG_PATH, "a", encoding="utf-8") as fh:
            fh.write(f"{time.strftime('%H:%M:%S')}\t{raw.hex().upper()}\t"
                     f"{raw.decode('ascii', 'ignore')[:200]!r}\n")
        # 设备对命令的应答是【单字节 0xC5】（实测），兼容 00 C5 双字节形式
        if raw == b"\xc5" or raw == b"\x00\xc5":
            state["ack"] = time.time()
            return
        # ② 再走文本协议解析
        text = raw.decode("ascii", "ignore")
        if not text:
            return
        handle_text(text, snap)
        # 写入会话记录（导出用）
        try:
            if snap.new_samples:
                record_samples([(x.v, x.a) for x in snap.new_samples], snap.elapsed)
            if getattr(snap, "new_pd", None):
                record_pd(snap.new_pd)
        except Exception as e:
            log(f"记录异常: {e}")
        # 整批推送：20SPS 时一帧含 10 个点，只推最后一个会让曲线速度打 1/10
        if snap.new_samples:
            push_event({"t": "samples",
                        "pts": [[s.v, s.a] for s in snap.new_samples],
                        "elapsed": snap.elapsed, "energy": snap.energy})

    async def raw_cmd(self, hexstr: str):
        """下发任意帧（hex 字符串），返回是否在 400ms 内收到 ACK(00 C5)"""
        payload = bytes.fromhex(hexstr.replace(' ', ''))
        before = state.get("ack", 0)
        await self.client.write_gatt_char(self.ctrl_char, payload, response=True)
        for _ in range(20):
            await asyncio.sleep(0.02)
            if state.get("ack", 0) != before:
                return True
        return False

    async def set_rate(self, key: str):
        payload = bytes([CMD_HEADER]) + CMD_SET_RATE + key.encode()
        await self.client.write_gatt_char(self.ctrl_char, payload, response=True)
        state["rate"] = key
        log(f"下发采样率指令 0xC4 '11{key}' -> {CMD_RATE.get(key, key)}")

    async def disconnect(self):
        try:
            await self.client.disconnect()
        except Exception:
            pass


dev: Optional[Device] = None
LAST_ADDR = [None]


def push_event(obj):
    for q in list(ui_clients):
        try:
            q.put_nowait(obj)
        except Exception:
            pass


# ----------------------------------------------------------------- HTTP
EXPORT_DIR = os.path.join(BASE_DIR, "export")


def build_xlsx_samples(path):
    """path 可以是路径或文件对象（BytesIO）"""
    from openpyxl import Workbook
    wb = Workbook(write_only=True)
    ws = wb.create_sheet("采样明细")
    ws.append(["相对时间(s)", "本地时间", "设备计时", "电压(V)", "电流(A)", "功率(W)", "电流方向"])
    for row in SESSION["samples"]:
        ws.append(list(row))
    wb.save(path)


def build_xlsx_pd(path):
    from openpyxl import Workbook
    wb = Workbook(write_only=True)
    ws = wb.create_sheet("PD报文")
    ws.append(["相对时间(s)", "本地时间", "方向", "序号", "消息类型", "对象数", "原始字节"])
    if SESSION["pd"]:
        for row in SESSION["pd"]:
            ws.append(list(row))
    else:
        ws.append(["-", "-", "-", "-", "本次会话还没有捕获到 PD 报文",
                   "-", "PD 报文只在插拔/重新协商时出现，插拔一次即可抓到"])
    ws2 = wb.create_sheet("电源能力与线缆")
    ws2.append(["项目", "内容"])
    for p in snap.pdos:
        if p.get("kind") == "Fixed":
            ws2.append([f"Fixed {p['volt']:.2f}V", f"{p['amp']:.2f}A"])
        else:
            ws2.append([f"APDO {p.get('volt_min')}-{p.get('volt_max')}V", f"{p['amp']:.2f}A"])
    if snap.rdo:
        r = snap.rdo
        ws2.append(["实际请求 RDO", f"PDO#{r.get('pdo_index')} {r.get('pdo_kind')} {r.get('unit')}"])
    for pd in reversed(snap.pd_log):
        em = pd.get("pd", {}).get("emarker")
        if em:
            c = em.get("passiveCableVdo") or {}
            ws2.append(["eMarker 厂商 VID", em.get("vendorId", "")])
            ws2.append(["eMarker 产品", em.get("productRaw", "")])
            ws2.append(["eMarker 线缆 VDO", c.get("raw", "")])
            ws2.append(["eMarker 供电能力", f"{c.get('maxVbusVoltage','')} {c.get('vbusCurrentHandlingCapacity','') or c.get('vbusCurrentHandlingCapability','')}"])
            break
    wb.save(path)

def _win_hwnd():
    """按本进程 PID 枚举可见顶层窗口，拿到真实句柄（比按标题查找可靠）"""
    import ctypes, ctypes.wintypes
    u = ctypes.windll.user32
    pid = os.getpid()
    found = []

    @ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.wintypes.HWND, ctypes.wintypes.LPARAM)
    def cb(h, _):
        p = ctypes.wintypes.DWORD()
        u.GetWindowThreadProcessId(h, ctypes.byref(p))
        if p.value == pid and u.IsWindowVisible(h):
            found.append(h)
        return True

    try:
        u.EnumWindows(cb, 0)
    except Exception:
        pass
    return found[0] if found else None


def _win_rect():
    """真实窗口矩形（物理像素）"""
    import ctypes, ctypes.wintypes
    h = _win_hwnd()
    if not h:
        return None
    r = ctypes.wintypes.RECT()
    ctypes.windll.user32.GetWindowRect(h, ctypes.byref(r))
    return (r.left, r.top, r.right - r.left, r.bottom - r.top)


def _win_setpos(x, y, w, h):
    """SetWindowPos：物理像素、含非客户区的整窗尺寸，一步到位"""
    import ctypes
    u = ctypes.windll.user32
    h = _win_hwnd()
    if not h:
        return False
    SWP_NOZORDER, SWP_NOACTIVATE = 0x0004, 0x0010
    return bool(u.SetWindowPos(h, 0, int(x), int(y), int(w), int(h),
                               SWP_NOZORDER | SWP_NOACTIVATE))


EDGE_PATHS = [
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
]


def _has_webview2_child() -> bool:
    """看有没有 msedgewebview2.exe 子进程，用于判断原生窗口是否真的起来了"""
    try:
        import subprocess
        out = subprocess.run(["tasklist", "/FI", "IMAGENAME eq msedgewebview2.exe"],
                             capture_output=True, text=True, timeout=6).stdout
        return "msedgewebview2.exe" in out
    except Exception:
        return False


def _edge_app(url: str) -> bool:
    """Edge 应用模式：独立窗口，无标签页无地址栏"""
    import subprocess
    for p in EDGE_PATHS:
        if os.path.exists(p):
            try:
                subprocess.Popen([p, f"--app={url}", "--window-size=1300,880"])
                log("已用 Edge 应用窗口打开界面")
                return True
            except Exception:
                pass
    return False


class WinApi:
    """暴露给网页的窗口控制（自绘标题栏用）"""

    def _w(self):
        import webview
        return webview.windows[0] if webview.windows else None

    def win_min(self):
        w = self._w()
        if w:
            w.minimize()
        return True

    def win_close(self):
        """关窗必须彻底退出：webview.start() 在 destroy() 后不保证返回，
        若不主动 os._exit，进程会残留并一直占着单实例互斥体。"""
        w = self._w()
        def _kill():
            try:
                if w:
                    w.destroy()
            except Exception:
                pass
            os._exit(0)
        threading.Timer(0.08, _kill).start()   # 先让窗口动画结束，再强杀进程
        return True

    # ---- 工作区（扣除任务栏后的可用区域）----
    @staticmethod
    def _work_area():
        import ctypes
        r = ctypes.wintypes.RECT()
        ctypes.windll.user32.SystemParametersInfoW(0x0030, 0, ctypes.byref(r), 0)  # SPI_GETWORKAREA
        return r.left, r.top, r.right - r.left, r.bottom - r.top

    def win_resize(self, w, h):
        """w/h 为物理像素"""
        w, h = max(int(w), 900), max(int(h), 600)
        r = _win_rect()
        x, y = (r[0], r[1]) if r else (100, 100)
        self._geom(self._w(), x, y, w, h)
        return True

    def win_size(self):
        """当前窗口物理尺寸（供前端缩放计算用）"""
        r = _win_rect()
        return [int(r[2]), int(r[3])] if r else [1300, 880]

    def win_drag_start(self):
        """原生窗口拖动：在 Python 里跑移动循环，直到左键松开。

        不用 WM_NCLBUTTONDOWN（会被 Chromium 的窗口过程吞掉），也不用逐事件
        JS 回调（pythonnet 桥接有延迟，手感黏）。这里直接读光标位置、
        用 SetWindowPos(SWP_NOSIZE) 移动窗口：
          · 循环频率 ~120Hz，跟手性等同于系统拖动
          · SWP_NOSIZE 不改变尺寸，绕开 Chromium 对无边框窗口的最小高度钳制
          · 拖到屏幕顶部=最大化，左右边缘=半屏，均按工作区计算不遮任务栏
        本调用阻塞到拖动结束，前端据此撤掉防误触覆盖层。
        """
        import ctypes, time
        u = ctypes.windll.user32
        h = _win_hwnd()
        if not h:
            return False

        class POINT(ctypes.Structure):
            _fields_ = [('x', ctypes.c_long), ('y', ctypes.c_long)]

        SWP_NOSIZE, SWP_NOZORDER, SWP_NOACTIVATE = 0x0001, 0x0004, 0x0010
        r0 = _win_rect()
        if not r0:
            return False
        wx, wy, ww, wh = r0

        pt = POINT()
        u.GetCursorPos(ctypes.byref(pt))
        sx, sy = pt.x, pt.y
        scr = self.screen_rect()                 # [0,0,W,H] 物理
        ax, ay, aw, ah = self._work_area()

        # 收鼠标捕获：窗外移动也能跟踪
        try:
            u.SetCapture(h)
        except Exception:
            pass

        snapped = None
        t0 = time.time()
        try:
            while True:
                if not (u.GetAsyncKeyState(0x01) & 0x8000):    # 左键松开 → 结束
                    break
                if time.time() - t0 > 60:                      # 兜底超时
                    break
                u.GetCursorPos(ctypes.byref(pt))

                # 边缘吸附判定（屏幕绝对坐标）
                mode = None
                if pt.y <= ay + 1:
                    mode = 'max'
                elif pt.x <= ax + 1:
                    mode = 'left'
                elif pt.x >= ax + aw - 1:
                    mode = 'right'

                if mode and mode != snapped:
                    snapped = mode
                    if mode == 'max':
                        self._clamp(self._w(), ax, ay, aw, ah)
                    elif mode == 'left':
                        self._clamp(self._w(), ax, ay, aw // 2, ah)
                    else:
                        self._clamp(self._w(), ax + aw - aw // 2, ay, aw // 2, ah)
                    break                              # 吸附后结束本次拖动
                if mode:
                    break

                nx, ny = wx + (pt.x - sx), wy + (pt.y - sy)
                # 限制不要拖出工作区太远（留 60px 可抓回）
                nx = max(ax - ww + 60, min(nx, ax + aw - 60))
                ny = max(ay, min(ny, ay + ah - 60))
                u.SetWindowPos(h, 0, int(nx), int(ny), 0, 0,
                               SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE)
                time.sleep(0.008)                      # ~120Hz
        finally:
            try:
                u.ReleaseCapture()
            except Exception:
                pass
        return True

    # ---------------- 导出：原生"另存为"对话框 ----------------
    def save_file_dialog(self, default_name="PowerZ_数据.xlsx"):
        """弹出 Windows 原生保存对话框（资源管理器那个"另存为"）。

        WebView2 里用 <a download> 弹不出系统保存框，必须走 comdlg32。
        返回用户选的完整路径；点取消返回 None。
        """
        import ctypes
        from ctypes import wintypes

        class OPENFILENAMEW(ctypes.Structure):
            _fields_ = [
                ('lStructSize', wintypes.DWORD),
                ('hwndOwner', wintypes.HWND),
                ('hInstance', wintypes.HINSTANCE),
                ('lpstrFilter', wintypes.LPCWSTR),
                ('lpstrCustomFilter', wintypes.LPWSTR),
                ('nMaxCustFilter', wintypes.DWORD),
                ('nFilterIndex', wintypes.DWORD),
                ('lpstrFile', wintypes.LPWSTR),
                ('nMaxFile', wintypes.DWORD),
                ('lpstrFileTitle', wintypes.LPWSTR),
                ('nMaxFileTitle', wintypes.DWORD),
                ('lpstrInitialDir', wintypes.LPCWSTR),
                ('lpstrTitle', wintypes.LPCWSTR),
                ('Flags', wintypes.DWORD),
                ('nFileOffset', wintypes.WORD),
                ('nFileExtension', wintypes.WORD),
                ('lpstrDefExt', wintypes.LPCWSTR),
                ('lCustData', wintypes.LPARAM),
                ('lpfnHook', wintypes.LPARAM),
                ('lpTemplateName', wintypes.LPCWSTR),
            ]

        buf = ctypes.create_unicode_buffer(default_name, 1024)
        ofn = OPENFILENAMEW()
        ofn.lStructSize = ctypes.sizeof(OPENFILENAMEW)
        ofn.lpstrFilter = "Excel 文件 (*.xlsx)\0*.xlsx\0所有文件 (*.*)\0*.*\0\0"
        ofn.lpstrFile = ctypes.cast(buf, wintypes.LPWSTR)
        ofn.nMaxFile = 1024
        ofn.lpstrTitle = "保存数据"
        ofn.lpstrDefExt = "xlsx"
        # OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR
        ofn.Flags = 0x00000002 | 0x00000800 | 0x00000008
        hwnd = _win_hwnd()
        ofn.hwndOwner = hwnd or None
        try:
            if ctypes.windll.comdlg32.GetSaveFileNameW(ctypes.byref(ofn)):
                return buf.value
        except Exception:
            pass
        return None

    def export_to(self, path, kind="samples"):
        """把数据直接写到用户选的路径。kind: samples / pd"""
        try:
            if kind == "samples":
                build_xlsx_samples(path)
            else:
                build_xlsx_pd(path)
            size = os.path.getsize(path)
            log(f"已保存 {os.path.basename(path)}（{size//1024} KB）")
            return {"ok": True, "path": path, "size": size}
        except Exception as e:
            log(f"保存失败: {e}")
            return {"ok": False, "error": str(e)}

    def screen_rect(self):
        """主屏物理边界（供前端判断是否拖到屏幕边缘）"""
        import ctypes
        u = ctypes.windll.user32
        return [0, 0, u.GetSystemMetrics(0), u.GetSystemMetrics(1)]

    def mouse_down(self):
        """左键是否仍按住。轮询这个状态作为兜底：
           WebView 在窗口外松手时可能收不到 mouseup，靠它保证拖拽一定结束。"""
        import ctypes
        return bool(ctypes.windll.user32.GetAsyncKeyState(0x01) & 0x8000)

    def _dpi_scale(self):
        """当前窗口的 DPI 缩放系数（物理/逻辑）。实测 175% 缩放下为 1.75。"""
        import ctypes
        h = _win_hwnd()
        if h:
            try:
                dpi = ctypes.windll.user32.GetDpiForWindow(h)
                if dpi:
                    return dpi / 96.0
            except Exception:
                pass
        return 1.0

    def _geom(self, win, x, y, w, h):
        """按【物理像素】设置窗口几何。

        pywebview 的 move()/resize() 吃的是逻辑像素（实测 move(100,100) 落到 175x175），
        而 GetWindowRect / screenX 都是物理像素。这里统一在内部换算，
        避免两种单位混用导致 175% 缩放下窗口超出屏幕、遮住任务栏。
        """
        if not win:
            return
        sc = self._dpi_scale()
        try:
            win.move(int(x) / sc, int(y) / sc)
            win.resize(int(w) / sc, int(h) / sc)
        except Exception:
            pass

    def _clamp(self, win, x, y, w, h):
        """把窗口限制在工作区内（物理像素），绝不越界/遮任务栏"""
        ax, ay, aw, ah = self._work_area()
        w = max(320, min(int(w), aw))
        h = max(240, min(int(h), ah))
        x = max(ax, min(int(x), ax + aw - w))
        y = max(ay, min(int(y), ay + ah - h))
        self._geom(win, x, y, w, h)

    def win_max(self):
        """按工作区最大化（不遮任务栏），再点一次还原"""
        win = self._w()
        if not win:
            return True
        try:
            x, y, w, h = self._work_area()
            if abs(win.width - w) < 8 and abs(win.height - h) < 8:
                self._clamp(win, x + (w - 1300) // 2, y + (h - 880) // 2, 1300, 880)
            else:
                self._clamp(win, x, y, w, h)
        except Exception:
            win.toggle_fullscreen()
        return True

    def win_snap(self, d):
        """Aero Snap：max / left / right，均按工作区计算"""
        win = self._w()
        if not win:
            return True
        try:
            x, y, w, h = self._work_area()
            if d == 'max':
                self._clamp(win, x, y, w, h)
            elif d == 'left':
                self._clamp(win, x, y, w // 2, h)
            elif d == 'right':
                self._clamp(win, x + w - w // 2, y, w // 2, h)
            elif d == 'restore':
                self._clamp(win, x + (w - 1300) // 2, y + (h - 880) // 2, 1300, 880)
        except Exception:
            pass
        return True

    def win_pos(self):
        """当前窗口物理坐标"""
        r = _win_rect()
        if r:
            return [int(r[0]), int(r[1])]
        w = self._w()
        try:
            sc = self._dpi_scale()
            return [int(w.x * sc), int(w.y * sc)]
        except Exception:
            return [0, 0]

    def win_move(self, x, y):
        """只移动、不改变尺寸（拖动手感的关键：resize 会引发抖动）"""
        win = self._w()
        if not win:
            return True
        sc = self._dpi_scale()
        try:
            win.move(int(x) / sc, int(y) / sc)
        except Exception:
            pass
        return True


def set_dpi_aware() -> bool:
    """声明 Per-Monitor V2 DPI 感知。

    不声明的话进程是"DPI 不感知"，SPI_GETWORKAREA / GetSystemMetrics 返回的是
    **逻辑像素**（已按缩放换算），而 pywebview 的 resize() 用的是**物理像素**。
    175% 缩放下两者差 1.75 倍，最大化时窗口会被放到 2560x1515，
    直接盖住任务栏并超出屏幕（实测复现）。
    """
    try:
        import ctypes
        # DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2 = (HANDLE)-4
        try:
            if ctypes.windll.user32.SetProcessDpiAwarenessContext(ctypes.c_void_p(-4)):
                return True
        except Exception:
            pass
        try:                                    # Win8.1+: shcore.SetProcessDpiAwareness
            ctypes.windll.shcore.SetProcessDpiAwareness(2)
            return True
        except Exception:
            pass
        try:                                    # Vista+: user32.SetProcessDPIAware
            ctypes.windll.user32.SetProcessDPIAware()
            return True
        except Exception:
            pass
    except Exception:
        pass
    return False


def wait_port(timeout=15.0):
    import socket
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            with socket.create_connection(("127.0.0.1", PORT), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.2)
    return False


def ensure_single_instance() -> bool:
    """防止多开：以 31416 端口是否被占用为准。

    用端口而不是按 exe 路径的互斥体——单文件版和目录版是同一款程序，
    必须只跑一个（两个都跑会抢端口，数据会时有时无）。
    """
    if "--allow-multi" in sys.argv:
        return True
    import socket
    s = socket.socket()
    try:                                   # 不带 SO_REUSEADDR：被占用就一定绑不上
        s.bind(("127.0.0.1", PORT))
        s.close()
        return True
    except OSError:
        return False
    finally:
        try:
            s.close()
        except Exception:
            pass


def run_ui():
    """在主线程跑界面：pywebview 原生窗口 → Edge 应用窗口 → 默认浏览器"""
    url = f"http://127.0.0.1:{PORT}/"
    wait_port()

    headless = ("--no-browser" in sys.argv) or ("--no-window" in sys.argv)
    if headless:
        while True:
            time.sleep(1)

    if "--browser" in sys.argv:
        import webbrowser
        webbrowser.open(url)
        while True:
            time.sleep(1)

    try:
        import webview
        api = WinApi()
        webview.create_window("Power-Z C240 Pro 上位机", url,
                              width=1300, height=880, min_size=(960, 640),
                              background_color="#f3f3f3",
                              frameless=True, easy_drag=False, js_api=api)
        log("原生窗口已创建（无边框自绘标题栏）")
        webview.start()          # 阻塞直到窗口关闭
        log("窗口已关闭，程序退出")
        os._exit(0)
    except Exception as e:
        log(f"原生窗口不可用: {e}")

    if not _edge_app(url):
        import webbrowser
        webbrowser.open(url)
    while True:
        time.sleep(1)



class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="application/json; charset=utf-8"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        p = self.path.split("?")[0]
        if p in ("/", "/index.html"):
            data = open(os.path.join(WEB_DIR, "index.html"), "rb").read()
            self._send(200, data, "text/html; charset=utf-8")
        elif p == "/events":
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            q: asyncio.Queue = queue_for_loop()
            try:
                while True:
                    ev = loop_queue_get(q)
                    if ev is None:
                        break
                    self.wfile.write(f"data: {json.dumps(ev, ensure_ascii=False)}\n\n".encode())
                    self.wfile.flush()
            except Exception:
                pass
            finally:
                if q in ui_clients:
                    ui_clients.remove(q)
        elif p == "/api/state":
            body = {"connected": state["connected"], "device": state["device"],
                    "rssi": state["rssi"], "rate": state["rate"],
                    "volt": snap.volt, "amp": snap.amp, "watt": snap.watt,
                    "elapsed": snap.elapsed, "energy": snap.energy,
                    "pdos": snap.pdos, "emarker": latest_emarker(), "rdo": snap.rdo,
                    "pd_count": len(snap.pd_log),
                    "pd_recent": [{"seq": x["seq"], "dir": x["direction"],
                                   "sop": x["pd"].get("sop", 1),
                                   "type": x["pd"].get("type_name", "?"),
                                   "n": x["pd"].get("n_objects", 0),
                                   "hex": x["pd"].get("raw", "")[:80],
                                   "t": x.get("time", ""),
                                   "note": x.get("note", ""),
                                   "vi": x.get("vi", "")}
                                  for x in snap.pd_log[-200:]],
                    "sess_points": len(SESSION["samples"]),
                    "sess_sec": round((time.monotonic() - SESSION["t0"]), 1)
                               if SESSION["t0"] else 0,
                    "rdo_age": round(time.time() - SESSION["rdo_wall"], 1)
                              if SESSION.get("rdo_wall") else None,
                    "log": state["log"][-40:]}
            self._send(200, json.dumps(body, ensure_ascii=False).encode())
        elif p in ("/api/export/samples.xlsx", "/api/export/pd.xlsx"):
            # 只在内存生成，直接弹浏览器保存框（不再服务端落盘，避免一份数据两个文件）
            which = "samples" if "samples" in p else "pd"
            try:
                import io
                buf = io.BytesIO()
                if which == "samples":
                    build_xlsx_samples(buf)
                    fn = f"PowerZ_曲线数据_{time.strftime('%Y%m%d_%H%M%S')}.xlsx"
                else:
                    build_xlsx_pd(buf)
                    fn = f"PowerZ_PD报文_{time.strftime('%Y%m%d_%H%M%S')}.xlsx"
                body = buf.getvalue()
                from urllib.parse import quote
                self.send_response(200)
                self.send_header("Content-Type",
                                 "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
                self.send_header("Content-Disposition",
                                 "attachment; filename*=UTF-8''" + quote(fn))
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Access-Control-Allow-Origin", "*")
                self.send_header("Access-Control-Expose-Headers", "Content-Disposition")
                self.end_headers()
                self.wfile.write(body)
                log(f"导出 {fn}（{len(body)//1024} KB）")
            except Exception as e:
                log(f"导出失败: {e}")
                self._send(500, json.dumps({"ok": False, "error": str(e)}, ensure_ascii=False).encode())
        elif p == "/api/scan":
            fut = asyncio.run_coroutine_threadsafe(scan(8.0), LOOP)
            try:
                res = fut.result(15)
            except Exception as e:
                res = {"error": str(e)}
            self._send(200, json.dumps(res, ensure_ascii=False).encode())
        else:
            fn = os.path.join(WEB_DIR, os.path.basename(p))
            if os.path.isfile(fn):
                self._send(200, open(fn, "rb").read(),
                           "application/javascript; charset=utf-8" if fn.endswith(".js")
                           else "application/octet-stream")
            else:
                self._send(404, b"not found", "text/plain")

    def do_POST(self):
        p = self.path.split("?")[0]
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n) if n else b"{}"
        try:
            body = json.loads(raw or b"{}")
        except Exception:
            body = {}
        if p == "/api/connect":
            addr = body.get("address")
            fut = asyncio.run_coroutine_threadsafe(do_connect(addr), LOOP)
            try:
                fut.result(25)
            except Exception as e:
                self._send(200, json.dumps({"ok": False, "error": str(e)}, ensure_ascii=False).encode())
                return
            self._send(200, json.dumps({"ok": state["connected"]}, ensure_ascii=False).encode())
        elif p == "/api/raw":
            hexstr = str(body.get("hex", "")).strip()
            if not (dev and state["connected"] and hexstr):
                self._send(200, json.dumps({"ok": False, "error": "未连接或参数为空"}, ensure_ascii=False).encode())
                return
            fut = asyncio.run_coroutine_threadsafe(dev.raw_cmd(hexstr), LOOP)
            try:
                ack = fut.result(5)
            except Exception as e:
                self._send(200, json.dumps({"ok": False, "error": str(e)}, ensure_ascii=False).encode())
                return
            log(f"RAW 下发 {hexstr.upper()} -> ACK={ack}")
            self._send(200, json.dumps({"ok": True, "ack": ack}, ensure_ascii=False).encode())
        elif p == "/api/rate":
            key = str(body.get("rate", "3"))
            if dev and state["connected"]:
                asyncio.run_coroutine_threadsafe(dev.set_rate(key), LOOP)
            self._send(200, json.dumps({"ok": True}, ensure_ascii=False).encode())
        else:
            self._send(404, b"not found", "text/plain")


LOOP: Optional[asyncio.AbstractEventLoop] = None

def queue_for_loop():
    q: asyncio.Queue = asyncio.Queue()
    ui_clients.append(q)
    return q

def loop_queue_get(q: asyncio.Queue):
    fut = asyncio.run_coroutine_threadsafe(q.get(), LOOP)
    return fut.result(30)

def latest_emarker():
    for pd in reversed(snap.pd_log):
        em = pd.get("pd", {}).get("emarker")
        if em:
            return em
    return None


async def do_connect(addr: Optional[str]):
    global dev
    if dev and state["connected"]:
        await dev.disconnect()
        state["connected"] = False
    if addr:
        LAST_ADDR[0] = addr
    if not addr:
        devs = await scan(4.0)
        cand = [d for d in devs if is_target(d)]
        if not cand:
            raise RuntimeError("未扫描到含 AF00 服务的设备（设备可能正被手机占用，或刚断开还在恢复广播，稍候重试）")
        addr = cand[0]["address"]
        state["rssi"] = cand[0]["rssi"]
    dev = Device(addr)
    await dev.connect()
    state["connected"] = True
    state["device"] = addr
    await dev.set_rate("3")


async def main():
    global LOOP
    LOOP = asyncio.get_running_loop()
    if len(sys.argv) > 1 and sys.argv[1] == "scan":
        for d in await scan(10.0):
            mark = "[Power-Z]" if is_target(d) else "         "
            print(f"{mark} {d['address']} rssi={d['rssi']} name={d['name']!r} uuids={d['uuids']}")
        return
    srv = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    log(f"界面地址: http://127.0.0.1:{PORT}/")
    try:
        await do_connect(None)
    except Exception as e:
        log(f"自动连接失败: {e}（看门狗将持续重试）")
    # 看门狗：短周期扫描 + 立即重连（PD 协商窗口只有几秒，必须抢）
    while True:
        await asyncio.sleep(0.3)
        if state["connected"]:
            continue
        try:
            devs = await scan(1.5)
            cand = [d for d in devs if is_target(d)]
            if cand:
                await do_connect(cand[0]["address"])
        except Exception:
            pass


def _run_service():
    global LOOP
    LOOP = asyncio.new_event_loop()
    asyncio.set_event_loop(LOOP)
    LOOP.run_until_complete(main())


if __name__ == "__main__":
    set_dpi_aware()          # 必须最早调用：DPI 感知只能设置一次
    try:
        if len(sys.argv) > 1 and sys.argv[1] == "scan":
            asyncio.run(main())          # 扫描模式：直接跑完退出
        else:
            if not ensure_single_instance():
                try:
                    import ctypes
                    ctypes.windll.user32.MessageBoxW(
                        0, "程序已经在运行中（端口 %d 被占用）。\n\n"
                           "请在任务栏找到已有的窗口；\n"
                           "若找不到，可在任务管理器结束 PowerZ-Host 进程后再启动。\n\n"
                           "注意：单文件版与目录版是同一个程序，请只运行其中一个。",
                        "Power-Z C240 Pro", 0x40)
                except Exception:
                    pass
                sys.exit(0)
            threading.Thread(target=_run_service, daemon=True).start()
            run_ui()                     # 主线程持有窗口
    except KeyboardInterrupt:
        pass
