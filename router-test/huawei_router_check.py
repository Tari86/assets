#!/usr/bin/env python3
"""
فحص شامل لراوتر هواوي - يشتغل على جهازك وهو متصل بشبكة البيت.
Comprehensive read-only health & security check for Huawei routers.

Usage:
    python3 huawei_router_check.py            # auto-detect router IP
    python3 huawei_router_check.py 192.168.8.1

Only uses the Python standard library. Nothing is changed on the router,
and no passwords are tried (to avoid locking the admin account).
"""
import datetime
import ipaddress
import json
import platform
import re
import socket
import ssl
import statistics
import subprocess
import sys
import time
import urllib.request

# Common Huawei default gateways (LTE/5G CPE, HG/EG ONTs, WiFi AX series)
HUAWEI_CANDIDATES = ["192.168.8.1", "192.168.3.1", "192.168.100.1",
                     "192.168.1.1", "192.168.18.1", "192.168.0.1"]

# port -> (service, risk note)
PORTS = {
    21: ("FTP", "خطر: FTP مفتوح، بيانات الدخول تمر بدون تشفير"),
    22: ("SSH", "انتبه: SSH مفتوح، تأكد إن كلمة المرور قوية"),
    23: ("Telnet", "خطر عالي: Telnet مفتوح وغير مشفّر، الأفضل تقفله"),
    53: ("DNS", None),
    80: ("HTTP (لوحة التحكم)", None),
    443: ("HTTPS (لوحة التحكم)", None),
    445: ("SMB (مشاركة ملفات)", "انتبه: مشاركة الملفات مفعّلة"),
    1900: ("UPnP/SSDP", "انتبه: UPnP مفعّل، يفضّل تقفله إذا ما تحتاجه"),
    7547: ("TR-069 (إدارة مزود الخدمة)", "معلومة: منفذ إدارة المزود، طبيعي في راوترات STC/Zain/Mobily"),
    8080: ("HTTP بديل", "انتبه: لوحة تحكم على منفذ إضافي"),
    8443: ("HTTPS بديل", None),
    37215: ("Huawei UPnP (HG532)", "خطر عالي: هذا المنفذ مرتبط بثغرة CVE-2017-17215، حدّث البرنامج فوراً"),
    52869: ("UPnP SOAP", "خطر: منفذ UPnP مستغل من بوتنتات"),
}

IS_WIN = platform.system().lower() == "windows"
results = []          # (section, status, message)   status: OK / WARN / FAIL / INFO


def add(section, status, msg):
    results.append((section, status, msg))
    icon = {"OK": "✅", "WARN": "⚠️ ", "FAIL": "❌", "INFO": "ℹ️ "}[status]
    print(f"  {icon} {msg}")


def run(cmd, timeout=30):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                              errors="replace").stdout
    except Exception:
        return ""


# ---------------------------------------------------------------- gateway
def detect_gateway():
    out = ""
    if IS_WIN:
        out = run(["ipconfig"])
        m = re.findall(r"Default Gateway[ .]*:\s*([\d.]+)", out)
        m += re.findall(r"البوابة الافتراضية[ .]*:\s*([\d.]+)", out)
        if m:
            return m[0]
    elif platform.system() == "Darwin":
        out = run(["route", "-n", "get", "default"])
        m = re.search(r"gateway:\s*([\d.]+)", out)
        if m:
            return m.group(1)
    else:
        out = run(["ip", "route"])
        m = re.search(r"default via ([\d.]+)", out)
        if m:
            return m.group(1)
    for ip in HUAWEI_CANDIDATES:
        if port_open(ip, 80, 0.7) or port_open(ip, 443, 0.7):
            return ip
    return None


def port_open(host, port, timeout=1.0):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


# ---------------------------------------------------------------- ping
def ping(host, count=20):
    if IS_WIN:
        out = run(["ping", "-n", str(count), host], timeout=count * 3 + 10)
        times = [float(x) for x in re.findall(r"(?:time|الوقت)[=<]\s*(\d+)\s*ms", out)]
    else:
        out = run(["ping", "-c", str(count), "-i", "0.3", host], timeout=count * 3 + 10)
        times = [float(x) for x in re.findall(r"time[=<]([\d.]+)", out)]
    loss = 100.0 * (count - len(times)) / count
    return times, loss


def check_ping(label, host, good_ms, ok_ms):
    times, loss = ping(host)
    if not times:
        add("الاتصال", "FAIL", f"{label} ({host}): ما فيه رد نهائياً")
        return
    avg = statistics.mean(times)
    jitter = statistics.pstdev(times)
    msg = (f"{label} ({host}): متوسط {avg:.1f}ms، أعلى {max(times):.1f}ms، "
           f"تذبذب {jitter:.1f}ms، فقدان {loss:.0f}%")
    if loss > 5 or avg > ok_ms:
        add("الاتصال", "FAIL", msg)
    elif loss > 0 or avg > good_ms or jitter > good_ms:
        add("الاتصال", "WARN", msg)
    else:
        add("الاتصال", "OK", msg)


# ---------------------------------------------------------------- DNS
def check_dns(router):
    for name in ["google.com", "cloudflare.com", "stc.com.sa"]:
        t0 = time.time()
        try:
            ip = socket.gethostbyname(name)
            ms = (time.time() - t0) * 1000
            add("DNS", "OK" if ms < 150 else "WARN", f"{name} → {ip} خلال {ms:.0f}ms")
        except OSError:
            add("DNS", "FAIL", f"فشل تحليل الاسم {name}")


# ---------------------------------------------------------------- speed
def check_speed():
    url = "https://speed.cloudflare.com/__down?bytes=25000000"
    try:
        t0 = time.time()
        total = 0
        with urllib.request.urlopen(url, timeout=30) as r:
            while True:
                chunk = r.read(65536)
                if not chunk:
                    break
                total += len(chunk)
                if time.time() - t0 > 20:
                    break
        mbps = total * 8 / (time.time() - t0) / 1e6
        add("السرعة", "OK" if mbps >= 20 else "WARN", f"سرعة التحميل تقريباً {mbps:.1f} Mbps")
    except Exception as e:
        add("السرعة", "FAIL", f"فشل اختبار التحميل: {e}")
    try:
        data = b"0" * 5_000_000
        req = urllib.request.Request("https://speed.cloudflare.com/__up", data=data, method="POST")
        t0 = time.time()
        urllib.request.urlopen(req, timeout=30).read()
        mbps = len(data) * 8 / (time.time() - t0) / 1e6
        add("السرعة", "OK" if mbps >= 5 else "WARN", f"سرعة الرفع تقريباً {mbps:.1f} Mbps")
    except Exception as e:
        add("السرعة", "FAIL", f"فشل اختبار الرفع: {e}")


# ---------------------------------------------------------------- ports
def check_ports(router):
    open_ports = []
    for port, (svc, note) in PORTS.items():
        if port_open(router, port, 0.8):
            open_ports.append(port)
            if note and note.startswith("خطر"):
                add("الأمان", "FAIL", f"منفذ {port} ({svc}) مفتوح. {note}")
            elif note:
                add("الأمان", "WARN" if "انتبه" in note else "INFO", f"منفذ {port} ({svc}) مفتوح. {note}")
            else:
                add("الأمان", "INFO", f"منفذ {port} ({svc}) مفتوح")
    if not open_ports:
        add("الأمان", "WARN", "ما لقيت أي منفذ مفتوح على الراوتر (ممكن جدار حماية قوي أو العنوان غلط)")
    return open_ports


# ---------------------------------------------------------------- web UI
def http_get(url, timeout=5):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 router-check"})
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
        return r.status, dict(r.headers), r.read(200_000).decode("utf-8", "replace")


def check_web(router, open_ports):
    https = 443 in open_ports
    http = 80 in open_ports
    if http and not https:
        add("لوحة التحكم", "WARN", "لوحة التحكم على HTTP فقط (غير مشفّرة)")
    elif https:
        add("لوحة التحكم", "OK", "لوحة التحكم متاحة عبر HTTPS")

    base = f"https://{router}" if https else f"http://{router}"
    try:
        status, headers, body = http_get(base + "/")
        title = re.search(r"<title>(.*?)</title>", body, re.I | re.S)
        is_huawei = "huawei" in body.lower() or "huawei" in str(headers).lower()
        add("لوحة التحكم", "OK", f"الصفحة ترد ({status})"
            + (f"، العنوان: {title.group(1).strip()}" if title else ""))
        add("لوحة التحكم", "OK" if is_huawei else "INFO",
            "تم التعرف على راوتر هواوي" if is_huawei else "ما قدرت أأكد إنه هواوي من الصفحة الرئيسية")
        srv = headers.get("Server")
        if srv:
            add("لوحة التحكم", "INFO", f"Server header: {srv}")
    except Exception as e:
        add("لوحة التحكم", "FAIL", f"ما قدرت أفتح لوحة التحكم: {e}")
        return

    # Huawei LTE/5G CPE (HiLink) API - some endpoints answer without login
    leaked = {}
    for ep in ["/api/device/basic_information", "/api/device/information",
               "/api/monitoring/status", "/api/device/signal", "/api/net/current-plmn"]:
        try:
            _, _, xml = http_get(base + ep, timeout=4)
            if "<error>" in xml or "<response" not in xml:
                continue
            for tag in ["productfamily", "DeviceName", "classify", "SoftwareVersion",
                        "HardwareVersion", "Imei", "SerialNumber", "MacAddress1",
                        "ConnectionStatus", "SignalIcon", "CurrentNetworkType",
                        "rsrp", "rsrq", "sinr", "rssi", "FullName"]:
                m = re.search(fr"<{tag}>(.*?)</{tag}>", xml, re.I)
                if m and m.group(1).strip():
                    leaked[tag] = m.group(1).strip()
        except Exception:
            pass
    if leaked:
        add("لوحة التحكم", "INFO", "معلومات من واجهة HiLink: "
            + json.dumps(leaked, ensure_ascii=False))
        if any(k in leaked for k in ("Imei", "SerialNumber", "MacAddress1")):
            add("الأمان", "WARN", "الراوتر يكشف IMEI أو الرقم التسلسلي بدون تسجيل دخول، حدّث البرنامج")
        signal_report(leaked)


def signal_report(d):
    def num(k):
        try:
            return float(re.sub(r"[^\d.\-]", "", d[k]))
        except (KeyError, ValueError):
            return None
    rsrp, sinr = num("rsrp"), num("sinr")
    if rsrp is not None:
        q = "ممتازة" if rsrp >= -80 else "جيدة" if rsrp >= -90 else "متوسطة" if rsrp >= -100 else "ضعيفة"
        add("الإشارة", "OK" if rsrp >= -90 else "WARN" if rsrp >= -100 else "FAIL",
            f"قوة الإشارة RSRP = {rsrp:.0f} dBm ({q})")
    if sinr is not None:
        q = "ممتازة" if sinr >= 20 else "جيدة" if sinr >= 13 else "متوسطة" if sinr >= 0 else "ضعيفة"
        add("الإشارة", "OK" if sinr >= 13 else "WARN" if sinr >= 0 else "FAIL",
            f"جودة الإشارة SINR = {sinr:.0f} dB ({q})")


# ---------------------------------------------------------------- wifi
def check_wifi():
    if IS_WIN:
        out = run(["netsh", "wlan", "show", "interfaces"])
        ssid = re.search(r"^\s*SSID\s*:\s*(.+)$", out, re.M)
        sig = re.search(r"(?:Signal|الإشارة)\s*:\s*(\d+)%", out)
        auth = re.search(r"(?:Authentication|المصادقة)\s*:\s*(.+)$", out, re.M)
        band = re.search(r"(?:Band|Radio type)\s*:\s*(.+)$", out, re.M)
        if ssid:
            add("الواي فاي", "INFO", f"متصل بـ {ssid.group(1).strip()}"
                + (f" ({band.group(1).strip()})" if band else ""))
        if sig:
            s = int(sig.group(1))
            add("الواي فاي", "OK" if s >= 70 else "WARN" if s >= 40 else "FAIL", f"قوة الواي فاي {s}%")
        if auth:
            a = auth.group(1).strip()
            weak = any(w in a.upper() for w in ("WEP", "OPEN", "مفتوح")) or a.upper() == "WPA-PERSONAL"
            add("الأمان", "FAIL" if weak else "OK", f"تشفير الواي فاي: {a}")
        if not ssid:
            add("الواي فاي", "INFO", "الجهاز غير متصل بواي فاي (ممكن كيبل)")
    elif platform.system() == "Darwin":
        out = run(["system_profiler", "SPAirPortDataType"], timeout=40)
        m = re.search(r"Current Network Information:\s*\n\s*(.+?):\s*\n(.*?)\n\s*\n", out, re.S)
        if m:
            block = m.group(2)
            sec = re.search(r"Security:\s*(.+)", block)
            sn = re.search(r"Signal / Noise:\s*(-?\d+) dBm / (-?\d+)", block)
            ch = re.search(r"Channel:\s*(.+)", block)
            add("الواي فاي", "INFO", f"متصل بـ {m.group(1).strip()}" + (f"، قناة {ch.group(1).strip()}" if ch else ""))
            if sn:
                rssi = int(sn.group(1))
                add("الواي فاي", "OK" if rssi >= -60 else "WARN" if rssi >= -70 else "FAIL",
                    f"قوة الواي فاي {rssi} dBm")
            if sec:
                s = sec.group(1)
                add("الأمان", "FAIL" if ("WEP" in s or "None" in s) else "OK", f"تشفير الواي فاي: {s}")
        else:
            add("الواي فاي", "INFO", "ما قدرت أقرأ معلومات الواي فاي")
    else:
        out = run(["nmcli", "-t", "-f", "ACTIVE,SSID,SIGNAL,SECURITY,CHAN", "dev", "wifi"])
        for line in out.splitlines():
            if line.startswith("yes:"):
                _, ssid, sig, sec, ch = (line.split(":") + [""] * 5)[:5]
                add("الواي فاي", "INFO", f"متصل بـ {ssid}، قناة {ch}")
                if sig.isdigit():
                    s = int(sig)
                    add("الواي فاي", "OK" if s >= 70 else "WARN" if s >= 40 else "FAIL", f"قوة الواي فاي {s}%")
                add("الأمان", "FAIL" if (not sec or "WEP" in sec) else "OK", f"تشفير الواي فاي: {sec or 'مفتوح'}")
                break
        else:
            add("الواي فاي", "INFO", "ما فيه اتصال واي فاي (ممكن كيبل) أو nmcli غير موجود")


# ---------------------------------------------------------------- devices
def check_devices(router):
    out = run(["arp", "-a"])
    try:
        net = ipaddress.ip_network(router + "/24", strict=False)
    except ValueError:
        return
    ips = {ip for ip in re.findall(r"(\d+\.\d+\.\d+\.\d+)", out)
           if ipaddress.ip_address(ip) in net and not ip.endswith(".255")}
    add("الأجهزة", "INFO", f"عدد الأجهزة اللي جهازك شافها مؤخراً على الشبكة: {len(ips)} "
        "(العدد الكامل موجود في لوحة التحكم)")


# ---------------------------------------------------------------- public IP
def check_public():
    try:
        _, _, body = http_get("https://api.ipify.org?format=json", timeout=8)
        ip = json.loads(body)["ip"]
        add("الإنترنت", "OK", f"عنوانك العام: {ip}")
        return ip
    except Exception as e:
        add("الإنترنت", "FAIL", f"ما قدرت أعرف العنوان العام: {e}")


# ---------------------------------------------------------------- report
def write_report(router):
    ts = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M")
    fn = f"router_report_{ts}.html"
    colors = {"OK": "#1a7f37", "WARN": "#9a6700", "FAIL": "#cf222e", "INFO": "#0969da"}
    labels = {"OK": "سليم", "WARN": "تنبيه", "FAIL": "مشكلة", "INFO": "معلومة"}
    rows = "".join(
        f"<tr><td>{s}</td><td style='color:{colors[st]};font-weight:bold'>{labels[st]}</td><td>{m}</td></tr>"
        for s, st, m in results)
    cnt = {k: sum(1 for _, st, _ in results if st == k) for k in colors}
    html = f"""<!doctype html><html lang="ar" dir="rtl"><meta charset="utf-8">
<title>تقرير فحص الراوتر</title>
<style>body{{font-family:Tahoma,Arial;max-width:900px;margin:24px auto;padding:0 16px}}
table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #ccc;padding:8px;text-align:right}}
th{{background:#f3f3f3}}</style>
<h1>تقرير فحص راوتر هواوي</h1>
<p>الراوتر: <b>{router}</b> | التاريخ: {ts.replace('_', ' ')} | النظام: {platform.system()}</p>
<p>✅ سليم: {cnt['OK']} &nbsp; ⚠️ تنبيه: {cnt['WARN']} &nbsp; ❌ مشكلة: {cnt['FAIL']} &nbsp; ℹ️ معلومة: {cnt['INFO']}</p>
<table><tr><th>القسم</th><th>الحالة</th><th>التفاصيل</th></tr>{rows}</table></html>"""
    with open(fn, "w", encoding="utf-8") as f:
        f.write(html)
    return fn, cnt


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    print("=== فحص شامل لراوتر هواوي ===\n")
    router = sys.argv[1] if len(sys.argv) > 1 else detect_gateway()
    if not router:
        print("❌ ما لقيت الراوتر. شغّل السكربت مع عنوان الراوتر، مثال:")
        print("   python3 huawei_router_check.py 192.168.8.1")
        sys.exit(1)
    print(f"الراوتر: {router}\n")

    steps = [
        ("[1/8] الاتصال بالراوتر", lambda: check_ping("الراوتر", router, 5, 20)),
        ("[2/8] الاتصال بالإنترنت", lambda: (check_ping("Google DNS", "8.8.8.8", 60, 150),
                                              check_ping("Cloudflare", "1.1.1.1", 60, 150), check_public())),
        ("[3/8] DNS", lambda: check_dns(router)),
        ("[4/8] المنافذ المفتوحة", lambda: None),
        ("[5/8] لوحة التحكم ومعلومات الجهاز", lambda: None),
        ("[6/8] الواي فاي", check_wifi),
        ("[7/8] الأجهزة المتصلة", lambda: check_devices(router)),
        ("[8/8] السرعة (تاخذ حوالي دقيقة)", check_speed),
    ]
    open_ports = []
    for title, fn in steps:
        print(title)
        if title.startswith("[4/8]"):
            open_ports = check_ports(router)
        elif title.startswith("[5/8]"):
            check_web(router, open_ports)
        else:
            fn()
        print()

    report, cnt = write_report(router)
    print("=== الخلاصة ===")
    print(f"✅ {cnt['OK']}  ⚠️  {cnt['WARN']}  ❌ {cnt['FAIL']}  ℹ️  {cnt['INFO']}")
    print(f"التقرير محفوظ في: {report}")
    print("\nنصائح يدوية: غيّر كلمة مرور لوحة التحكم الافتراضية، استخدم WPA2/WPA3، "
          "قفل WPS و UPnP إذا ما تحتاجها، وحدّث برنامج الراوتر من لوحة التحكم.")


if __name__ == "__main__":
    main()
