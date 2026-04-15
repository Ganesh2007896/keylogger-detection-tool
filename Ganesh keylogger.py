#!/usr/bin/env python3
import os, sys, platform, datetime, json, socket, subprocess, webbrowser
import psutil
from colorama import init, Fore, Style
init(autoreset=True)
OS = platform.system()

SUSPICIOUS_PROCESSES = [
    {"name": "keylogger.exe",        "desc": "Generic keylogger binary",     "risk": "high"},
    {"name": "ardamax.exe",          "desc": "Ardamax Keylogger",             "risk": "high"},
    {"name": "spyrix.exe",           "desc": "Spyrix monitoring software",    "risk": "high"},
    {"name": "refog.exe",            "desc": "REFOG Keylogger",               "risk": "high"},
    {"name": "kidlogger.exe",        "desc": "KidLogger monitoring tool",     "risk": "high"},
    {"name": "revealer.exe",         "desc": "Revealer Keylogger",            "risk": "high"},
    {"name": "kgb.exe",              "desc": "KGB Spy keylogger",             "risk": "high"},
    {"name": "pykeylogger",          "desc": "Python-based keylogger",        "risk": "high"},
    {"name": "logkeys",              "desc": "Linux keylogger daemon",        "risk": "high"},
    {"name": "xspy",                 "desc": "X11 keyboard spy tool",         "risk": "high"},
    {"name": "xinput",               "desc": "X11 input capture utility",     "risk": "medium"},
    {"name": "hook32.dll",           "desc": "Keyboard hook DLL",             "risk": "high"},
    {"name": "elite keylogger",      "desc": "Elite Keylogger process",       "risk": "high"},
    {"name": "perfect keylogger",    "desc": "Perfect Keylogger",             "risk": "high"},
    {"name": "actual keylogger",     "desc": "Actual Keylogger",              "risk": "high"},
    {"name": "all in one keylogger", "desc": "All In One Keylogger",          "risk": "high"},
]
SUSPICIOUS_REGISTRY_KEYS = [
    r"SOFTWARE\Ardamax", r"SOFTWARE\Keylogger", r"SOFTWARE\Revealer Keylogger",
    r"SOFTWARE\Elite Keylogger", r"SOFTWARE\Spyrix", r"SOFTWARE\KidLogger", r"SOFTWARE\REFOG",
]
AUTORUN_REGISTRY_KEYS = [
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
]
SUSPICIOUS_FILES_WIN = [
    os.path.join(os.environ.get("TEMP", "C:\\Temp"), "keylog.txt"),
    os.path.join(os.environ.get("TEMP", "C:\\Temp"), "clipboard.log"),
    os.path.join(os.environ.get("APPDATA", ""), "keylog.dat"),
    os.path.join(os.environ.get("APPDATA", ""), "log.dat"),
]
SUSPICIOUS_FILES_LINUX = [
    "/tmp/.klog", "/tmp/.keylog", "/var/log/keylog.txt",
    os.path.expanduser("~/.keylog"), os.path.expanduser("~/.klog.txt"),
]
SUSPICIOUS_STARTUP_FOLDERS = [
    os.path.expanduser(r"~\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"),
    r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
]
SUSPICIOUS_NETWORK_PORTS = [25, 465, 587, 21, 4444, 1337, 9001, 9050]
KNOWN_CLEAN_SERVICES = {
    "svchost.exe","explorer.exe","winlogon.exe","lsass.exe","services.exe",
    "csrss.exe","smss.exe","wininit.exe","System","Registry","sihost.exe","taskhostw.exe",
}

def banner():
    print(Fore.CYAN + r"""
  _  __          _                 _____       _            _
 | |/ /___ _  _| |___  __ _ __ _ |  __ \     | |          | |
 | ' </ _ \ || | / _ \/ _` / _` || |  | | ___| |_ ___  ___| |_ ___  _ __
 |  _\  __/ || | \/ _ \ (_| (_| || |  | |/ _ \ __/ _ \/ __| __/ _ \| '__|
 |_| \_\___|\_,_|_\___/\__, \__, ||____/\  __/ ||  __/ (__| ||  (_) | |
                        |___/|___/       \___|\___|\___|___|\__\___/|_|
    """ + Style.RESET_ALL)
    print(Fore.WHITE + "  Keylogger Detection Tool — " + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    print(Fore.WHITE + "  Platform: " + platform.system() + " " + platform.release())
    print(Fore.WHITE + "  Python:   " + sys.version.split()[0])
    print()

def section(title):
    print(Fore.CYAN + f"\n{'─'*60}\n  {title}\n{'─'*60}" + Style.RESET_ALL)

def found(msg, risk="high"):
    colour = Fore.RED if risk == "high" else Fore.YELLOW
    tag = "[THREAT]" if risk == "high" else "[WARN]  "
    print(colour + f"  {tag} {msg}" + Style.RESET_ALL)
    return {"status": "detected", "message": msg, "risk": risk}

def clean(msg):
    print(Fore.GREEN + f"  [OK]     {msg}" + Style.RESET_ALL)
    return {"status": "clean", "message": msg}

def info(msg):
    print(Fore.WHITE + f"  [INFO]   {msg}" + Style.RESET_ALL)

# ─── Detection modules ───────────────────────────────────────────────────────

def scan_processes():
    section("1 / 6  Suspicious Processes")
    results = []
    running = {p.name().lower(): p for p in psutil.process_iter(["name", "pid", "exe", "cmdline"])}
    for sig in SUSPICIOUS_PROCESSES:
        name_lc = sig["name"].lower()
        if name_lc in running:
            proc = running[name_lc]
            results.append(found(f"Process '{sig['name']}' running (PID {proc.pid}) — {sig['desc']}", sig["risk"]))
        else:
            clean(f"Process '{sig['name']}' not found")
    for proc in psutil.process_iter(["name", "pid", "exe"]):
        try:
            name = proc.name().lower()
            if name in KNOWN_CLEAN_SERVICES:
                continue
            if proc.exe() and "temp" in proc.exe().lower():
                results.append(found(f"Process '{proc.name()}' (PID {proc.pid}) running from TEMP directory", "medium"))
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            pass
    return results

def scan_registry():
    section("2 / 6  Registry Anomalies")
    results = []
    if OS != "Windows":
        info("Registry scan skipped — not Windows")
        return results
    try:
        import winreg
    except ImportError:
        info("winreg not available — install pywin32")
        return results
    for key_path in SUSPICIOUS_REGISTRY_KEYS:
        for hive, hive_name in [(winreg.HKEY_LOCAL_MACHINE, "HKLM"), (winreg.HKEY_CURRENT_USER, "HKCU")]:
            try:
                winreg.OpenKey(hive, key_path)
                results.append(found(f"Registry key found: {hive_name}\\{key_path}", "high"))
            except FileNotFoundError:
                clean(f"{hive_name}\\{key_path}")
            except PermissionError:
                info(f"Access denied: {hive_name}\\{key_path}")
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows")
        val, _ = winreg.QueryValueEx(key, "AppInit_DLLs")
        if val.strip():
            results.append(found(f"AppInit_DLLs contains: {val}", "high"))
        else:
            clean("AppInit_DLLs is empty")
    except Exception:
        clean("AppInit_DLLs not set")
    for key_path in AUTORUN_REGISTRY_KEYS:
        for hive, hive_name in [(winreg.HKEY_LOCAL_MACHINE, "HKLM"), (winreg.HKEY_CURRENT_USER, "HKCU")]:
            try:
                key = winreg.OpenKey(hive, key_path)
                i = 0
                while True:
                    try:
                        name, data, _ = winreg.EnumValue(key, i)
                        if any(s in data.lower() for s in ["temp", "appdata\\local\\temp", "klog"]):
                            results.append(found(f"Suspicious autorun: [{name}] = {data} in {hive_name}\\{key_path}", "high"))
                        i += 1
                    except OSError:
                        break
            except (FileNotFoundError, PermissionError):
                pass
    return results

def scan_files():
    section("3 / 6  File System Indicators")
    results = []
    targets = SUSPICIOUS_FILES_WIN if OS == "Windows" else SUSPICIOUS_FILES_LINUX
    for path in targets:
        if os.path.exists(path):
            size = os.path.getsize(path)
            mtime = datetime.datetime.fromtimestamp(os.path.getmtime(path))
            results.append(found(f"Suspicious file: {path} ({size} bytes, modified {mtime.strftime('%Y-%m-%d %H:%M')})", "high"))
        else:
            clean(f"Not found: {path}")
    if OS == "Windows":
        for folder in SUSPICIOUS_STARTUP_FOLDERS:
            if os.path.isdir(folder):
                for fname in os.listdir(folder):
                    results.append(found(f"Startup item: {os.path.join(folder, fname)}", "medium"))
    if OS == "Linux":
        try:
            out = subprocess.check_output(["lsof", "/dev/input"], stderr=subprocess.DEVNULL, text=True)
            for line in out.splitlines()[1:]:
                cols = line.split()
                if cols and cols[0].lower() not in {"xorg", "x", "libinput", "systemd", "gdm"}:
                    results.append(found(f"Non-system process reading /dev/input: {line.strip()}", "high"))
        except (FileNotFoundError, subprocess.CalledProcessError):
            info("lsof not available or /dev/input not accessible")
    return results

def scan_network():
    section("4 / 6  Network Exfiltration Indicators")
    results = []
    try:
        connections = psutil.net_connections(kind="inet")
    except psutil.AccessDenied:
        info("Access denied — run as root for network scan")
        return results
    for conn in connections:
        if conn.status != "ESTABLISHED":
            continue
        if conn.raddr and conn.raddr.port in SUSPICIOUS_NETWORK_PORTS:
            try:
                proc = psutil.Process(conn.pid) if conn.pid else None
                pname = proc.name() if proc else "unknown"
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pname = "unknown"
            results.append(found(f"Process '{pname}' (PID {conn.pid}) connected to {conn.raddr.ip}:{conn.raddr.port}", "high"))
    if not any(r["status"] == "detected" for r in results):
        clean("No connections to suspicious ports detected")
    for conn in connections:
        if conn.laddr and conn.laddr.port in (9050, 9051):
            results.append(found("Tor SOCKS proxy listening locally — traffic may be anonymised", "medium"))
    return results

def scan_hooks():
    section("5 / 6  Keyboard Hook Detection")
    results = []
    if OS == "Windows":
        try:
            for proc in psutil.process_iter(["name", "pid"]):
                try:
                    if proc.name().lower() in KNOWN_CLEAN_SERVICES:
                        continue
                    mods = proc.memory_maps()
                    for m in mods:
                        path_lc = m.path.lower()
                        if any(s in path_lc for s in ["hook", "spy", "klog"]):
                            results.append(found(f"Suspicious DLL in {proc.name()} (PID {proc.pid}): {m.path}", "high"))
                except (psutil.AccessDenied, psutil.NoSuchProcess, NotImplementedError):
                    pass
        except Exception as e:
            info(f"Hook scan partial: {e}")
    elif OS == "Linux":
        for proc in psutil.process_iter(["name", "pid", "environ"]):
            try:
                env = proc.environ()
                if "LD_PRELOAD" in env:
                    results.append(found(f"LD_PRELOAD set in '{proc.name()}' (PID {proc.pid}): {env['LD_PRELOAD']}", "high"))
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass
        try:
            with open("/proc/sys/kernel/yama/ptrace_scope") as f:
                scope = f.read().strip()
            if scope == "0":
                results.append(found("ptrace_scope=0 — any process can ptrace any other", "medium"))
            else:
                clean(f"ptrace_scope={scope} (restricted)")
        except FileNotFoundError:
            info("ptrace_scope check not available")
    if not results:
        clean("No keyboard hook indicators found")
    return results

def scan_persistence():
    section("6 / 6  Persistence Mechanisms")
    results = []
    if OS == "Windows":
        try:
            out = subprocess.check_output(
                ["schtasks", "/query", "/fo", "CSV", "/v"],
                stderr=subprocess.DEVNULL, text=True, encoding="utf-8", errors="ignore"
            )
            for line in out.splitlines():
                if "\\AppData\\Local\\Temp\\" in line or "keylog" in line.lower():
                    results.append(found(f"Suspicious scheduled task entry: {line[:120]}", "high"))
        except Exception:
            info("Could not query scheduled tasks")
    elif OS == "Linux":
        try:
            out = subprocess.check_output(["crontab", "-l"], stderr=subprocess.DEVNULL, text=True)
            for line in out.splitlines():
                if line.strip() and not line.startswith("#"):
                    if any(s in line.lower() for s in ["keylog", "klog", "spy", "logger"]):
                        results.append(found(f"Suspicious cron job: {line.strip()}", "high"))
        except Exception:
            pass
        svc_dir = os.path.expanduser("~/.config/systemd/user/")
        if os.path.isdir(svc_dir):
            for fname in os.listdir(svc_dir):
                if fname.endswith(".service"):
                    fpath = os.path.join(svc_dir, fname)
                    with open(fpath) as f:
                        content = f.read().lower()
                    if any(s in content for s in ["keylog", "klog", "xspy"]):
                        results.append(found(f"Suspicious systemd service: {fpath}", "high"))
    if not results:
        clean("No suspicious persistence mechanisms found")
    return results

# ─── Summary ─────────────────────────────────────────────────────────────────

def print_summary(all_results):
    threats = [r for r in all_results if r.get("status") == "detected" and r.get("risk") == "high"]
    warnings = [r for r in all_results if r.get("status") == "detected" and r.get("risk") != "high"]
    if threats:
        risk_level, risk_color = ("CRITICAL" if len(threats) >= 3 else "HIGH"), Fore.RED
    elif warnings:
        risk_level, risk_color = ("MEDIUM" if len(warnings) >= 3 else "LOW"), Fore.YELLOW
    else:
        risk_level, risk_color = "NONE", Fore.GREEN
    print(Fore.CYAN + f"\n{'═'*60}\n  SCAN SUMMARY\n{'═'*60}" + Style.RESET_ALL)
    print(f"  High-risk threats : {Fore.RED}{len(threats)}{Style.RESET_ALL}")
    print(f"  Warnings          : {Fore.YELLOW}{len(warnings)}{Style.RESET_ALL}")
    print(f"  Overall risk      : {risk_color}{risk_level}{Style.RESET_ALL}")
    if threats:
        print(Fore.RED + "\n  Recommended actions:\n  • Terminate and remove detected processes immediately\n  • Run a full antivirus / EDR scan\n  • Audit autostart entries and scheduled tasks\n  • Change all passwords from a clean, trusted device\n  • Review outbound firewall rules" + Style.RESET_ALL)
    elif warnings:
        print(Fore.YELLOW + "\n  Recommended actions:\n  • Investigate flagged items manually\n  • Review startup programs and browser extensions\n  • Keep OS and security software up to date" + Style.RESET_ALL)
    else:
        print(Fore.GREEN + "\n  No keylogger indicators detected. Keep your system updated." + Style.RESET_ALL)
    return {"risk_level": risk_level, "threats": len(threats), "warnings": len(warnings)}

# ─── HTML Report ─────────────────────────────────────────────────────────────

def export_html(all_results, summary, html_path):
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    risk = summary["risk_level"]
    threats = summary["threats"]
    warnings_count = summary["warnings"]
    risk_color = {"NONE": "#1D9E75", "LOW": "#EF9F27", "MEDIUM": "#EF9F27", "HIGH": "#E24B4A", "CRITICAL": "#A32D2D"}.get(risk, "#888")
    detected = [r for r in all_results if r.get("status") == "detected"]

    rows = ""
    for r in all_results:
        if r.get("status") == "detected":
            badge_style = "background:#FCEBEB;color:#791F1F;" if r.get("risk") == "high" else "background:#FAEEDA;color:#633806;"
            badge = "THREAT" if r.get("risk") == "high" else "WARNING"
            rows += f"""<tr>
              <td><span style="font-size:11px;padding:3px 10px;border-radius:20px;font-weight:600;{badge_style}">{badge}</span></td>
              <td style="color:#1a1a1a;font-size:13px;">{r.get('message','')}</td>
              <td style="text-align:center;font-size:12px;color:#555;">{r.get('risk','').upper()}</td>
            </tr>"""

    if not rows:
        rows = '<tr><td colspan="3" style="text-align:center;color:#1D9E75;padding:20px;font-size:14px;">✓ No threats or warnings detected</td></tr>'

    cat_sections = ""
    categories = [
        ("Suspicious Processes", "P"),
        ("Registry Anomalies", "R"),
        ("File System Indicators", "F"),
        ("Network Exfiltration", "N"),
        ("Keyboard Hooks", "H"),
        ("Persistence Mechanisms", "X"),
    ]
    for cat_name, _ in categories:
        cat_items = [r for r in all_results if cat_name.lower().split()[0] in r.get("message","").lower() or True]

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Keylogger Detection Report</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#f4f4f0;color:#1a1a1a;padding:2rem}}
  .wrap{{max-width:860px;margin:0 auto}}
  .header{{background:#0f0f0f;color:#fff;border-radius:12px;padding:2rem;margin-bottom:1.5rem}}
  .header h1{{font-size:22px;font-weight:500;margin-bottom:4px;letter-spacing:0.5px}}
  .header .meta{{font-size:13px;color:#888;margin-top:6px}}
  .cards{{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:1.5rem}}
  .card{{background:#fff;border-radius:10px;padding:1rem 1.25rem;border:1px solid #e8e8e4}}
  .card .label{{font-size:12px;color:#888;margin-bottom:6px}}
  .card .value{{font-size:26px;font-weight:500}}
  .section{{background:#fff;border-radius:10px;border:1px solid #e8e8e4;margin-bottom:1rem;overflow:hidden}}
  .section-title{{padding:14px 20px;font-size:14px;font-weight:500;border-bottom:1px solid #e8e8e4;background:#fafaf8}}
  table{{width:100%;border-collapse:collapse}}
  th{{text-align:left;font-size:11px;color:#888;text-transform:uppercase;letter-spacing:0.5px;padding:10px 20px;border-bottom:1px solid #e8e8e4;background:#fafaf8}}
  td{{padding:12px 20px;border-bottom:1px solid #f0f0ec;vertical-align:top;font-size:13px}}
  tr:last-child td{{border-bottom:none}}
  .risk-badge{{display:inline-block;padding:6px 18px;border-radius:20px;font-weight:600;font-size:13px;color:#fff;background:{risk_color}}}
  .footer{{text-align:center;font-size:12px;color:#aaa;margin-top:1.5rem}}
</style>
</head>
<body>
<div class="wrap">
  <div class="header">
    <h1>Keylogger Detection Report</h1>
    <div class="meta">Generated: {ts} &nbsp;|&nbsp; Platform: {platform.system()} {platform.release()} &nbsp;|&nbsp; Python {sys.version.split()[0]}</div>
  </div>

  <div class="cards">
    <div class="card">
      <div class="label">Overall Risk</div>
      <div class="value"><span class="risk-badge">{risk}</span></div>
    </div>
    <div class="card">
      <div class="label">High-risk Threats</div>
      <div class="value" style="color:{'#E24B4A' if threats else '#1D9E75'}">{threats}</div>
    </div>
    <div class="card">
      <div class="label">Warnings</div>
      <div class="value" style="color:{'#EF9F27' if warnings_count else '#1D9E75'}">{warnings_count}</div>
    </div>
    <div class="card">
      <div class="label">Total Checks</div>
      <div class="value" style="color:#555">{len(all_results)}</div>
    </div>
  </div>

  <div class="section">
    <div class="section-title">Findings</div>
    <table>
      <thead><tr><th style="width:100px">Status</th><th>Detail</th><th style="width:80px;text-align:center">Risk</th></tr></thead>
      <tbody>{rows}</tbody>
    </table>
  </div>

  <div class="footer">Keylogger Detection Tool &mdash; report generated {ts}</div>
</div>
</body>
</html>"""

    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html)

def ctypes_is_admin():
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False

# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    banner()

    if OS == "Windows" and not ctypes_is_admin():
        print(Fore.YELLOW + "  [!] Not running as administrator — some checks may be limited.\n" + Style.RESET_ALL)

    # Run all scans
    all_results = []
    all_results += scan_processes()
    all_results += scan_registry()
    all_results += scan_files()
    all_results += scan_network()
    all_results += scan_hooks()
    all_results += scan_persistence()

    # Print terminal summary
    summary = print_summary(all_results)

    # 1) Save HTML report to disk first
    html_path = os.path.abspath("keylogger_scan_report.html")
    export_html(all_results, summary, html_path)
    print(Fore.GREEN + f"  Report saved  : {html_path}" + Style.RESET_ALL)

    # 2) Also save JSON alongside
    json_path = os.path.abspath("keylogger_scan_report.json")
    report_json = {
        "timestamp": datetime.datetime.now().isoformat(),
        "platform": platform.system() + " " + platform.release(),
        "summary": summary,
        "findings": [r for r in all_results if r.get("status") == "detected"],
    }
    with open(json_path, "w") as f:
        json.dump(report_json, f, indent=2)

    # 3) Open browser AFTER both files are fully written
    file_url = "file:///" + html_path.replace("\\", "/")
    print(Fore.CYAN + f"  Opening report: {file_url}" + Style.RESET_ALL)
    webbrowser.open(file_url)

if __name__ == "__main__":
    main()