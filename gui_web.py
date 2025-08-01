import tkinter as tk
from tkinter import filedialog, scrolledtext, messagebox
import threading, requests, tldextract, os, json
from bs4 import BeautifulSoup
from datetime import datetime


COMMON_DIRS = ['admin', 'login', 'uploads', 'images', 'css', 'js', 'backup', '.git', 'robots.txt']
COMMON_SUBDOMAINS = ['www', 'mail', 'ftp', 'test', 'dev', 'api', 'admin', 'blog']

def log(msg, box):
    box.insert(tk.END, f"{msg}\n")
    box.see(tk.END)
    box.update()

def fetch_headers(url, box):
    try:
        r = requests.get(url, timeout=5)
        log(f"\n[*] HTTP HEADERS for {url}:", box)
        for k, v in r.headers.items():
            log(f"  {k}: {v}", box)
        return r
    except Exception as e:
        log(f"[!] Header Error: {e}", box)

def detect_tech(html, box):
    soup = BeautifulSoup(html, 'html.parser')
    techs = set()
    if soup.find('meta', attrs={"name": "generator"}):
        techs.add(soup.find('meta', attrs={"name": "generator"})['content'])
    if "wp-content" in html: techs.add("WordPress")
    if "jquery" in html: techs.add("jQuery")
    if "bootstrap" in html: techs.add("Bootstrap")
    if techs:
        log("[*] Technologies Detected:", box)
        for t in techs: log(f"  {t}", box)
    else:
        log("[*] No obvious tech found.", box)

def brute_dirs(url, box):
    log("\n[*] Directory Bruteforce:", box)
    for d in COMMON_DIRS:
        path = f"{url.rstrip('/')}/{d}"
        try:=
            r = requests.get(path, timeout=3)
            if r.status_code in [200, 403, 302]:
                log(f"  [+] {path} [Status: {r.status_code}]", box)
        except: pass

def enum_subdomains(domain, box):
    ext = tldextract.extract(domain)
    root = f"{ext.domain}.{ext.suffix}"
    log("\n[*] Subdomain Scan:", box)
    for s in COMMON_SUBDOMAINS:
        test = f"http://{s}.{root}"
        try:
            r = requests.get(test, timeout=3)
            log(f"  [+] {test} [Status: {r.status_code}]", box)
        except: pass

def export_report(content, json_data):
    ts = datetime.now().strftime('%Y%m%d-%H%M%S')
    with open(f"web_report_{ts}.txt", 'w') as f:
        f.write(content)
    with open(f"web_report_{ts}.json", 'w') as jf:
        json.dump(json_data, jf, indent=2)

def run_scan(url_entry, log_box):
    url = url_entry.get().strip()
    if not url.startswith("http"):
        url = "http://" + url

    log_box.delete(1.0, tk.END)
    log(f"[*] Starting Scan: {url}", log_box)
    scan_data = {"target": url, "headers": {}, "dirs": [], "subdomains": [], "tech": []}

    try:
        res = requests.get(url, timeout=5)
        scan_data["status_code"] = res.status_code
        scan_data["title"] = BeautifulSoup(res.text, 'html.parser').title.string.strip()
        log(f"  [+] Page Title: {scan_data['title']}", log_box)
    except: log("  [!] Could not load page", log_box)

    try:
        r = fetch_headers(url, log_box)
        scan_data["headers"] = dict(r.headers)
        detect_tech(r.text, log_box)
    except: pass

    for d in COMMON_DIRS:
        try:
            test = f"{url.rstrip('/')}/{d}"
            r = requests.get(test, timeout=3)
            if r.status_code in [200, 403, 302]:
                scan_data["dirs"].append((test, r.status_code))
        except: pass

    ext = tldextract.extract(url)
    domain = f"{ext.domain}.{ext.suffix}"
    for sub in COMMON_SUBDOMAINS:
        sub_url = f"http://{sub}.{domain}"
        try:
            r = requests.get(sub_url, timeout=2)
            scan_data["subdomains"].append((sub_url, r.status_code))
        except: pass

    for d in scan_data["dirs"]:
        log(f"  [+] {d[0]} [Status: {d[1]}]", log_box)
    for s in scan_data["subdomains"]:
        log(f"  [+] {s[0]} [Status: {s[1]}]", log_box)

    export_report(log_box.get("1.0", tk.END), scan_data)
    log("\n[✓] Scan Complete. Report Saved.", log_box)

# ---- GUI Setup ----
root = tk.Tk()
root.title("Prachan Pro Web Enum Tool")
root.geometry("800x550")

tk.Label(root, text="Target URL:").pack(pady=5)
url_entry = tk.Entry(root, width=60)
url_entry.pack(pady=2)

scan_button = tk.Button(root, text="Start Scan", command=lambda: threading.Thread(target=run_scan, args=(url_entry, output_box)).start())
scan_button.pack(pady=5)

output_box = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=90, height=25)
output_box.pack(padx=10, pady=10)

root.mainloop()
