#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import subprocess
import socket
import requests
import json
import os
import sys
import re
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

# =========================
# 配置与常量
# =========================
CDN_KEYWORDS = [
    "cloudflare", "akamai", "cloudfront", "fastly", "incapsula", "sucuri", "imperva"
]

COMMON_PORTS = "80,443,8080,8443,21,22,23,25,53,110,143,161,389,445,1433,1521,3306,3389,5432,5900,6379,9200,27017"

# 默认字典路径（如果不存在则使用内置小型字典）
DEFAULT_WORDLIST = "/usr/share/wordlists/dirb/common.txt"
BUILTIN_WORDLIST = [
    ".git", ".env", ".svn", ".htaccess", "config.php", "web.config", "admin", "login", 
    "api", "v1", "v2", "backup", "db", "setup", "phpinfo.php", "robots.txt"
]

class InfoWeave:
    def __init__(self, domain):
        self.domain = domain
        self.subdomains = set()
        self.found_ips = set()
        self.results = {
            "domain": domain,
            "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "subdomains": [],
            "ips": {},
        }
        self.output_file = f"report_{domain.replace('.', '_')}.json"

    def log(self, tag, message):
        print(f"[{tag}] {message}")

    # =========================
    # 1. 子域名收集 (Subfinder)
    # =========================
    def get_subdomains(self):
        self.log("SUB", f"正在收集 {self.domain} 的子域名...")
        try:
            # 增加 -all 选项以获取更多结果
            cmd = ["subfinder", "-d", self.domain, "-silent"]
            result = subprocess.check_output(cmd, stderr=subprocess.DEVNULL).decode().splitlines()
            for sub in result:
                if sub.strip():
                    self.subdomains.add(sub.strip())
            self.log("SUB", f"发现 {len(self.subdomains)} 个子域名")
        except Exception as e:
            self.log("!", f"Subfinder 运行失败: {e}")

    # =========================
    # 2. 解析子域名并识别 CDN
    # =========================
    def resolve_and_check_cdn(self):
        self.log("RESOLVE", "正在解析子域名并检测 CDN...")
        for sub in self.subdomains:
            try:
                ip = socket.gethostbyname(sub)
                self.found_ips.add(ip)
                
                if ip not in self.results["ips"]:
                    self.results["ips"][ip] = {
                        "subdomains": [],
                        "ports": {},
                        "cdn": False,
                        "origin_candidate": False,
                        "http_info": {}
                    }
                
                if sub not in self.results["ips"][ip]["subdomains"]:
                    self.results["ips"][ip]["subdomains"].append(sub)

                # 简单 CDN 检测
                try:
                    r = requests.get(f"http://{sub}", timeout=3, allow_redirects=True)
                    headers_str = str(r.headers).lower()
                    for kw in CDN_KEYWORDS:
                        if kw in headers_str:
                            self.results["ips"][ip]["cdn"] = True
                            break
                except:
                    pass
            except:
                continue

    # =========================
    # 3. 端口扫描与服务识别 (Nmap)
    # =========================
    def scan_ports(self):
        self.log("NMAP", "正在进行端口扫描与服务识别 (TCP)...")
        for ip in self.found_ips:
            if self.results["ips"][ip]["cdn"]:
                self.log("NMAP", f"跳过 CDN 节点: {ip}")
                continue
            
            self.log("NMAP", f"扫描 IP: {ip}")
            try:
                # -sV: 版本识别, -T4: 速度, -F: 快速扫描或指定端口
                cmd = ["nmap", "-sV", "-T4", "-p", COMMON_PORTS, "--open", ip]
                output = subprocess.check_output(cmd, stderr=subprocess.DEVNULL).decode()
                
                # 解析 Nmap 输出 (简单正则)
                matches = re.findall(r"(\d+)/tcp\s+open\s+([^\s]+)\s+(.*)", output)
                for port, service, version in matches:
                    self.results["ips"][ip]["ports"][port] = {
                        "service": service,
                        "version": version.strip()
                    }
                    self.log("OPEN", f"{ip}:{port} -> {service} ({version.strip()})")
            except Exception as e:
                self.log("!", f"Nmap 扫描 {ip} 失败: {e}")

    # =========================
    # 4. 目录结构爆破 (Gobuster/Built-in)
    # =========================
    def dir_brute(self):
        self.log("DIR", "正在探测 Web 目录结构...")
        
        # 准备字典
        wordlist_path = "wordlist.txt"
        if not os.path.exists(DEFAULT_WORDLIST):
            with open(wordlist_path, "w") as f:
                f.write("\n".join(BUILTIN_WORDLIST))
        else:
            wordlist_path = DEFAULT_WORDLIST

        for ip, data in self.results["ips"].items():
            # 仅对开放 80/443 或识别为 http 的端口进行爆破
            web_ports = [p for p, info in data["ports"].items() if "http" in info["service"] or p in ["80", "443", "8080"]]
            
            for port in web_ports:
                protocol = "https" if port in ["443", "8443"] else "http"
                target_url = f"{protocol}://{ip}:{port}/"
                self.log("DIR", f"爆破目标: {target_url}")
                
                try:
                    # 使用 gobuster 进行目录爆破
                    cmd = ["gobuster", "dir", "-u", target_url, "-w", wordlist_path, "-t", "20", "-q", "-n"]
                    output = subprocess.check_output(cmd, stderr=subprocess.DEVNULL).decode()
                    
                    dirs = []
                    for line in output.splitlines():
                        if "Status: 200" in line or "Status: 301" in line or "Status: 302" in line:
                            dirs.append(line.strip())
                    
                    if "dirs" not in self.results["ips"][ip]:
                        self.results["ips"][ip]["dirs"] = {}
                    self.results["ips"][ip]["dirs"][port] = dirs
                    
                    for d in dirs:
                        self.log("FOUND", f"{target_url} -> {d}")
                except:
                    # 如果 gobuster 失败，尝试简单的内置探测
                    self.log("!", f"Gobuster 失败，尝试基础探测 {target_url}")
                    found = []
                    for path in BUILTIN_WORDLIST:
                        try:
                            url = f"{target_url}{path}"
                            r = requests.get(url, timeout=2)
                            if r.status_code == 200:
                                found.append(f"/{path} (Status: 200)")
                        except:
                            continue
                    if found:
                        if "dirs" not in self.results["ips"][ip]:
                            self.results["ips"][ip]["dirs"] = {}
                        self.results["ips"][ip]["dirs"][port] = found

    # =========================
    # 5. 保存报告
    # =========================
    def save_report(self):
        with open(self.output_file, "w") as f:
            json.dump(self.results, f, indent=4)
        self.log("DONE", f"扫描完成！报告已保存至: {self.output_file}")

    def run(self):
        self.get_subdomains()
        self.resolve_and_check_cdn()
        self.scan_ports()
        self.dir_brute()
        self.save_report()

if __name__ == "__main__":
    target = input("输入目标域名 (例如 example.com): ").strip()
    if not target:
        print("域名不能为空")
        sys.exit(1)
    
    scanner = InfoWeave(target)
    scanner.run()
