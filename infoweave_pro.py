#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Filename: infoweave_pro.py
Author: Manus
Disclaimer: 仅用于教育和授权测试目的 (For educational and authorized testing purposes only).
Description: 
    InfoWeave Pro 是一款专业的信息收集与漏洞预检工具。
    [修复版]：针对大量子域名解析卡死问题，引入了并发解析、超时控制及优雅的键盘中断响应。
Legal Disclaimer: 
    严禁将本脚本用于任何未经授权的攻击行为。使用者需对自己的行为承担全部法律责任。
"""

import subprocess
import socket
import requests
import json
import os
import sys
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from urllib3.exceptions import InsecureRequestWarning

# 禁用不安全请求警告
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

# =========================
# 配置与常量
# =========================
CDN_KEYWORDS = ["cloudflare", "akamai", "cloudfront", "fastly", "incapsula", "sucuri", "imperva"]
TCP_PORTS = "21,22,23,25,53,80,110,139,143,389,443,445,1433,1521,2049,3306,3389,5432,5900,6379,8000,8080,8443,9000,9200,27017"
MAX_WORKERS = 20
DEFAULT_TIMEOUT = 5

class InfoWeavePro:
    def __init__(self, domain):
        self.domain = domain
        self.subdomains = set()
        self.found_ips = {} # {ip: {"cdn": bool, "subdomains": [], "ports": {}, "vulns": [], "cloud": "unknown"}}
        self.results = {
            "domain": domain,
            "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "summary": {"total_subdomains": 0, "total_ips": 0, "vulnerabilities": 0},
            "details": {}
        }
        self.output_file = f"pro_report_{domain.replace('.', '_')}.json"

    def log(self, tag, message):
        print(f"[{datetime.now().strftime('%H:%M:%S')}] [{tag}] {message}")

    # 1. 增强型子域名收集
    def get_subdomains(self):
        self.log("SUB", f"正在深度收集 {self.domain} 的子域名...")
        try:
            cmd = ["subfinder", "-d", self.domain, "-silent", "-all"]
            result = subprocess.check_output(cmd, stderr=subprocess.DEVNULL).decode().splitlines()
            for sub in result:
                if sub.strip(): self.subdomains.add(sub.strip())
            self.log("SUB", f"发现 {len(self.subdomains)} 个子域名")
        except Exception as e:
            self.log("!", f"Subfinder 失败: {e}")

    # 2. 真实 IP 识别与 CDN 过滤 (并发优化)
    def resolve_assets(self):
        self.log("RESOLVE", f"正在并发解析 {len(self.subdomains)} 个子域名的资产并识别 CDN...")
        
        def process_subdomain(sub):
            try:
                ip = socket.gethostbyname(sub)
                cdn_flag = False
                # 简单 CDN 检测
                try:
                    r = requests.get(f"http://{sub}", timeout=DEFAULT_TIMEOUT, allow_redirects=False, verify=False)
                    headers = str(r.headers).lower()
                    if any(kw in headers for kw in CDN_KEYWORDS):
                        cdn_flag = True
                except: pass
                return (sub, ip, cdn_flag)
            except:
                return None

        count = 0
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = {executor.submit(process_subdomain, sub): sub for sub in self.subdomains}
            try:
                for future in as_completed(futures):
                    res = future.result()
                    if res:
                        sub, ip, cdn_flag = res
                        if ip not in self.found_ips:
                            self.found_ips[ip] = {"cdn": cdn_flag, "subdomains": [], "ports": {}, "vulns": [], "cloud": "unknown"}
                        if sub not in self.found_ips[ip]["subdomains"]:
                            self.found_ips[ip]["subdomains"].append(sub)
                        if cdn_flag: self.found_ips[ip]["cdn"] = True
                    
                    count += 1
                    if count % 50 == 0:
                        self.log("RESOLVE", f"进度: {count}/{len(self.subdomains)}")
            except KeyboardInterrupt:
                self.log("!", "用户中断解析，正在保存当前已解析的资产...")
                raise KeyboardInterrupt

        # 云资产识别
        for ip in self.found_ips:
            try:
                host = socket.gethostbyaddr(ip)[0]
                if "azure" in host: self.found_ips[ip]["cloud"] = "Azure"
                elif "aws" in host or "amazon" in host: self.found_ips[ip]["cloud"] = "AWS"
            except: pass

    # 3. 深度端口扫描与服务识别
    def deep_scan(self):
        self.log("NMAP", "正在进行深度端口扫描与服务识别...")
        for ip, data in self.found_ips.items():
            if data["cdn"]: continue
            self.log("NMAP", f"扫描目标: {ip}")
            try:
                cmd = ["nmap", "-sV", "-p", TCP_PORTS, "--open", "--script=banner,http-title", "--host-timeout", "5m", ip]
                output = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, timeout=310).decode()
                matches = re.findall(r"(\d+)/tcp\s+open\s+([^\s]+)\s+(.*)", output)
                for port, service, version in matches:
                    data["ports"][port] = {"service": service, "version": version.strip()}
                    self.log("OPEN", f"{ip}:{port} -> {service}")
            except: pass

    # 4. 自动化漏洞扫描 (Nuclei)
    def vuln_scan(self):
        self.log("NUCLEI", "正在启动 Nuclei 自动化漏洞扫描...")
        target_file = "targets.txt"
        with open(target_file, "w") as f:
            for ip, data in self.found_ips.items():
                if not data["cdn"]: f.write(f"{ip}\n")
                for sub in data["subdomains"]: f.write(f"{sub}\n")

        try:
            cmd = ["nuclei", "-l", target_file, "-silent", "-severity", "medium,high,critical", "-jsonl"]
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
            for line in process.stdout:
                try:
                    vuln = json.loads(line)
                    ip_or_host = vuln.get("ip", vuln.get("host"))
                    for ip in self.found_ips:
                        if ip == ip_or_host or any(sub in ip_or_host for sub in self.found_ips[ip]["subdomains"]):
                            self.found_ips[ip]["vulns"].append({
                                "name": vuln.get("info", {}).get("name"),
                                "severity": vuln.get("info", {}).get("severity"),
                                "id": vuln.get("template-id")
                            })
                            self.results["summary"]["vulnerabilities"] += 1
                except: continue
        except: pass

    # 5. 云元数据与敏感路径探测
    def cloud_and_dir_brute(self):
        self.log("BRUTE", "正在进行云元数据与敏感路径探测...")
        for ip, data in self.found_ips.items():
            if data["cdn"]: continue
            if data["cloud"] != "unknown":
                paths = ["/latest/meta-data/", "/metadata/instance?api-version=2017-08-01"]
                for p in paths:
                    try:
                        r = requests.get(f"http://{ip}{p}", timeout=3)
                        if r.status_code == 200:
                            data["vulns"].append({"name": "Potential Cloud Metadata Exposure", "severity": "high"})
                    except: pass

            web_ports = [p for p, info in data["ports"].items() if "http" in info["service"] or p in ["80", "443", "8080"]]
            for port in web_ports:
                target = f"http://{ip}:{port}/"
                try:
                    for path in [".git/config", ".env", "admin/", "phpinfo.php"]:
                        r = requests.get(f"{target}{path}", timeout=2)
                        if r.status_code == 200:
                            data["vulns"].append({"name": f"Sensitive Path: {path}", "severity": "medium"})
                except: pass

    def save_report(self):
        self.results["details"] = self.found_ips
        self.results["summary"]["total_subdomains"] = len(self.subdomains)
        self.results["summary"]["total_ips"] = len(self.found_ips)
        with open(self.output_file, "w") as f:
            json.dump(self.results, f, indent=4)
        self.log("DONE", f"报告已生成: {self.output_file}")

    def run(self):
        try:
            self.get_subdomains()
            self.resolve_assets()
            self.deep_scan()
            self.vuln_scan()
            self.cloud_and_dir_brute()
            self.save_report()
        except KeyboardInterrupt:
            self.log("!", "检测到 Ctrl+C，正在保存当前结果并退出...")
            self.save_report()
            sys.exit(130)

if __name__ == "__main__":
    target = input("输入目标域名: ").strip()
    if target:
        scanner = InfoWeavePro(target)
        scanner.run()
    else:
        sys.exit(1)
