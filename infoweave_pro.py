#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import subprocess
import socket
import requests
import json
import os
import sys
import re
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

# =========================
# 配置与常量
# =========================
CDN_KEYWORDS = ["cloudflare", "akamai", "cloudfront", "fastly", "incapsula", "sucuri", "imperva"]
# 常用 TCP 端口（包含数据库、中间件、远程管理）
TCP_PORTS = "21,22,23,25,53,80,110,139,143,389,443,445,1433,1521,2049,3306,3389,5432,5900,6379,8000,8080,8443,9000,9200,27017"
# 常用 UDP 端口
UDP_PORTS = "53,67,68,69,123,161,162,500,4500,1900,5353"

class InfoWeavePro:
    def __init__(self, domain):
        self.domain = domain
        self.subdomains = set()
        self.found_ips = {} # {ip: {"cdn": bool, "subdomains": [], "ports": {}, "vulns": []}}
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

    # 2. 真实 IP 识别与 CDN 过滤
    def resolve_assets(self):
        self.log("RESOLVE", "正在解析资产并识别 CDN...")
        for sub in self.subdomains:
            try:
                ip = socket.gethostbyname(sub)
                if ip not in self.found_ips:
                    self.found_ips[ip] = {"cdn": False, "subdomains": [], "ports": {}, "vulns": [], "cloud": "unknown"}
                
                if sub not in self.found_ips[ip]["subdomains"]:
                    self.found_ips[ip]["subdomains"].append(sub)

                # CDN 检测
                try:
                    r = requests.get(f"http://{sub}", timeout=2, allow_redirects=True)
                    headers = str(r.headers).lower()
                    if any(kw in headers for kw in CDN_KEYWORDS):
                        self.found_ips[ip]["cdn"] = True
                except: pass
            except: continue
        
        # 云资产识别 (简单示例：Azure/AWS)
        for ip in self.found_ips:
            try:
                host = socket.gethostbyaddr(ip)[0]
                if "azure" in host: self.found_ips[ip]["cloud"] = "Azure"
                elif "aws" in host or "amazon" in host: self.found_ips[ip]["cloud"] = "AWS"
            except: pass

    # 3. 深度端口扫描与服务识别 (Nmap NSE)
    def deep_scan(self):
        self.log("NMAP", "正在进行深度端口扫描与服务识别...")
        for ip, data in self.found_ips.items():
            if data["cdn"]: continue
            
            self.log("NMAP", f"扫描目标: {ip} (Cloud: {data['cloud']})")
            try:
                # -sV: 版本, -sC: 默认脚本, --script=vulners: 漏洞匹配
                cmd = ["nmap", "-sV", "-p", TCP_PORTS, "--open", "--script=banner,http-title", ip]
                output = subprocess.check_output(cmd, stderr=subprocess.DEVNULL).decode()
                
                # 解析端口与服务
                matches = re.findall(r"(\d+)/tcp\s+open\s+([^\s]+)\s+(.*)", output)
                for port, service, version in matches:
                    data["ports"][port] = {"service": service, "version": version.strip()}
                    self.log("OPEN", f"{ip}:{port} -> {service} ({version.strip()})")
                
                # 提取标题
                title_match = re.search(r"http-title: (.*)", output)
                if title_match: data["title"] = title_match.group(1).strip()
            except: pass

    # 4. 自动化漏洞扫描 (Nuclei)
    def vuln_scan(self):
        self.log("NUCLEI", "正在启动 Nuclei 自动化漏洞扫描...")
        target_file = "targets.txt"
        with open(target_file, "w") as f:
            for ip, data in self.found_ips.items():
                if data["cdn"]: continue
                f.write(f"{ip}\n")
                for sub in data["subdomains"]: f.write(f"{sub}\n")

        try:
            # 扫描低、中、高、严重漏洞
            cmd = ["nuclei", "-l", target_file, "-silent", "-severity", "medium,high,critical", "-jsonl"]
            output = subprocess.check_output(cmd, stderr=subprocess.DEVNULL).decode()
            
            for line in output.splitlines():
                vuln = json.loads(line)
                ip_or_host = vuln.get("ip", vuln.get("host"))
                # 匹配回对应的 IP
                for ip in self.found_ips:
                    if ip == ip_or_host or any(sub in ip_or_host for sub in self.found_ips[ip]["subdomains"]):
                        self.found_ips[ip]["vulns"].append({
                            "name": vuln.get("info", {}).get("name"),
                            "severity": vuln.get("info", {}).get("severity"),
                            "id": vuln.get("template-id")
                        })
                        self.log("VULN", f"发现漏洞: {ip_or_host} -> {vuln.get('info', {}).get('name')} [{vuln.get('info', {}).get('severity')}]")
                        self.results["summary"]["vulnerabilities"] += 1
        except Exception as e:
            self.log("!", f"Nuclei 扫描失败: {e}")

    # 5. 云元数据与敏感路径探测
    def cloud_and_dir_brute(self):
        self.log("BRUTE", "正在进行云元数据与敏感路径探测...")
        for ip, data in self.found_ips.items():
            if data["cdn"]: continue
            
            # 针对 Azure/AWS 的元数据探测 (SSRF 预检)
            if data["cloud"] != "unknown":
                self.log("CLOUD", f"检测到云资产 {ip}，尝试元数据路径...")
                paths = ["/latest/meta-data/", "/metadata/instance?api-version=2017-08-01"]
                for p in paths:
                    try:
                        r = requests.get(f"http://{ip}{p}", timeout=2)
                        if r.status_code == 200:
                            self.log("ALERT", f"可能存在云元数据泄露: http://{ip}{p}")
                            data["vulns"].append({"name": "Potential Cloud Metadata Exposure", "severity": "high"})
                    except: pass

            # 基础目录爆破 (针对 Web 端口)
            web_ports = [p for p, info in data["ports"].items() if "http" in info["service"] or p in ["80", "443", "8080"]]
            for port in web_ports:
                target = f"http://{ip}:{port}/"
                try:
                    # 探测 .git, .env, /admin, /config
                    for path in [".git/config", ".env", "admin/", "phpinfo.php"]:
                        r = requests.get(f"{target}{path}", timeout=2)
                        if r.status_code == 200:
                            self.log("FOUND", f"敏感路径: {target}{path}")
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
        self.get_subdomains()
        self.resolve_assets()
        self.deep_scan()
        self.vuln_scan()
        self.cloud_and_dir_brute()
        self.save_report()

if __name__ == "__main__":
    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        target = input("输入目标域名: ").strip()
    
    if target:
        scanner = InfoWeavePro(target)
        scanner.run()
