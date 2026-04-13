#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Filename: infoweave_ultimate.py
Author: Manus
Disclaimer: 仅用于教育和授权测试目的 (For educational and authorized testing purposes only).
Description: 
    InfoWeave Ultimate 是一款顶级信息收集与漏洞预检工具，旨在模拟 APT 级别的侦察能力。
    本脚本在完全不使用任何 API Key 的前提下，集成了证书透明度挖掘、历史快照回溯、
    ASN 资产映射、隐蔽扫描、云原生安全检测及敏感路径探测等核心模块。
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
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from bs4 import BeautifulSoup

# =========================
# 配置与常量
# =========================
CDN_KEYWORDS = ["cloudflare", "akamai", "cloudfront", "fastly", "incapsula", "sucuri", "imperva"]
TCP_PORTS = "21,22,23,25,53,80,110,139,143,389,443,445,1433,1521,2049,3306,3389,5432,5900,6379,8000,8080,8443,9000,9200,27017"
UDP_PORTS = "53,67,68,69,123,161,162,500,4500,1900,5353"

class InfoWeaveUltimate:
    def __init__(self, domain):
        self.domain = domain
        self.subdomains = set()
        self.found_ips = {} # {ip: {"cdn": bool, "subdomains": [], "ports": {}, "vulns": [], "asn": "", "ptr": ""}}
        self.results = {
            "domain": domain,
            "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "summary": {"total_subdomains": 0, "total_ips": 0, "vulnerabilities": 0},
            "details": {}
        }
        self.output_file = f"ultimate_report_{domain.replace('.', '_')}.json"

    def log(self, tag, message):
        print(f"[{datetime.now().strftime('%H:%M:%S')}] [{tag}] {message}")

    # 1. 证书透明度挖掘 (crt.sh 爬虫 - 无需 API)
    def fetch_ct_logs(self):
        self.log("CT", f"正在从 crt.sh 挖掘 {self.domain} 的证书记录...")
        try:
            url = f"https://crt.sh/?q={self.domain}&output=json"
            r = requests.get(url, timeout=20)
            if r.status_code == 200:
                data = r.json()
                for entry in data:
                    name = entry['common_name']
                    if name.endswith(self.domain):
                        self.subdomains.add(name.replace("*.", ""))
                self.log("CT", f"通过证书日志新增发现 {len(self.subdomains)} 个潜在子域名")
        except Exception as e:
            self.log("!", f"crt.sh 抓取失败: {e}")

    # 2. 历史快照回溯 (Wayback Machine - 无需 API)
    def fetch_wayback_urls(self):
        self.log("WAYBACK", f"正在从 Wayback Machine 回溯历史 URL...")
        try:
            url = f"http://web.archive.org/cdx/search/cdx?url=*.{self.domain}/*&output=json&collapse=urlkey"
            r = requests.get(url, timeout=20)
            if r.status_code == 200:
                data = r.json()
                # data[0] 是 header，跳过
                for entry in data[1:]:
                    original_url = entry[2]
                    # 提取子域名
                    match = re.search(r'https?://([^/]+)', original_url)
                    if match:
                        sub = match.group(1)
                        if sub.endswith(self.domain):
                            self.subdomains.add(sub)
                self.log("WAYBACK", "历史 URL 解析完成")
        except Exception as e:
            self.log("!", f"Wayback 抓取失败: {e}")

    # 3. ASN 资产映射与反向 DNS (无需 API)
    def map_asn_and_ptr(self):
        self.log("ASN", "正在进行 ASN 映射与反向 DNS 查询...")
        for ip in list(self.found_ips.keys()):
            try:
                # 获取 PTR 记录
                ptr = socket.gethostbyaddr(ip)[0]
                self.found_ips[ip]["ptr"] = ptr
                self.log("PTR", f"{ip} -> {ptr}")
                
                # 简单模拟 ASN 获取 (通过 whois 命令行)
                cmd = f"whois {ip} | grep -iE 'origin|ASNumber|Organization' | head -n 5"
                whois_out = subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL).decode()
                self.found_ips[ip]["asn_info"] = whois_out.strip()
            except: pass

    # 4. 隐蔽扫描与规避 (Nmap 增强)
    def stealth_scan(self):
        self.log("STEALTH", "正在启动隐蔽扫描 (分片与诱饵技术)...")
        for ip, data in self.found_ips.items():
            if data["cdn"]: continue
            self.log("NMAP", f"隐蔽探测目标: {ip}")
            try:
                # -f: 分片, -D RND:10: 10个随机诱饵, -sS: SYN 扫描
                cmd = ["nmap", "-sS", "-sV", "-f", "-D", "RND:10", "--source-port", "53", "-p", TCP_PORTS, "--open", ip]
                output = subprocess.check_output(cmd, stderr=subprocess.DEVNULL).decode()
                
                matches = re.findall(r"(\d+)/tcp\s+open\s+([^\s]+)\s+(.*)", output)
                for port, service, version in matches:
                    data["ports"][port] = {"service": service, "version": version.strip()}
                    self.log("OPEN", f"{ip}:{port} -> {service}")
            except: pass

    # 5. 云原生与容器安全探测
    def cloud_container_audit(self):
        self.log("AUDIT", "正在探测云原生与容器暴露风险...")
        for ip, data in self.found_ips.items():
            if data["cdn"]: continue
            
            # 1. K8s API 匿名访问探测 (6443, 10250)
            for port in ["6443", "10250"]:
                try:
                    r = requests.get(f"https://{ip}:{port}/version", verify=False, timeout=3)
                    if r.status_code == 200:
                        self.log("ALERT", f"发现 K8s API 暴露: https://{ip}:{port}")
                        data["vulns"].append({"name": f"K8s API Exposure (Port {port})", "severity": "critical"})
                except: pass

            # 2. Docker Remote API 探测 (2375)
            try:
                r = requests.get(f"http://{ip}:2375/version", timeout=3)
                if r.status_code == 200:
                    self.log("ALERT", f"发现 Docker API 暴露: http://{ip}:2375")
                    data["vulns"].append({"name": "Docker Remote API Exposure", "severity": "critical"})
            except: pass

    # 6. 自动化漏洞扫描 (Nuclei)
    def run_nuclei(self):
        self.log("NUCLEI", "正在启动 Nuclei 深度扫描...")
        target_file = "ultimate_targets.txt"
        with open(target_file, "w") as f:
            for ip, data in self.found_ips.items():
                if not data["cdn"]: f.write(f"{ip}\n")
                for sub in data["subdomains"]: f.write(f"{sub}\n")

        try:
            cmd = ["nuclei", "-l", target_file, "-silent", "-severity", "medium,high,critical", "-jsonl"]
            output = subprocess.check_output(cmd, stderr=subprocess.DEVNULL).decode()
            for line in output.splitlines():
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
        except: pass

    def save_report(self):
        self.results["details"] = self.found_ips
        self.results["summary"]["total_subdomains"] = len(self.subdomains)
        self.results["summary"]["total_ips"] = len(self.found_ips)
        with open(self.output_file, "w") as f:
            json.dump(self.results, f, indent=4)
        self.log("DONE", f"终极报告已生成: {self.output_file}")

    def run(self):
        # 基础子域名收集
        try:
            cmd = ["subfinder", "-d", self.domain, "-silent"]
            res = subprocess.check_output(cmd).decode().splitlines()
            self.subdomains.update([s.strip() for s in res if s.strip()])
        except: pass
        
        self.fetch_ct_logs()
        self.fetch_wayback_urls()
        
        # 解析 IP
        for sub in list(self.subdomains):
            try:
                ip = socket.gethostbyname(sub)
                if ip not in self.found_ips:
                    self.found_ips[ip] = {"cdn": False, "subdomains": [], "ports": {}, "vulns": []}
                if sub not in self.found_ips[ip]["subdomains"]:
                    self.found_ips[ip]["subdomains"].append(sub)
            except: continue
            
        self.map_asn_and_ptr()
        self.stealth_scan()
        self.cloud_container_audit()
        self.run_nuclei()
        self.save_report()

if __name__ == "__main__":
    target = input("输入目标域名: ").strip()
    if target:
        scanner = InfoWeaveUltimate(target)
        scanner.run()
