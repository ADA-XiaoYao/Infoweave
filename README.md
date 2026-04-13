# InfoWeave - 顶级信息收集与漏洞预检仓库

InfoWeave 是一款专为渗透测试和红队评估设计的高效工具。它不仅集成了基础的资产发现功能，还通过 **InfoWeave Pro** 实现了自动化的漏洞扫描与深度探测，且**完全不需要任何 API Key**。

## 核心功能

### 1. 基础版 (infoweave.py)
- **子域名收集**：集成 `subfinder` 引擎。
- **CDN 识别**：自动检测并过滤 CDN 节点。
- **端口扫描**：快速识别常用开放端口。

### 2. 专业版 (infoweave_pro.py) - **NEW!**
- **深度服务识别**：利用 `nmap` NSE 脚本识别中间件版本、标题及 Banner。
- **自动化漏洞扫描**：集成 `nuclei` 引擎，自动匹配中、高、严重级别漏洞模板。
- **云原生安全检测**：针对 Azure/AWS IP 自动进行元数据服务（SSRF）探测。
- **敏感路径探测**：自动爆破 `.git`, `.env`, `admin` 等高危路径。
- **全协议支持**：支持 TCP 全端口扫描与高频 UDP 探测。

## 安装要求

工具依赖以下外部组件，请确保已安装：

- Python 3.x
- `nmap` (建议安装完整版以支持 NSE 脚本)
- `subfinder`
- `nuclei` (专业版必需)
- `requests` (Python 库)

## 使用方法

1. 克隆仓库：
   ```bash
   git clone https://github.com/ADA-XiaoYao/Infoweave.git
   cd Infoweave
   ```

2. 运行专业版：
   ```bash
   python3 infoweave_pro.py
   ```

3. 输入目标域名（如 `example.com`），等待扫描完成。结果将保存为 `pro_report_domain.json`。

## 法律声明

本工具仅用于授权的渗透测试和安全研究。使用者需遵守当地法律法规，严禁用于非法攻击。
