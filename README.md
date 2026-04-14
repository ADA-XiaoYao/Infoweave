# InfoWeave - 顶级信息收集与漏洞预检仓库

InfoWeave 是一款专为渗透测试和红队评估设计的高效工具。它不仅集成了基础的资产发现功能，还通过 **InfoWeave Ultimate (APT Edition)** 实现了国际顶级侦察能力，且**完全不需要任何 API Key**。

## 核心功能

### 1. 基础版 (infoweave.py)
- **子域名收集**：集成 `subfinder` 引擎。
- **CDN 识别**：自动检测并过滤 CDN 节点。

### 2. 专业版 (infoweave_pro.py)
- **深度服务识别**：利用 `nmap` NSE 脚本识别中间件版本。
- **自动化漏洞扫描**：集成 `nuclei` 引擎。

### 3. 终极版 (infoweave_ultimate.py) - **[APT Edition]**
- **OSINT 深度关联**：
    - **SPF/MX 解析**：自动提取邮件记录中的隐藏 IP 段。
    - **GitHub 敏感信息探测**：自动化代码仓库关键字搜索（无需 Key）。
    - **Wayback 历史回溯**：分页抓取历史 URL、API 文档及备份文件。
- **网络空间测绘专精**：
    - **C 段 PTR 反向解析**：对发现的 IP 进行全网段 PTR 扫描，识别服务器用途。
    - **ASN 资产映射**：自动获取目标 AS 号并进行资产对齐。
- **隐蔽性与规避**：
    - **隐蔽扫描引擎**：集成 Nmap 的分片（-f）、诱饵（-D）及源端口（53）伪装技术。
    - **动态 User-Agent 池**：模拟多种浏览器指纹规避 WAF。
- **云原生与供应链**：
    - **云存储桶爆破**：自动化探测 S3/Azure Blob 公开访问权限。
    - **容器审计**：探测 K8s API、Docker Remote API 暴露风险。

## 安装要求

工具依赖以下外部组件，请确保已安装：

- Python 3.x
- `nmap` (完整版)
- `subfinder`
- `nuclei`
- `requests`, `beautifulsoup4` (Python 库)

## 使用方法

1. 克隆仓库：
   ```bash
   git clone https://github.com/ADA-XiaoYao/Infoweave.git
   cd Infoweave
   ```

2. 运行终极版：
   ```bash
   # 基础运行
   python3 infoweave_ultimate.py example.com
   
   # 高级参数
   python3 infoweave_ultimate.py example.com --timeout 30 --no-wayback
   ```

## 法律声明

本工具仅用于授权的渗透测试和安全研究。使用者需遵守当地法律法规，严禁用于非法攻击。
