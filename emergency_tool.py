# -*- coding: utf-8 -*-
"""
蚂蚁安全 - Windows应急排查工具
Copyright (C) 蚂蚁安全 (www.mayisafe.cn)
"""

import os
import sys
import json
import subprocess
import socket
import re
import hashlib
import base64
import requests
import threading
import webbrowser
import tempfile
from datetime import datetime
from pathlib import Path
from urllib.parse import quote

# ====== AI 模块 ======
class AIModule:
    """内置AI分析引擎"""
    
    def __init__(self):
        self.api_key = None
        self.endpoint = "https://api.minimax.chat/v1"
        self.model = "MiniMax-Text-01"
        self.api_type = "minimax"
        self.group_id = None
        
    def load_config(self):
        """加载AI配置"""
        config_path = os.path.join(os.path.dirname(__file__), "ai_config.json")
        if os.path.exists(config_path):
            with open(config_path, "r", encoding="utf-8") as f:
                config = json.load(f)
                self.api_key = config.get("api_key", "")
                self.endpoint = config.get("endpoint", self.endpoint)
                self.model = config.get("model", self.model)
                self.api_type = config.get("api_type", self.api_type)
                self.group_id = config.get("group_id", "")
                
    def save_config(self, api_key, endpoint, model, api_type, group_id=""):
        """保存AI配置"""
        config = {
            "api_key": api_key,
            "endpoint": endpoint,
            "model": model,
            "api_type": api_type,
            "group_id": group_id
        }
        config_path = os.path.join(os.path.dirname(__file__), "ai_config.json")
        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2, ensure_ascii=False)
        self.api_key = api_key
        self.endpoint = endpoint
        self.model = model
        self.api_type = api_type
        self.group_id = group_id
        
    def analyze(self, prompt, context=""):
        """使用AI分析威胁"""
        if not self.api_key:
            return None, "AI API未配置，请在设置中配置API密钥"
            
        full_prompt = f"""【威胁分析任务】
{context}

请分析以下检测结果，给出专业的安全分析意见：
{prompt}

请返回JSON格式：
{{
    "threat_level": "严重/高危/中危/低危/安全",
    "threat_type": "威胁类型",
    "analysis": "详细分析说明",
    "recommendations": ["建议1", "建议2", "建议3"],
    "evidence": ["证据1", "证据2"]
}}
"""
        
        try:
            if self.api_type == "minimax":
                return self._call_minimax(full_prompt)
            elif self.api_type == "kimi":
                return self._call_kimi(full_prompt)
            elif self.api_type == "deepseek":
                return self._call_deepseek(full_prompt)
            elif self.api_type == "qwen":
                return self._call_qwen(full_prompt)
            elif self.api_type == "openai":
                return self._call_openai(full_prompt)
            else:
                return None, "不支持的API类型"
        except Exception as e:
            return None, f"AI分析出错: {str(e)}"
    
    def _call_minimax(self, prompt):
        """调用MiniMax API"""
        url = f"{self.endpoint}/text/chatcompletion_v2"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        payload = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.3,
            "max_tokens": 2048
        }
        response = requests.post(url, headers=headers, json=payload, timeout=60)
        if response.status_code == 200:
            result = response.json()
            content = result.get("choices", [{}])[0].get("message", {}).get("content", "")
            try:
                return json.loads(content), None
            except:
                return {"raw_response": content}, None
        else:
            return None, f"API调用失败: {response.status_code} - {response.text}"
    
    def _call_kimi(self, prompt):
        """调用Kimi API"""
        url = "https://api.moonshot.cn/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        payload = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.3
        }
        response = requests.post(url, headers=headers, json=payload, timeout=60)
        if response.status_code == 200:
            result = response.json()
            content = result.get("choices", [{}])[0].get("message", {}).get("content", "")
            try:
                return json.loads(content), None
            except:
                return {"raw_response": content}, None
        else:
            return None, f"API调用失败: {response.status_code}"
    
    def _call_deepseek(self, prompt):
        """调用DeepSeek API"""
        url = "https://api.deepseek.com/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        payload = {
            "model": self.model or "deepseek-chat",
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.3
        }
        response = requests.post(url, headers=headers, json=payload, timeout=60)
        if response.status_code == 200:
            result = response.json()
            content = result.get("choices", [{}])[0].get("message", {}).get("content", "")
            try:
                return json.loads(content), None
            except:
                return {"raw_response": content}, None
        else:
            return None, f"API调用失败: {response.status_code} - {response.text}"
    
    def _call_qwen(self, prompt):
        """调用阿里千问API"""
        url = f"https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        payload = {
            "model": self.model or "qwen-plus",
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.3
        }
        response = requests.post(url, headers=headers, json=payload, timeout=60)
        if response.status_code == 200:
            result = response.json()
            content = result.get("choices", [{}])[0].get("message", {}).get("content", "")
            try:
                return json.loads(content), None
            except:
                return {"raw_response": content}, None
        else:
            return None, f"API调用失败: {response.status_code} - {response.text}"
    
    def _call_openai(self, prompt):
        """调用OpenAI兼容API"""
        url = f"{self.endpoint}/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        payload = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.3
        }
        response = requests.post(url, headers=headers, json=payload, timeout=60)
        if response.status_code == 200:
            result = response.json()
            content = result.get("choices", [{}])[0].get("message", {}).get("content", "")
            try:
                return json.loads(content), None
            except:
                return {"raw_response": content}, None
        else:
            return None, f"API调用失败: {response.status_code}"


# ====== 检测模块基类 ======
class DetectionModule:
    """检测模块基类"""
    name = "基础模块"
    description = "基础检测"
    threat_type = "未知威胁"
    
    def __init__(self):
        self.findings = []
        
    def check(self, progress_callback=None):
        """执行检测"""
        raise NotImplementedError
        
    def get_findings(self):
        """获取检测结果"""
        return self.findings


# ====== 挖矿检测模块 ======
class MiningDetector(DetectionModule):
    """挖矿木马检测"""
    name = "挖矿检测"
    description = "检测挖矿木马、矿池连接、异常CPU占用"
    threat_type = "挖矿木马"
    
    def __init__(self):
        super().__init__()
        self.mining_processes = [
            "xmrig", "miner", "minerd", "stratum", "nicehash", "ethminer",
            "cgminer", "bfgminer", "sgminer", "ccminer", "claymore", "nbminer",
            "bminer", "t-rex", "stratum", "cryptonight", "phoenixminer", "gminer",
            "lolminer", "beam", "aionminer", "rift", "kaspa"
        ]
        self.mining_urls = ["mining", "pool", "stratum", "cryptonight", "算法"]
        self.suspicious_ports = [3333, 4444, 5555, 6666, 7777, 8888, 9999, 14444, 14433, 16999, 17999, 18080]
        
    def check(self, progress_callback=None):
        self.findings = []
        
        if progress_callback:
            progress_callback(10, "检查系统进程...")        
        self._check_processes()
        
        if progress_callback:
            progress_callback(40, "检查网络连接...")        
        self._check_network()
        
        if progress_callback:
            progress_callback(60, "检查启动项...")        
        self._check_startup()
        
        if progress_callback:
            progress_callback(80, "检查计划任务...")        
        self._check_scheduled_tasks()
        
        if progress_callback:
            progress_callback(100, "检查完成")
            
        return self.findings
    
    def _check_processes(self):
        """检查可疑进程"""
        try:
            result = subprocess.run(
                ["powershell", "-Command", 
                 "Get-Process | Select-Object Name, Id, CPU, @{N='Path';E={$_.Path}}, "
                 "@{N='Company';E={$_.CompanyName}} | ConvertTo-Json -Compress"],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0:
                processes = json.loads(result.stdout)
                if isinstance(processes, dict):
                    processes = [processes]
                for proc in processes:
                    name = proc.get("Name", "").lower()
                    path = proc.get("Path") or ""
                    for mining_proc in self.mining_processes:
                        if mining_proc in name:
                            self.findings.append({
                                "type": "进程",
                                "severity": "高危",
                                "name": proc.get("Name"),
                                "pid": proc.get("Id"),
                                "path": path,
                                "description": f"发现可疑挖矿进程: {proc.get('Name')}，路径: {path}"
                            })
                    # 检查高CPU占用的无签名进程
                    if not path and name not in ["system", "svchost", "lsass", "csrss", "wininit", "services"]:
                        if proc.get("CPU", 0) > 50:
                            self.findings.append({
                                "type": "高CPU进程",
                                "severity": "中危",
                                "name": proc.get("Name"),
                                "pid": proc.get("Id"),
                                "cpu": proc.get("CPU"),
                                "description": f"高CPU占用无签名进程: {proc.get('Name')} (CPU: {proc.get('CPU')}%)"
                            })
        except Exception as e:
            self.findings.append({"type": "错误", "severity": "信息", "description": f"进程检查出错: {str(e)}"})
    
    def _check_network(self):
        """检查网络连接"""
        try:
            result = subprocess.run(
                ["powershell", "-Command",
                 "Get-NetTCPConnection -State Established | Select-Object -First 200 | "
                 "Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess | "
                 "ConvertTo-Json -Compress"],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0:
                connections = json.loads(result.stdout)
                if isinstance(connections, dict):
                    connections = [connections]
                for conn in connections:
                    remote_ip = conn.get("RemoteAddress", "")
                    remote_port = conn.get("RemotePort", "")
                    # 检查矿池常用端口
                    if remote_port in self.suspicious_ports:
                        self.findings.append({
                            "type": "网络连接",
                            "severity": "高危",
                            "remote": f"{remote_ip}:{remote_port}",
                            "local_port": conn.get("LocalPort"),
                            "pid": conn.get("OwningProcess"),
                            "description": f"可疑矿池端口连接: {remote_ip}:{remote_port}，PID: {conn.get('OwningProcess')}"
                        })
        except Exception as e:
            self.findings.append({"type": "错误", "severity": "信息", "description": f"网络检查出错: {str(e)}"})
    
    def _check_startup(self):
        """检查启动项"""
        try:
            result = subprocess.run(
                ["powershell", "-Command",
                 "Get-CimInstance Win32_StartupCommand | Select-Object Name, Command, Location | "
                 "ConvertTo-Json -Compress"],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0:
                items = json.loads(result.stdout)
                if isinstance(items, dict):
                    items = [items]
                for item in items:
                    cmd = str(item.get("Command", "")).lower()
                    for mining in self.mining_processes:
                        if mining in cmd:
                            self.findings.append({
                                "type": "启动项",
                                "severity": "高危",
                                "name": item.get("Name"),
                                "command": item.get("Command"),
                                "location": item.get("Location"),
                                "description": f"可疑挖矿启动项: {item.get('Name')}，位置: {item.get('Location')}"
                            })
        except Exception as e:
            self.findings.append({"type": "错误", "severity": "信息", "description": f"启动项检查出错: {str(e)}"})
    
    def _check_scheduled_tasks(self):
        """检查计划任务"""
        try:
            result = subprocess.run(
                ["powershell", "-Command",
                 "Get-ScheduledTask | Where-Object {$_.State -eq 'Running'} | "
                 "Get-ScheduledTaskInfo | Select-Object TaskName, TaskPath, LastRunTime | "
                 "ConvertTo-Json -Compress"],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0:
                tasks = json.loads(result.stdout)
                if isinstance(tasks, dict):
                    tasks = [tasks]
                for task in tasks:
                    name = str(task.get("TaskName", "")).lower()
                    for mining in self.mining_processes:
                        if mining in name:
                            self.findings.append({
                                "type": "计划任务",
                                "severity": "高危",
                                "name": task.get("TaskName"),
                                "path": task.get("TaskPath"),
                                "description": f"可疑挖矿计划任务: {task.get('TaskName')}"
                            })
        except Exception as e:
            self.findings.append({"type": "错误", "severity": "信息", "description": f"计划任务检查出错: {str(e)}"})


# ====== 勒索检测模块 ======
class RansomwareDetector(DetectionModule):
    """勒索病毒检测"""
    name = "勒索检测"
    description = "检测勒索病毒、加密文件、勒索信"
    threat_type = "勒索病毒"
    
    def __init__(self):
        super().__init__()
        self.ransomware_extensions = [
            ".encrypted", ".locked", ".crypto", ".crypt", ".enc", ".locked",
            ".encrypted", ".cryptid", ".crypto", ".locky", ".wnry", ".wcry",
            ".thor", ".zepto", ".lock", ".crypto", ".crypt38", ".micro",
            ".harma", ".rmd", ".horse", ".控", ".敲诈", ".求救", ".恢复",
            ".encrypted AES", ".RSA4096", ".777", ".aaa", ".xyz", ".vvv",
            ".onion", ".tor", ".bitcoin", ".wallet", ".key"
        ]
        self.ransomware_files = [
            "readme", "readme.txt", "how_to_decrypt", "decrypt", "restore",
            "恢复", "解密", "注意", "WARNING", "INSTRUCTIONS", "README_RESTORE",
            "YOUR_FILES", "RECOVERY", "DECRYPT_INSTRUCTIONS"
        ]
        self.suspicious_processes = [
            "vssadmin", "wmic", "bcdedit", "wbadmin", "diskshadow",
            "cipher", "net", "schtasks", "reg", "vssadmin.exe"
        ]
        
    def check(self, progress_callback=None):
        self.findings = []
        
        if progress_callback:
            progress_callback(15, "检查文件加密痕迹...")        
        self._check_encrypted_files()
        
        if progress_callback:
            progress_callback(35, "检查勒索信...")        
        self._check_ransom_notes()
        
        if progress_callback:
            progress_callback(55, "检查卷影删除...")        
        self._check_shadow_copy()
        
        if progress_callback:
            progress_callback(70, "检查可疑进程...")        
        self._check_processes()
        
        if progress_callback:
            progress_callback(85, "检查启动恢复功能...")        
        self._check_recovery_disabled()
        
        if progress_callback:
            progress_callback(100, "检查完成")
            
        return self.findings
    
    def _check_encrypted_files(self):
        """检查被加密的文件"""
        try:
            search_paths = []
            for drive in ["C:", "D:", "E:", "F:"]:
                for path in [f"{drive}\\Users", f"{drive}\\Document", f"{drive}\\Desktop"]:
                    if os.path.exists(path):
                        search_paths.append(path)
            
            for base_path in search_paths[:3]:
                for root, dirs, files in os.walk(base_path):
                    # 跳过系统目录
                    dirs[:] = [d for d in dirs if d not in ["Windows", "Windows.old", "Program Files", "Program Files (x86)", "$Recycle.Bin", "System Volume Information"]]
                    
                    for file in files:
                        ext = os.path.splitext(file)[1].lower()
                        if ext in self.ransomware_extensions:
                            filepath = os.path.join(root, file)
                            self.findings.append({
                                "type": "加密文件",
                                "severity": "严重",
                                "file": filepath,
                                "name": file,
                                "description": f"发现疑似勒索加密文件: {file}，完整路径: {filepath}"
                            })
                    if len(files) > 5000:
                        break
        except Exception as e:
            self.findings.append({"type": "错误", "severity": "信息", "description": f"加密文件检查出错: {str(e)}"})
    
    def _check_ransom_notes(self):
        """检查勒索信"""
        try:
            search_dirs = [
                os.path.expanduser("~"),
                os.path.join(os.path.expanduser("~"), "Desktop"),
                os.path.join(os.path.expanduser("~"), "Documents"),
                "C:\\", "D:\\"
            ]
            
            for base_dir in search_dirs[:3]:
                if not os.path.exists(base_dir):
                    continue
                for root, dirs, files in os.walk(base_dir):
                    dirs[:] = [d for d in dirs if d not in ["Windows", "$Recycle.Bin", "System Volume Information"]]
                    
                    for file in files:
                        filename_lower = file.lower()
                        for ransom_file in self.ransomware_files:
                            if ransom_file in filename_lower:
                                filepath = os.path.join(root, file)
                                try:
                                    size = os.path.getsize(filepath)
                                    if size < 5 * 1024 * 1024:
                                        self.findings.append({
                                            "type": "勒索信",
                                            "severity": "严重",
                                            "file": filepath,
                                            "name": file,
                                            "size": size,
                                            "description": f"发现勒索信文件: {file}，路径: {filepath}"
                                        })
                                except:
                                    pass
                    if len(files) > 3000:
                        break
        except Exception as e:
            self.findings.append({"type": "错误", "severity": "信息", "description": f"勒索信检查出错: {str(e)}"})
    
    def _check_shadow_copy(self):
        """检查卷影删除"""
        try:
            result = subprocess.run(["vssadmin", "list", "shadow"], 
                                   capture_output=True, text=True, timeout=10)
            if "No items found" in result.stdout or result.returncode != 0:
                self.findings.append({
                    "type": "卷影删除",
                    "severity": "高危",
                    "description": "卷影副本已被删除或无法访问（勒索软件特征）"
                })
        except:
            pass
        
        # 检查系统还原是否被禁用
        try:
            result = subprocess.run(
                ["powershell", "-Command",
                 "Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SystemRestore' | "
                 "Select-Object DisableSR, DisableConfigDisks | ConvertTo-Json"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                props = json.loads(result.stdout)
                if props.get("DisableSR") == 1 or props.get("DisableConfigDisks") == 1:
                    self.findings.append({
                        "type": "系统还原",
                        "severity": "高危",
                        "description": "系统还原功能被禁用"
                    })
        except:
            pass
    
    def _check_processes(self):
        """检查勒索相关进程"""
        try:
            result = subprocess.run(
                ["powershell", "-Command",
                 "Get-Process | Select-Object Name, Id, Path | ConvertTo-Json -Compress"],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0:
                processes = json.loads(result.stdout)
                if isinstance(processes, dict):
                    processes = [processes]
                for proc in processes:
                    name = proc.get("Name", "").lower()
                    if name in self.suspicious_processes:
                        self.findings.append({
                            "type": "可疑进程",
                            "severity": "高危",
                            "name": proc.get("Name"),
                            "pid": proc.get("Id"),
                            "path": proc.get("Path") or "无路径",
                            "description": f"勒索相关进程: {proc.get('Name')}，路径: {proc.get('Path', '无')}"
                        })
        except Exception as e:
            self.findings.append({"type": "错误", "severity": "信息", "description": f"进程检查出错: {str(e)}"})
    
    def _check_recovery_disabled(self):
        """检查恢复功能是否被禁用"""
        try:
            result = subprocess.run(["bcdedit"], capture_output=True, text=True, timeout=10)
            for line in result.stdout.split("\n"):
                if "recoveryenabled" in line.lower() and "yes" not in line.lower():
                    self.findings.append({
                        "type": "启动恢复",
                        "severity": "高危",
                        "description": "Windows启动恢复功能被禁用"
                    })
                    break
        except:
            pass


# ====== 翻墙/VPN检测模块 ======
class VPNDetector(DetectionModule):
    """翻墙/VPN检测"""
    name = "翻墙检测"
    description = "检测VPN、代理、翻墙软件"
    threat_type = "翻墙行为"
    
    def __init__(self):
        super().__init__()
        self.vpn_processes = [
            "v2ray", "xray", "shadowsocks", "ss-local", "ss-server", "shadowsocksr",
            "trojan", "trojan-go", "naiveproxy", "lantern", "蓝灯", "expressvpn",
            "nordvpn", "ipvanish", "vyprvpn", "openvpn", "wireguard", "softether",
            "proxifier", "skype", "telegram", "whatsapp", "skype",
            "clash", "v2rayng", "v2rayn", "quantumult", "surge", "shadowrocket",
            "anxpro", "gfw", "pptp", "l2tp", "ikev2", "sstap", "sockscap",
            " Brook", "mellow", "outline", "fqrouter", "VPN", "GoProxy", "goproxy"
        ]
        self.vpn_ports = [1080, 10808, 10809, 8118, 8123, 7890, 7891, 7892, 8080, 8888, 2080, 1081, 10087]
        self.proxy_keywords = ["proxy", "vpn", "tunnel", "shadowsocks", "trojan", "xray", "v2ray"]
        
    def check(self, progress_callback=None):
        self.findings = []
        
        if progress_callback:
            progress_callback(15, "检查翻墙进程...")        
        self._check_processes()
        
        if progress_callback:
            progress_callback(35, "检查网络连接...")        
        self._check_network()
        
        if progress_callback:
            progress_callback(50, "检查VPN适配器...")        
        self._check_vpn_adapters()
        
        if progress_callback:
            progress_callback(65, "检查代理设置...")        
        self._check_proxy_settings()
        
        if progress_callback:
            progress_callback(80, "检查翻墙流量...")        
        self._check_suspicious_traffic()
        
        if progress_callback:
            progress_callback(100, "检查完成")
            
        return self.findings
    
    def _check_processes(self):
        """检查VPN进程"""
        try:
            result = subprocess.run(
                ["powershell", "-Command",
                 "Get-Process | Select-Object Name, Id, Path, Company | ConvertTo-Json -Compress"],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0:
                processes = json.loads(result.stdout)
                if isinstance(processes, dict):
                    processes = [processes]
                for proc in processes:
                    name = proc.get("Name", "").lower()
                    path = proc.get("Path") or ""
                    for vpn in self.vpn_processes:
                        if vpn.lower() in name or vpn.lower() in path.lower():
                            self.findings.append({
                                "type": "翻墙软件",
                                "severity": "中危",
                                "name": proc.get("Name"),
                                "pid": proc.get("Id"),
                                "path": path,
                                "company": proc.get("Company", "未知"),
                                "description": f"发现翻墙/VPN软件: {proc.get('Name')}，公司: {proc.get('Company', '未知')}，路径: {path}"
                            })
        except Exception as e:
            self.findings.append({"type": "错误", "severity": "信息", "description": f"VPN进程检查出错: {str(e)}"})
    
    def _check_network(self):
        """检查VPN网络连接"""
        try:
            result = subprocess.run(
                ["powershell", "-Command",
                 "Get-NetTCPConnection -State Established | "
                 "Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess | "
                 "ConvertTo-Json -Compress"],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0:
                connections = json.loads(result.stdout)
                if isinstance(connections, dict):
                    connections = [connections]
                for conn in connections:
                    port = conn.get("RemotePort", 0)
                    if port in self.vpn_ports:
                        self.findings.append({
                            "type": "翻墙端口",
                            "severity": "中危",
                            "remote": f"{conn.get('RemoteAddress')}:{port}",
                            "local_port": conn.get("LocalPort"),
                            "pid": conn.get("OwningProcess"),
                            "description": f"发现翻墙/代理端口连接: {conn.get('RemoteAddress')}:{port}，PID: {conn.get('OwningProcess')}"
                        })
        except Exception as e:
            self.findings.append({"type": "错误", "severity": "信息", "description": f"VPN网络检查出错: {str(e)}"})
    
    def _check_vpn_adapters(self):
        """检查VPN适配器"""
        try:
            result = subprocess.run(
                ["powershell", "-Command",
                 "Get-NetAdapter | Where-Object {$_.InterfaceDescription -like '*VPN*' -or "
                 "$_.InterfaceDescription -like '*TAP*' -or "
                 "$_.InterfaceDescription -like '*TUN*' -or "
                 "$_.InterfaceDescription -like '*WireGuard*' -or "
                 "$_.InterfaceDescription -like '*Virtual*' -or "
                 "$_.Name -like '*VPN*' -or "
                 "$_.Name -like '*TAP*' -or "
                 "$_.Name -like '*TUN*'} | "
                 "Select-Object Name, InterfaceDescription, Status, MacAddress | ConvertTo-Json -Compress"],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0 and result.stdout.strip():
                adapters = json.loads(result.stdout)
                if isinstance(adapters, dict):
                    adapters = [adapters]
                for adapter in adapters:
                    if adapter.get("Status") == "Up":
                        self.findings.append({
                            "type": "VPN适配器",
                            "severity": "中危",
                            "name": adapter.get("Name"),
                            "description": f"发现活跃VPN适配器: {adapter.get('Name')}，描述: {adapter.get('InterfaceDescription')}"
                        })
        except Exception as e:
            pass
    
    def _check_proxy_settings(self):
        """检查代理设置"""
        try:
            result = subprocess.run(
                ["powershell", "-Command",
                 "Get-ItemProperty 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' | "
                 "Select-Object AutoConfigURL, ProxyEnable, ProxyServer, ProxyOverride | ConvertTo-Json"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                settings = json.loads(result.stdout)
                if settings.get("ProxyEnable") == 1:
                    proxy = settings.get("ProxyServer", "")
                    self.findings.append({
                        "type": "代理设置",
                        "severity": "中危",
                        "proxy": proxy,
                        "description": f"系统启用代理: {proxy}"
                    })
                auto_url = settings.get("AutoConfigURL", "")
                if auto_url:
                    self.findings.append({
                        "type": "自动代理",
                        "severity": "低危",
                        "auto_url": auto_url,
                        "description": f"发现自动代理配置: {auto_url}"
                    })
        except Exception as e:
            pass
    
    def _check_suspicious_traffic(self):
        """检查翻墙流量特征"""
        try:
            # 检查是否有连接到境外IP的异常流量
            result = subprocess.run(
                ["powershell", "-Command",
                 "Get-NetTCPConnection -State Established | "
                 "Where-Object {$_.RemoteAddress -notlike '192.168.*' -and "
                 "$_.RemoteAddress -notlike '10.*' -and "
                 "$_.RemoteAddress -notlike '172.*' -and "
                 "$_.RemoteAddress -notlike '127.*' -and "
                 "$_.RemoteAddress -notlike '169.254.*'} | "
                 "Select-Object RemoteAddress, RemotePort, OwningProcess | ConvertTo-Json -Compress"],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0 and result.stdout.strip():
                connections = json.loads(result.stdout)
                if isinstance(connections, dict):
                    connections = [connections]
                count = len(connections)
                if count > 10:
                    self.findings.append({
                        "type": "异常外连",
                        "severity": "中危",
                        "count": count,
                        "description": f"发现{count}个境外网络连接，可能存在翻墙行为"
                    })
        except Exception as e:
            pass


# ====== 远控检测模块 ======
class RemoteControlDetector(DetectionModule):
    """远控木马检测"""
    name = "远控检测"
    description = "检测远控木马、后门程序"
    threat_type = "远控木马"
    
    def __init__(self):
        super().__init__()
        self.remote_access_processes = [
            "teamviewer", "anydesk", "ammyy", "litecam", "logmein", "gotoassist",
            "bomgar", "webex", "zoom", "vnc", "vncserver", "vncviewer",
            "radmin", "lmremote", "pcanywhere", "remoteutil", "mremote", "xming",
            "putty", "kitty", "xshell", "moba", "termius", "windterm",
            "remotedesktop", "mstsc", "chrome", "msedge", "firefox",
            "rdesktop", "freerdp", "xfreerdp", "nc", "netcat", "socat",
            "psexec", "wmiexec", "dcomexec", "smbexec",
            "metasploit", "meterpreter", "cobaltstrike", "cs", "beacon",
            "koadic", "pupy", "silk", "covenant", "empire", "posh", "powersploit"
        ]
        self.suspicious_ports = [22, 23, 3389, 5900, 5901, 5938, 8080, 8443, 4444, 5555, 5556, 6666, 6667, 31337]
        
    def check(self, progress_callback=None):
        self.findings = []
        
        if progress_callback:
            progress_callback(15, "检查远程访问进程...")        
        self._check_processes()
        
        if progress_callback:
            progress_callback(35, "检查异常端口...")        
        self._check_ports()
        
        if progress_callback:
            progress_callback(50, "检查可疑服务...")        
        self._check_services()
        
        if progress_callback:
            progress_callback(70, "检查注册表...")        
        self._check_registry()
        
        if progress_callback:
            progress_callback(85, "检查后门程序...")        
        self._check_backdoors()
        
        if progress_callback:
            progress_callback(100, "检查完成")
            
        return self.findings
    
    def _check_processes(self):
        """检查远控进程"""
        try:
            result = subprocess.run(
                ["powershell", "-Command",
                 "Get-Process | Select-Object Name, Id, Path, Company | ConvertTo-Json -Compress"],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0:
                processes = json.loads(result.stdout)
                if isinstance(processes, dict):
                    processes = [processes]
                for proc in processes:
                    name = proc.get("Name", "").lower()
                    path = proc.get("Path") or ""
                    for remote in self.remote_access_processes:
                        if remote.lower() in name or remote.lower() in path.lower():
                            company = proc.get("Company", "")
                            severity = "中危"
                            if any(x in name for x in ["meterpreter", "cobaltstrike", "beacon", "koadic", "pupy", "powersploit"]):
                                severity = "严重"
                            self.findings.append({
                                "type": "远控程序",
                                "severity": severity,
                                "name": proc.get("Name"),
                                "pid": proc.get("Id"),
                                "path": path,
                                "description": f"发现远控/渗透工具: {proc.get('Name')}，公司: {company or '未知'}，路径: {path}"
                            })
        except Exception as e:
            self.findings.append({"type": "错误", "severity": "信息", "description": f"远控进程检查出错: {str(e)}"})
    
    def _check_ports(self):
        """检查可疑端口"""
        try:
            result = subprocess.run(
                ["powershell", "-Command",
                 "Get-NetTCPConnection -Listen | "
                 "Select-Object LocalAddress, LocalPort, OwningProcess | "
                 "ConvertTo-Json -Compress"],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0:
                listeners = json.loads(result.stdout)
                if isinstance(listeners, dict):
                    listeners = [listeners]
                for listener in listeners:
                    port = listener.get("LocalPort", 0)
                    if port in self.suspicious_ports:
                        self.findings.append({
                            "type": "可疑监听",
                            "severity": "高危",
                            "port": port,
                            "address": listener.get("LocalAddress"),
                            "pid": listener.get("OwningProcess"),
                            "description": f"发现可疑监听端口: {port}，地址: {listener.get('LocalAddress')}，PID: {listener.get('OwningProcess')}"
                        })
        except Exception as e:
            self.findings.append({"type": "错误", "severity": "信息", "description": f"端口检查出错: {str(e)}"})
    
    def _check_services(self):
        """检查可疑服务"""
        try:
            result = subprocess.run(
                ["powershell", "-Command",
                 "Get-Service | Where-Object {$_.Status -eq 'Running'} | "
                 "Select-Object Name, DisplayName, ServiceType | ConvertTo-Json -Compress"],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0:
                services = json.loads(result.stdout)
                if isinstance(services, dict):
                    services = [services]
                suspicious_keywords = ["remote", "vnc", "teamviewer", "anydesk", 
                                       "backdoor", "后门", "remote access"]
                for svc in services:
                    name = str(svc.get("Name", "")).lower()
                    display = str(svc.get("DisplayName", "")).lower()
                    for kw in suspicious_keywords:
                        if kw in name or kw in display:
                            self.findings.append({
                                "type": "可疑服务",
                                "severity": "中危",
                                "name": svc.get("Name"),
                                "display": svc.get("DisplayName"),
                                "description": f"发现可疑服务: {svc.get('DisplayName')}"
                            })
        except Exception as e:
            self.findings.append({"type": "错误", "severity": "信息", "description": f"服务检查出错: {str(e)}"})
    
    def _check_registry(self):
        """检查注册表启动项"""
        try:
            result = subprocess.run(
                ["powershell", "-Command",
                 "Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run' | "
                 "ConvertTo-Json -Compress"],
                capture_output=True, text=True, timeout=15
            )
            if result.returncode == 0 and result.stdout.strip():
                try:
                    items = json.loads(result.stdout)
                    for key, value in items.items():
                        if key.startswith("PS"):
                            continue
                        value_str = str(value).lower()
                        for remote in self.remote_access_processes:
                            if remote.lower() in value_str:
                                self.findings.append({
                                    "type": "注册表启动",
                                    "severity": "高危",
                                    "key": key,
                                    "value": value,
                                    "description": f"发现可疑启动项: {key} -> {value}"
                                })
                except:
                    pass
        except:
            pass
    
    def _check_backdoors(self):
        """检查常见后门特征"""
        try:
            # 检查HTTP后门特征
            result = subprocess.run(
                ["powershell", "-Command",
                 "Get-Process | Where-Object {$_.MainWindowTitle -ne ''} | "
                 "Select-Object Name, Id, MainWindowTitle | ConvertTo-Json -Compress"],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0:
                try:
                    procs = json.loads(result.stdout)
                    if isinstance(procs, dict):
                        procs = [procs]
                    for proc in procs:
                        title = str(proc.get("MainWindowTitle", "")).lower()
                        if any(x in title for x in ["backdoor", "remote", "shell", "cmd"]):
                            self.findings.append({
                                "type": "可疑窗口",
                                "severity": "中危",
                                "name": proc.get("Name"),
                                "title": proc.get("MainWindowTitle"),
                                "description": f"发现可疑窗口标题: {proc.get('Name')} - {proc.get('MainWindowTitle')}"
                            })
                except:
                    pass
        except:
            pass


# ====== WebShell检测模块 ======
class WebShellDetector(DetectionModule):
    """WebShell检测"""
    name = "WebShell检测"
    description = "检测WebShell后门文件"
    threat_type = "WebShell"
    
    def __init__(self):
        super().__init__()
        self.webshell_signatures = [
            "eval(", "base64_decode", "system(", "exec(", "shell_exec", "passthru",
            "popen(", "proc_open", "assert(", "preg_replace", "create_function",
            "call_user_func", "call_user_func_array", "file_get_contents",
            "file_put_contents", "fopen", "fwrite", "unserialize",
            "eval(base64", "eval(gzinflate", "eval(gzuncompress", "@eval",
            "Runtime.getRuntime", "ProcessBuilder", "ProcessImpl",
            "Class.forName", "Method.invoke", "InvocationTargetException",
            "cmd.exe", "powershell", "wscript.shell", "shell.application"
        ]
        self.suspicious_extensions = [".php", ".jsp", ".asp", ".aspx", ".jspx", ".php3", ".php4", ".php5", ".phtml", ".php7"]
        self.common_paths = [
            "C:\\inetpub\\wwwroot",
            "C:\\xampp\\htdocs",
            "C:\\wamp\\www",
            "C:\\phpstudy\\www",
            "C:\\phpstudy_pro\\www",
            "D:\\phpstudy\\www",
            "D:\\phpstudy_pro\\www",
            "C:\\phpnow\\htdocs",
            "C:\\wampserver\\www",
            "C:\\AppServ\\www",
            "C:\\xampp\\apache\\htdocs",
        ]
        
    def check(self, progress_callback=None):
        self.findings = []
        
        if progress_callback:
            progress_callback(15, "扫描网站目录...")        
        self._scan_webshell()
        
        if progress_callback:
            progress_callback(85, "检查日志...")        
        self._check_access_log()
        
        if progress_callback:
            progress_callback(100, "检查完成")
            
        return self.findings
    
    def _scan_webshell(self):
        """扫描WebShell文件"""
        found_any = False
        for base_path in self.common_paths:
            if os.path.exists(base_path):
                found_any = True
                self._scan_directory(base_path)
        
        if not found_any:
            self.findings.append({
                "type": "信息",
                "severity": "信息",
                "description": f"未检测到常见Web目录（phpstudy/xampp/wamp等），如需扫描请手动指定目录"
            })
    
    def _scan_directory(self, directory):
        """扫描目录"""
        try:
            file_count = 0
            for root, dirs, files in os.walk(directory):
                # 跳过node_modules, .git等目录
                dirs[:] = [d for d in dirs if d not in ["node_modules", ".git", ".svn", "vendor", "assets", "static", "uploads"]]
                
                for file in files:
                    ext = os.path.splitext(file)[1].lower()
                    if ext not in self.suspicious_extensions:
                        continue
                    
                    filepath = os.path.join(root, file)
                    file_count += 1
                    
                    if file_count > 5000:
                        break
                    
                    try:
                        size = os.path.getsize(filepath)
                        if size > 500 * 1024:  # 跳过大于500KB的文件
                            continue
                        
                        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                            content = f.read(100 * 1024)  # 只读前100KB
                        
                        matches = []
                        for sig in self.webshell_signatures:
                            if sig in content.lower():
                                matches.append(sig)
                        
                        if len(matches) >= 2:
                            self.findings.append({
                                "type": "WebShell",
                                "severity": "严重",
                                "file": filepath,
                                "name": file,
                                "matches": matches,
                                "size": size,
                                "description": f"发现疑似WebShell: {file}，路径: {filepath}，特征: {', '.join(matches[:3])}"
                            })
                    except:
                        pass
                
                if file_count > 5000:
                    break
        except Exception as e:
            self.findings.append({"type": "错误", "severity": "信息", "description": f"扫描 {directory} 出错: {str(e)}"})
    
    def _check_access_log(self):
        """检查Web访问日志中的可疑请求"""
        log_paths = [
            "C:\\inetpub\\logs\\LogFiles",
            "C:\\xampp\\apache\\logs",
            "C:\\Apache\\logs",
            "C:\\nginx\\logs",
            "C:\\phpstudy\\Apache\\logs",
            "C:\\phpstudy_pro\\Apache\\logs",
        ]
        
        for log_path in log_paths:
            if not os.path.exists(log_path):
                continue
            try:
                suspicious_count = 0
                for root, dirs, files in os.walk(log_path):
                    for file in files:
                        if not file.endswith(".log"):
                            continue
                        filepath = os.path.join(root, file)
                        try:
                            size = os.path.getsize(filepath)
                            if size > 10 * 1024 * 1024:
                                continue
                            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                                lines = f.readlines()
                            
                            suspicious_patterns = [
                                r"eval\(", r"base64\(", r"cmd=", r"shell=", 
                                r"\.\./", r"wget", r"curl ", r"powershell", r"system\("
                            ]
                            
                            suspicious_lines = []
                            for line in lines[-500:]:
                                for pattern in suspicious_patterns:
                                    if re.search(pattern, line, re.IGNORECASE):
                                        suspicious_count += 1
                                        if len(suspicious_lines) < 3:
                                            suspicious_lines.append(line.strip()[:100])
                                        break
                            
                            if len(suspicious_lines) > 0:
                                self.findings.append({
                                    "type": "可疑日志",
                                    "severity": "高危",
                                    "file": filepath,
                                    "lines": suspicious_lines,
                                    "description": f"日志中发现可疑请求: {file}，{len(suspicious_lines)}条记录"
                                })
                                break
                        except:
                            pass
            except:
                pass


# ====== 常规黑客攻击检测模块 ======
class HackerAttackDetector(DetectionModule):
    """常规黑客攻击检测 - 全面检测"""
    name = "黑客攻击检测"
    description = "全面检测日志、账号、弱口令、注册表、远控、病毒等"
    threat_type = "黑客攻击"
    
    def __init__(self):
        super().__init__()
        self.suspicious_accounts = ["admin", "administrator", "root", "guest", "default", "test", "backup"]
        
    def check(self, progress_callback=None):
        self.findings = []
        
        if progress_callback:
            progress_callback(10, "检查登录失败日志...")        
        self._check_logon_failures()
        
        if progress_callback:
            progress_callback(25, "检查账户锁定...")        
        self._check_account_lockouts()
        
        if progress_callback:
            progress_callback(35, "检查可疑账号...")        
        self._check_suspicious_accounts()
        
        if progress_callback:
            progress_callback(45, "检查防火墙日志...")        
        self._check_firewall_logs()
        
        if progress_callback:
            progress_callback(55, "检查异常连接...")        
        self._check_abnormal_connections()
        
        if progress_callback:
            progress_callback(65, "检查注册表...")        
        self._check_registry()
        
        if progress_callback:
            progress_callback(75, "检查远控特征...")        
        self._check_remote_access()
        
        if progress_callback:
            progress_callback(85, "检查病毒特征...")        
        self._check_virus_signatures()
        
        if progress_callback:
            progress_callback(100, "检查完成")
            
        return self.findings
    
    def _check_logon_failures(self):
        """检查登录失败事件"""
        try:
            result = subprocess.run(
                ["powershell", "-Command",
                 "Get-WinEvent -FilterHashtable @{LogName='Security';ID=4625} -MaxEvents 100 | "
                 "Select-Object TimeCreated, Message | ConvertTo-Json -Compress"],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0 and result.stdout.strip():
                try:
                    events = json.loads(result.stdout)
                    if isinstance(events, dict):
                        events = [events]
                    
                    failure_count = len(events)
                    # 检查是否有同一IP的多次失败
                    ip_counts = {}
                    for event in events:
                        msg = event.get("Message", "")
                        # 尝试提取IP地址
                        import re
                        ips = re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', msg)
                        for ip in ips:
                            if not ip.startswith(("192.168", "10.", "172.", "127.")):
                                ip_counts[ip] = ip_counts.get(ip, 0) + 1
                    
                    if failure_count > 10:
                        self.findings.append({
                            "type": "暴力破解",
                            "severity": "高危",
                            "count": failure_count,
                            "description": f"检测到{failure_count}次登录失败，可能存在暴力破解攻击"
                        })
                    elif failure_count > 0:
                        self.findings.append({
                            "type": "登录失败",
                            "severity": "中危",
                            "count": failure_count,
                            "description": f"检测到{failure_count}次登录失败"
                        })
                    
                    # 报告可疑IP
                    for ip, count in ip_counts.items():
                        if count >= 5:
                            self.findings.append({
                                "type": "可疑IP攻击",
                                "severity": "高危",
                                "ip": ip,
                                "count": count,
                                "description": f"发现可疑IP {ip} 有{count}次登录失败记录"
                            })
                except:
                    pass
        except:
            pass
    
    def _check_account_lockouts(self):
        """检查账户锁定"""
        try:
            result = subprocess.run(
                ["powershell", "-Command",
                 "Search-ADAccount -LockedOut 2>$null | Select-Object Name, LastLogonDate | "
                 "ConvertTo-Json -Compress"],
                capture_output=True, text=True, timeout=30
            )
            # 如果AD命令不可用，尝试其他方式
            if result.returncode != 0 or not result.stdout.strip():
                result = subprocess.run(
                    ["powershell", "-Command",
                     "Get-WinEvent -FilterHashtable @{LogName='Security';ID=4740} -MaxEvents 20 | "
                     "Select-Object TimeCreated, Message | ConvertTo-Json -Compress"],
                    capture_output=True, text=True, timeout=30
                )
            
            if result.returncode == 0 and result.stdout.strip():
                try:
                    locked = json.loads(result.stdout)
                    if isinstance(locked, dict):
                        locked = [locked]
                    for account in locked:
                        name = account.get("Name") or ""
                        if not name:
                            msg = account.get("Message", "")
                            import re
                            names = re.findall(r'Account Name:\s*(\S+)', msg)
                            if names:
                                name = names[0]
                        if name:
                            self.findings.append({
                                "type": "账户锁定",
                                "severity": "高危",
                                "account": name,
                                "description": f"账户已被锁定: {name}"
                            })
                except:
                    pass
        except:
            pass
    
    def _check_suspicious_accounts(self):
        """检查可疑账户"""
        try:
            result = subprocess.run(
                ["powershell", "-Command",
                 "Get-LocalUser | Select-Object Name, Enabled, LastLogonDate, Description | "
                 "ConvertTo-Json -Compress"],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0:
                try:
                    users = json.loads(result.stdout)
                    if isinstance(users, dict):
                        users = [users]
                    for user in users:
                        name = user.get("Name", "").lower()
                        if name in self.suspicious_accounts:
                            enabled = user.get("Enabled", True)
                            self.findings.append({
                                "type": "可疑账户",
                                "severity": "中危",
                                "name": user.get("Name"),
                                "enabled": enabled,
                                "description": f"发现系统账户: {user.get('Name')}，状态: {'启用' if enabled else '禁用'}"
                            })
                except:
                    pass
        except:
            pass
    
    def _check_firewall_logs(self):
        """检查防火墙日志"""
        try:
            result = subprocess.run(
                ["powershell", "-Command",
                 "Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Firewall With Advanced Security/Firewall';"
                 "Level=2} -MaxEvents 50 | "
                 "Select-Object TimeCreated, Message | ConvertTo-Json -Compress"],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0 and result.stdout.strip():
                try:
                    events = json.loads(result.stdout)
                    if isinstance(events, dict):
                        events = [events]
                    blocked_count = len(events)
                    if blocked_count > 20:
                        self.findings.append({
                            "type": "防火墙拦截",
                            "severity": "低危",
                            "count": blocked_count,
                            "description": f"防火墙已拦截{blocked_count}次连接"
                        })
                except:
                    pass
        except:
            pass
    
    def _check_abnormal_connections(self):
        """检查异常连接"""
        try:
            result = subprocess.run(
                ["powershell", "-Command",
                 "Get-NetTCPConnection -State Established | "
                 "Where-Object {$_.RemoteAddress -notlike '192.168.*' -and "
                 "$_.RemoteAddress -notlike '10.*' -and "
                 "$_.RemoteAddress -notlike '172.*' -and "
                 "$_.RemoteAddress -notlike '127.*'} | "
                 "Select-Object RemoteAddress, RemotePort, OwningProcess | "
                 "ConvertTo-Json -Compress"],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0 and result.stdout.strip():
                try:
                    connections = json.loads(result.stdout)
                    if isinstance(connections, dict):
                        connections = [connections]
                    
                    unique_ips = {}
                    for conn in connections:
                        ip = conn.get("RemoteAddress")
                        if ip and not ip.startswith(("192.168", "10.", "172.", "127.")):
                            if ip not in unique_ips:
                                unique_ips[ip] = 1
                            else:
                                unique_ips[ip] += 1
                    
                    if len(unique_ips) > 15:
                        self.findings.append({
                            "type": "异常外连",
                            "severity": "中危",
                            "count": len(unique_ips),
                            "description": f"发现{len(unique_ips)}个境外IP连接，可能存在数据外泄风险"
                        })
                except:
                    pass
        except:
            pass
    
    def _check_registry(self):
        """检查注册表安全项"""
        try:
            # 检查远程桌面相关注册表
            result = subprocess.run(
                ["powershell", "-Command",
                 "Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server' | "
                 "Select-Object fDenyTSConnections, fAllowToGetHelp | ConvertTo-Json"],
                capture_output=True, text=True, timeout=15
            )
            if result.returncode == 0:
                try:
                    props = json.loads(result.stdout)
                    if props.get("fDenyTSConnections") == 0:
                        self.findings.append({
                            "type": "远程桌面",
                            "severity": "中危",
                            "description": "远程桌面(RDP)已开启，建议确认是否为业务需要"
                        })
                except:
                    pass
        except:
            pass
        
        # 检查是否允许匿名访问
        try:
            result = subprocess.run(
                ["powershell", "-Command",
                 "Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' | "
                 "Select-Object NullSessionPipes, RestrictAnonymousSAM | ConvertTo-Json"],
                capture_output=True, text=True, timeout=15
            )
            if result.returncode == 0:
                try:
                    props = json.loads(result.stdout)
                    if props.get("RestrictAnonymousSAM") == 0:
                        self.findings.append({
                            "type": "匿名访问",
                            "severity": "中危",
                            "description": "系统允许匿名SAM访问，可能存在安全风险"
                        })
                except:
                    pass
        except:
            pass
    
    def _check_remote_access(self):
        """检查远程访问工具痕迹"""
        try:
            # 检查最近打开的远程连接
            result = subprocess.run(
                ["powershell", "-Command",
                 "Get-ItemProperty 'HKCU:\\Software\\Microsoft\\Terminal Server Client\\Recent' 2>$null | "
                 "Get-Member -MemberType NoteProperty | Select-Object Name | ConvertTo-Json -Compress"],
                capture_output=True, text=True, timeout=15
            )
            if result.returncode == 0 and result.stdout.strip():
                try:
                    entries = json.loads(result.stdout)
                    if isinstance(entries, dict):
                        entries = [entries]
                    if len(entries) > 0:
                        self.findings.append({
                            "type": "RDP历史",
                            "severity": "低危",
                            "count": len(entries),
                            "description": f"检测到{len(entries)}条远程桌面连接历史"
                        })
                except:
                    pass
        except:
            pass
        
        # 检查Putty连接历史
        try:
            putty_path = os.path.join(os.path.expanduser("~"), "Documents", "PuTTY", "puttycnt.ini")
            if os.path.exists(putty_path):
                self.findings.append({
                    "type": "SSH工具",
                    "severity": "低危",
                    "file": putty_path,
                    "description": f"检测到Putty SSH工具使用痕迹: {putty_path}"
                })
        except:
            pass
    
    def _check_virus_signatures(self):
        """检查病毒/恶意软件特征"""
        try:
            # 检查系统文件是否被修改
            result = subprocess.run(
                ["powershell", "-Command",
                 "Get-FileHash 'C:\\Windows\\System32\\cmd.exe' -Algorithm MD5 2>$null | "
                 "Select-Object Hash | ConvertTo-Json"],
                capture_output=True, text=True, timeout=15
            )
            if result.returncode == 0:
                # 这里只是示例，实际需要比对已知正常hash
                pass
        except:
            pass
        
        # 检查可疑的系统进程
        try:
            result = subprocess.run(
                ["powershell", "-Command",
                 "Get-Process | Where-Object {$_.Path -like '*temp*' -or "
                 "$_.Path -like '*appdata*\\local\\temp*'} | "
                 "Select-Object Name, Id, Path | ConvertTo-Json -Compress"],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0 and result.stdout.strip():
                try:
                    procs = json.loads(result.stdout)
                    if isinstance(procs, dict):
                        procs = [procs]
                    for proc in procs[:5]:
                        self.findings.append({
                            "type": "可疑进程",
                            "severity": "中危",
                            "name": proc.get("Name"),
                            "pid": proc.get("Id"),
                            "path": proc.get("Path", ""),
                            "description": f"发现临时目录下的进程: {proc.get('Name')}，路径: {proc.get('Path', '')}"
                        })
                except:
                    pass
        except:
            pass


# ====== 完整系统检测模块 ======
class FullSystemScanner(DetectionModule):
    """完整系统扫描"""
    name = "全盘扫描"
    description = "全面检测系统安全问题"
    threat_type = "综合威胁"
    
    def __init__(self):
        super().__init__()
        self.modules = [
            MiningDetector(),
            RansomwareDetector(),
            VPNDetector(),
            RemoteControlDetector(),
            WebShellDetector(),
            HackerAttackDetector()
        ]
        
    def check(self, progress_callback=None):
        self.findings = []
        total = len(self.modules)
        
        for i, module in enumerate(self.modules):
            if progress_callback:
                progress = int((i / total) * 100)
                progress_callback(progress, f"正在执行{module.name}...")
            
            try:
                results = module.check(progress_callback)
                self.findings.extend(results)
            except Exception as e:
                self.findings.append({
                    "type": "错误",
                    "severity": "信息",
                    "module": module.name,
                    "description": f"模块执行出错: {str(e)}"
                })
        
        if progress_callback:
            progress_callback(100, "全盘扫描完成")
            
        return self.findings
