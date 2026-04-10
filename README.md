# Windows应急排查工具 v2.0

**Copyright (C) 蚂蚁安全 | www.mayisafe.cn**

## 工具简介

专业的Windows系统安全应急排查工具，支持检测多种威胁场景，集成AI智能分析。

## 支持的检测场景

| 场景 | 说明 |
|------|------|
| 🪙 挖矿检测 | 检测挖矿木马、矿池连接、异常CPU占用、启动项、计划任务 |
| 🔒 勒索检测 | 检测勒索病毒、加密文件、勒索信、卷影删除、可疑进程 |
| 🌐 翻墙检测 | 检测VPN/代理软件、翻墙流量、异常外连、VPN适配器 |
| 💻 远控检测 | 检测远控木马、后门程序、可疑监听端口、可疑服务、注册表启动项 |
| 🕷️ WebShell检测 | 扫描常见Web目录（phpstudy/xampp/wamp等）、日志分析 |
| ⚔️ 黑客攻击检测 | 登录失败、账户锁定、可疑账号、防火墙日志、异常连接、注册表安全、远控痕迹、病毒特征 |

## AI功能

支持多种AI服务进行智能分析：
- **MiniMax** (默认)
- **Kimi** (Moonshot)
- **DeepSeek** ⭐ 新增
- **阿里千问** (通义千问) ⭐ 新增
- **OpenAI兼容**

## 报告导出

支持多种格式报告导出：
- **HTML** - 精美网页报告
- **PDF** - 便携式文档（需安装: pip install reportlab）
- **Word** - 可编辑文档（需安装: pip install python-docx）
- **TXT** - 纯文本格式

所有报告均包含完整版权信息。

## 运行要求

- Windows 7/8/10/11 或 Windows Server
- Python 3.8+

### 依赖库

```bash
pip install requests Pillow
```

可选（PDF/Word导出）：
```bash
pip install reportlab python-docx
```

## 使用方法

### 图形界面

```bash
python gui_app.py
```

或双击 `启动工具.bat`

### 命令行模式

```bash
python emergency_tool.py
```

## 界面预览

工具界面包含：
- 主机信息展示
- 多种扫描选项
- 实时扫描进度
- 检测结果详情（含完整路径）
- AI智能分析结果
- 多格式报告导出

## 功能特性

- ✅ 7大检测场景覆盖
- ✅ 4大AI服务支持
- ✅ 4种报告格式导出
- ✅ 完整文件路径显示
- ✅ 扫描进度实时显示
- ✅ 结果双击查看详情
- ✅ 中文界面

## 版权声明

本工具及报告版权为 **蚂蚁安全 (www.mayisafe.cn)** 所有。

---

*安全第一，预防为主*
