# Codex_CLI_Security
Codex_CLI_Security Detection in Sec msft 


markdown_content = """# 🛡️ Codex CLI Security Overview & Briefing

**Developed by:** [https://curtis9662.github.io/](https://curtis9662.github.io/)

---

## 📋 Executive Briefing

Recent security research has identified a supply chain attack vector within the **Codex CLI** ecosystem (e.g., CVE-2025-61260). The vulnerability involves malicious Model Context Protocol (MCP) configuration files that can lead to arbitrary command injection and code execution. 

This document serves as an engineering overview for detecting and mitigating these dynamic threats using Microsoft Defender XDR.

---

## 🎯 Indicators of Compromise (IoCs)

While static indicators (like specific malicious domains) are constantly evolving, the primary threat footprint involves **behavioral IoCs**:

* 📄 **Unexpected Configurations:** `.codex/config.toml` or `.env` files appearing in repository directories containing embedded shell commands.
* 🌐 **Anomalous Network Traffic:** Suspicious outbound network connections initiated immediately after executing the `codex` command.
* 🔀 **Unusual Process Spawning:** Shells (`bash`, `cmd.exe`, `powershell`) or network utilities (`curl`, `netcat`) spawning as child processes of the Codex CLI.
* 🛠️ **Environment Tampering:** Unexplained modifications to developer environment files (e.g., `.bashrc`, `.zshrc`, SSH configurations) following Codex CLI usage.

---

## ⚙️ Engineering Overview: Mitigation & Blocking

To effectively defend against these vectors in **Microsoft Defender XDR**, security engineers must deploy a hybrid defense strategy utilizing both Static Indicators and Advanced Hunting rules.

### 🛡️ Phase 1: Static Indicator Blocking (Known Threats)
For known malicious file hashes (SHA-256) or Command-and-Control (C2) IP addresses:
1. Navigate to `Security.microsoft.com` ➡️ **Settings** ➡️ **Endpoints** ➡️ **Indicators**.
2. Add the specific File Hash or IP Address.
3. Set action to **Block and remediate**.

### 🕵️‍♂️ Phase 2: Behavioral Blocking via Advanced Hunting (Dynamic Threats)
Deploy the following KQL queries as **Custom Detection Rules** to stop suspicious behaviors dynamically.

```
See Repo
