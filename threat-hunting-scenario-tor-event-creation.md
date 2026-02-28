# 🚨 Threat Event: Unauthorized Tor Browser Installation and Usage

---

## 📌 Overview

This document outlines the detection of **unauthorized Tor Browser installation and usage** within an enterprise environment.

Tor (The Onion Router) is a legitimate privacy tool designed to protect users against tracking, surveillance, and censorship. However, in corporate environments, unsanctioned use may indicate:

- Acceptable Use Policy violations  
- Attempted anonymization of activity  
- Data exfiltration  
- Insider threat behavior  
- Evasion of monitoring controls  

This guide provides:

- Simulated adversary steps  
- Indicators of Compromise (IoCs)  
- Microsoft Defender XDR hunting queries  
- Detection strategy  

---

# 🧪 Simulated Adversary Activity (Lab Scenario)

> The following steps simulate activity to generate logs for detection validation.

---

## 1️⃣ Download Tor Browser Installer

Download location:

```
https://www.torproject.org/download/
```

Example installer:

```
tor-browser-windows-x86_64-portable-14.0.1.exe
```

---

## 2️⃣ Silent Installation

Execute installer silently:

```bash
tor-browser-windows-x86_64-portable-14.0.1.exe /S
```

> ⚠️ Note: Some logs may show two spaces before `/S`.

---

## 3️⃣ Launch Tor Browser

User launches Tor Browser from Desktop folder.

Expected process artifacts:

- `tor.exe`
- Bundled `firefox.exe`
- Tor background service initialization

---

## 4️⃣ Connect to Tor Network

User connects to Tor and browses websites.

Example historical onion destinations:

- Dread Forum  
- DarkNetMarkets forum  
- Elysium Market  

> ⚠️ Onion URLs frequently change. Any browsing over Tor will generate relevant telemetry.

---

## 5️⃣ Create Suspicious File

Create a file:

```
tor-shopping-list.txt
```

Populate with fake illicit items.

---

## 6️⃣ Delete the File

Delete the file to simulate cleanup.

Generated artifacts:

- File creation event  
- File modification event (optional)  
- File deletion event  

---

# 🔎 Detection Strategy

---

## 🗂️ Table: DeviceFileEvents

| Parameter | Description |
|------------|--------------|
| **Name** | `DeviceFileEvents` |
| **Purpose** | Detect Tor installer download, Tor binaries written to disk, and suspicious file creation/deletion |
| **Use Case** | Identify filesystem artifacts |

---

## 🗂️ Table: DeviceProcessEvents

| Parameter | Description |
|------------|--------------|
| **Name** | `DeviceProcessEvents` |
| **Purpose** | Detect silent installation and Tor process execution |
| **Use Case** | Identify execution of `tor.exe` and bundled `firefox.exe` |

---

## 🗂️ Table: DeviceNetworkEvents

| Parameter | Description |
|------------|--------------|
| **Name** | `DeviceNetworkEvents` |
| **Purpose** | Detect Tor network connections |
| **Use Case** | Monitor outbound connections on Tor ports |

Common Tor Ports:

```
9001
9030
9040
9050
9051
9150
```

---

# 🧠 Hunting Queries (KQL)

---

## 🔹 Detect Tor Installer Download

```kql
DeviceFileEvents
| where FileName startswith "tor-browser"
| project Timestamp, DeviceName, FolderPath, FileName, ActionType, InitiatingProcessFileName
| order by Timestamp desc
```

---

## 🔹 Detect Silent Installation

```kql
DeviceProcessEvents
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable"
| where ProcessCommandLine contains "/S"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
| order by Timestamp desc
```

---

## 🔹 Detect Tor Binaries on Disk

```kql
DeviceFileEvents
| where FileName in~ ("tor.exe", "firefox.exe")
| project Timestamp, DeviceName, RequestAccountName, ActionType, FolderPath
| order by Timestamp desc
```

---

## 🔹 Detect Tor Execution

```kql
DeviceProcessEvents
| where FileName in~ ("tor.exe", "firefox.exe")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
| order by Timestamp desc
```

---

## 🔹 Detect Active Tor Network Connections

```kql
DeviceNetworkEvents
| where InitiatingProcessFileName in~ ("tor.exe", "firefox.exe")
| where RemotePort in (9001, 9030, 9040, 9050, 9051, 9150)
| project Timestamp,
         DeviceName,
         InitiatingProcessAccountName,
         InitiatingProcessFileName,
         RemoteIP,
         RemotePort,
         RemoteUrl
| order by Timestamp desc
```

---

## 🔹 Detect Suspicious File Creation / Deletion

```kql
DeviceFileEvents
| where FileName =~ "tor-shopping-list.txt"
| project Timestamp, DeviceName, RequestAccountName, ActionType, FolderPath
| order by Timestamp desc
```

---

# 🚩 Key Indicators of Compromise (IoCs)

- Presence of `tor-browser-*.exe`
- Silent installation using `/S`
- Execution of:
  - `tor.exe`
  - `firefox.exe` (bundled Tor instance)
- Outbound connections over known Tor ports
- Executables running from user Desktop or Downloads directories
- Creation and deletion of suspicious files

---

# 🛡️ Defensive Recommendations

- Implement application allowlisting (AppLocker / WDAC)
- Restrict execution from user writeable directories
- Monitor anonymization-related ports
- Alert on portable browser execution
- Enforce least privilege principles
- Correlate EDR + proxy + DNS telemetry

---

# 📄 Documentation

## ✅ Created By

- **Author Name:**  
- **Author Contact:**  
- **Date:** February 27, 2026  

---

## ✅ Validated By

- **Reviewer Name:**  
- **Reviewer Contact:**  
- **Validation Date:**  

---

# 📝 Revision History

| Version | Changes | Date | Modified By |
|----------|----------|------------|--------------|
| 1.0 | Initial draft | Feb. 27, 2026 | Alexander Morrison |
| 1.1 | Enhanced formatting, expanded detection logic | February 27, 2026 | — |

---

# 📎 Additional Notes

- Tor usage is not inherently malicious.
- Investigate activity in proper business and policy context.
- Combine endpoint telemetry with network-layer detection for stronger signal fidelity.

---
