# Azure SOC Lab: Brute-Force Detection with Microsoft Sentinel

## Project Documentation / Presentation
The full presentation and documentation for this lab can be accessed here:  
[Azure SOC Lab Presentation](https://1drv.ms/p/c/83a9edf43cc661da/IQTtHXgTCxeUTYdSBkRSeJPvAXO7n6Jw0h7Tux-9r5QDZYA)

---

## Overview
This project demonstrates an end-to-end **Security Operations Center (SOC) workflow** in Microsoft Azure. The lab simulates a vulnerable VM environment to detect and visualize **brute-force and credential-stuffing attacks** using Microsoft Sentinel.


---

## Objectives
- Deploy a **vulnerable VM honeypot** in Azure.
- Forward Windows Security logs to Microsoft Sentinel using **Azure Monitoring Agent (AMA)**.
- Analyze failed login attempts to detect **credential-stuffing activity**.
- Develop **KQL queries and analytics rules** to trigger automated alerts.
- Build a **Sentinel dashboard / workbook** to visualize attacks on a geolocation map.


---

## Lab Setup

1. **Azure VM**
   - Windows 10 Enterprise deployed as a vulnerable honeypot.
   - Network Security Group and Windows firewalls adjusted and disabled.

2. **Log Forwarding**
   - Installed Azure Monitoring Agent (AMA) on the VM.
   - Configured log forwarding to a **Log Analytics Workspace** connected to Microsoft Sentinel.

3. **Attack Simulation**
   - Simulated brute-force attacks against exposed accounts.
   - Captured over **75,000 failed login attempts** from multiple IPs.

---

## KQL Queries

### Failed Login Detection
```kql
SecurityEvent
| where EventID == 4625
| where LogonType == 3
| summarize FailedAttempts = count() by IpAddress, bin(TimeGenerated, 5m)
| where FailedAttempts >= 30

