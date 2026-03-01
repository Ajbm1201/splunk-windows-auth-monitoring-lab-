# Splunk Windows Authentication Monitoring & Detection Lab

## Overview
Deployed a single-node Splunk Enterprise SIEM on Windows 11 to monitor Windows authentication activity, engineer detection logic, and simulate brute-force authentication attacks.

This project demonstrates hands-on SIEM deployment, SPL query development, detection engineering, and structured incident investigation.

---

## Environment
- Host: Windows 11 (single-node)
- SIEM Platform: Splunk Enterprise
- Log Forwarder: Splunk Universal Forwarder
- Forwarding Method: TCP (Port 9997)
- Data Source: Windows Security Event Logs (XML rendering enabled)

---

# Phase 1 – SIEM Deployment & Log Ingestion

## Architecture
- Splunk Enterprise configured as Indexer + Receiver
- Universal Forwarder configured to send logs to 127.0.0.1:9997
- Windows Security, System, and Application logs ingested
- XML rendering enabled for structured field extraction

## Validation
- Verified receiving port 9997 active via netstat
- Confirmed forward-server connection status: Active
- Confirmed Security Event logs indexed in Splunk

Outcome: Functional SIEM ingestion pipeline capable of monitoring authentication telemetry.

---

# Phase 2 – Failed Authentication Detection Engineering

## Detection Objective
Identify excessive failed logon attempts (Event ID 4625) within a 15-minute window.

## Threshold Detection Rule
```spl
index=main sourcetype=XmlWinEventLog:Security
| rex "<EventID>(?<EventID>\d+)</EventID>"
| search EventID=4625
| stats count by host
| where count > 5
```

### Alert Configuration:
Schedule: Every 5 minutes
Time Range: Last 15 minutes
Trigger: Results > 0
Severity: Medium

---

## Investigation Workflow

## Target Account Identification
```spl
index=main sourcetype=XmlWinEventLog:Security
| rex "<EventID>(?<EventID>\d+)</EventID>"
| search EventID=4625
| rex "TargetUserName'>(?<TargetUserName>[^<]+)<"
| stats count by TargetUserName
```

## Logon Type Analysis
```spl
index=main sourcetype=XmlWinEventLog:Security
| rex "<EventID>(?<EventID>\d+)</EventID>"
| search EventID=4625
| rex "LogonType'>(?<LogonType>\d+)<"
| stats count by LogonType
```

### Logon Type Reference:
2 = Interactive (Local login)
3 = Network
5 = Service
7 = Unlock
10 = Remote Desktop

## Correlation With Successful Logons
```spl
index=main sourcetype=XmlWinEventLog:Security
| rex "<EventID>(?<EventID>\d+)</EventID>"
| search EventID=4625 OR EventID=4624
| stats count by EventID
```

### Findings:
- Successful logons observed were LogonType 5 (SYSTEM service activity)
- No interactive compromise identified
- Incident assessed as unsuccessful authentication attempts
- Severity maintained: Medium

---

# Phase 3 – Brute Force Simulation & Correlated Detection

## Attack Simulation
- 20 failed authentication attempts against local user antho
- Generated using Windows runas with incorrect credentials
- Workstation unlock generated successful Event ID 4624 (LogonType 7)
- Post-login commands executed to simulate legitimate activity

---

## Correlated Brute Force Detection (High Severity)
Objective: Detect repeated failed authentication followed by successful login within 15 minutes.
```spl
index=main sourcetype=XmlWinEventLog:Security earliest=-15m
| rex "<EventID>(?<EventID>\d+)</EventID>"
| search EventID=4625 OR EventID=4624
| stats count(eval(EventID=4625)) as Failures
        count(eval(EventID=4624)) as Successes
        by host
| where Failures >= 5 AND Successes >= 1
```

### Alert Configuration:
- Schedule: */5 * * * *
- Time Range: Last 15 minutes
- Trigger: Results > 0
- Severity: High

---

## Skills Demonstrated
- SIEM deployment and log ingestion architecture
- Windows Security Event analysis
- SPL query development
- Regex field extraction (rex)
- Threshold-based detection engineering
- Correlation rule design
- Incident investigation workflow
- Authentication attack simulation

---

## Lab Execution Evidence

### 1️⃣ Universal Forwarder Connectivity
![Forwarder Connection](Screenshot%202026-02-23%20221113.png)

### 2️⃣ Windows Security Events Ingested
![Security Events](Screenshot%202026-02-23%20224026.png)

### 3️⃣ Failed Logon Detection Query (Event ID 4625)
![4625 Query](Screenshot%202026-02-24%20224324.png)

### 4️⃣ Threshold Rule Statistics View
![Statistics View](Screenshot%202026-02-24%20224921.png)

### 5️⃣ Triggered Alert (Medium Severity)
![Triggered Alert](Screenshot%202026-02-25%20204627.png)

### 6️⃣ Target User Investigation
![User Investigation](Screenshot%202026-02-26%20211141.png)

### 7️⃣ Logon Type Analysis
![Logon Type](Screenshot%202026-02-26%20211718.png)

### 8️⃣ Correlated Brute Force Detection
![Correlation Detection](Screenshot%202026-02-27%20164307.png)

### 9️⃣ Correlated Detection Validation
![Correlation Validation](Screenshot%202026-02-27%20164454.png)
