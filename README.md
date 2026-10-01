# 🛡️ Windows SIEM--REAL TIME EDITION


A lightweight **Windows Security Information and Event Management (SIEM)** platform built using **Python and Flask** for cybersecurity learning, security monitoring, and SOC analyst practice.

Windows SIEM collects Windows Event Logs, analyzes security events using detection rules, generates alerts, and provides a real-time monitoring dashboard.

---

# 📌 Project Overview

Traditional SIEM solutions such as Splunk, IBM QRadar, and Microsoft Sentinel are used by Security Operations Centers (SOC) to monitor enterprise environments.

This project is a simplified SIEM implementation designed to understand:

- Security event collection
- Log analysis
- Threat detection
- Alert generation
- SOC monitoring workflow

The system runs locally on a Windows machine and provides a web-based security dashboard.

---

# 🚀 Features

## 🔍 Windows Event Log Collection

Collects security events from:

- Security Logs
- System Logs
- Application Logs

Monitored information includes:

- Event ID
- Timestamp
- Source
- Username
- Computer Name
- Event Message
- Severity Level


---

## 🧠 Detection Engine

The SIEM analyzes collected events and detects suspicious activities.

Current detection capabilities:

### 🔴 Brute Force Detection

Detects multiple failed login attempts.

### 🔴 Security Log Clearing Detection

Detects attempts to remove Windows audit history.

### 🟠 New Service Installation Detection

Detects newly installed Windows services.

Event:

```
7045 - New Service Created
```


### 🟡 Privileged Account Usage Detection

Detects special privilege usage.

Event:

```
4672 - Special Privileges Assigned
```


---

# 📊 Dashboard

The web dashboard provides:

- Real-time monitoring
- Security alerts
- Event statistics
- Log searching
- Severity visualization
- Alert acknowledgement


Dashboard includes:

```
Total Events
Active Alerts
Critical Alerts
Event Timeline
Severity Distribution
Recent Security Events
```

---

# 🔐 Authentication & Access Control

The system supports user authentication.

Roles:

## Administrator

Permissions:

- View dashboard
- Manage alerts
- Acknowledge alerts
- Manage SIEM functions


## Analyst

Permissions:

- View security events
- Investigate alerts
- Monitor activity


---

# 🏗️ Architecture

```
                 Windows Machine

                      |
                      |
             Windows Event Logs

                      |
                      |

             Event Collection Engine

                      |
                      |

              Detection Engine

                      |
                      |

                 SQLite Database

                      |
                      |

              Flask Web Dashboard

                      |
                      |

                 Security Analyst
```

---

# 🛠️ Technologies Used

## Programming Language

- Python 3


## Backend

- Flask
- Flask-CORS
- Flask-SocketIO


## Database

- SQLite


## Security Libraries

- bcrypt
- Flask Login


## Frontend

- HTML
- CSS
- JavaScript
- Chart.js


---

# 📂 Project Structure

```
# ⚙️ Installation

## 1. Clone Repository

```bash
git clone https://github.com/yourusername/Windows-SIEM.git
```

Move into project directory:

```bash
cd Windows-SIEM
```

---

## 2. Install Dependencies

```bash
pip install -r requirements.txt
```

---

## 3. Run Application

Open Command Prompt as Administrator:

```bash
python windows_siem.py
```

---

## 4. Open Dashboard

Open browser:

```
http://127.0.0.1:5000
```

---

# 🖥️ System Requirements

Minimum:

- Windows 10/11
- Python 3.10+
- Administrator privileges
- 4GB RAM

Recommended:

- Windows 11
- 8GB RAM
- Virtual Machine testing environment


---
---

# 🔮 Future Improvements

## Detection Improvements

- Sigma Rule Engine
- MITRE ATT&CK Mapping
- Advanced Correlation Rules
- Risk Scoring System


## Endpoint Security

- Process Monitoring
- File Integrity Monitoring
- Registry Monitoring
- Persistence Detection


## Threat Intelligence

- IP Reputation Checking
- Malware Hash Analysis
- Domain Reputation


## SOC Features

- Incident Management
- Case Tracking
- Analyst Notes
- Email Alerts
- Telegram Notifications


## Enterprise Features

- Multiple Agent Support
- Central SIEM Server
- Elasticsearch Integration
- Threat Hunting Dashboard


---

# 🎯 Learning Objectives

This project helps understand:

- Security Operations Center workflow
- Windows Event Monitoring
- Blue Team security concepts
- Log analysis
- Threat detection
- Incident response basics


---

# ⚠️ Disclaimer

This project is created for:

- Educational purposes
- Cybersecurity learning
- Personal lab environments

Do not deploy this system in a production environment without additional security hardening.

---

# 👨‍💻 Author

OJAS

---


