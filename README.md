# Cloud-Native Security Audit & BOLA/IDOR Defense Lab

[![Security Audit Gate](https://github.com/shivarajboza94/cloud-threat-lab/actions/workflows/security-scan.yml/badge.svg)](https://github.com/shivarajboza94/cloud-threat-lab/actions/workflows/security-scan.yml)

An automated DevSecOps pipeline and containerized threat-modeling lab designed to detect and prevent Broken Object-Level Authorization (BOLA/IDOR), SSRF, and container escape vulnerabilities in CI/CD.

---

## 🛡️ Security Features
- **Automated API Auditing:** Custom Nuclei templates scanning microservices for authorization flaws.
- **SARIF Code Scanning:** Results export to SARIF 2.1.0 and integrate directly with GitHub Code Scanning alerts.
- **Baseline Suppression Gate:** Python-driven quality gate supporting expiration-managed exception lists (`config/security-baseline.json`).
- **PR Commenter:** Automatically posts detailed Markdown summary tables directly onto active Pull Requests.
