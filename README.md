# Secure Software Development Project

### Team Members

* **Abdelrhman Islam** – ID: 2305152
* * **Abdelrhman Elsayed** – ID: 2305153
* **Mohamed Adel** – ID: 2305184

**Course:** Secure Software Development
**Program:** Cybersecurity
**Faculty:** Computers and Data Science
**Semester:** Fall 2025

---

## Project Overview

This project demonstrates a full secure software development lifecycle by hardening a deliberately vulnerable **Node.js + Express** web application. The work combines **Dynamic Application Security Testing (DAST)**, **Static Application Security Testing (SAST)** using **Semgrep**, secure remediation, and re-testing to verify that vulnerabilities have been successfully eliminated.

The project follows the official course workflow and exceeds the minimum requirements by identifying, exploiting, and fixing **9 distinct real-world vulnerabilities** mapped to the **OWASP Top 10** categories.

---

## Learning Objectives

* Perform real-world web penetration testing using DAST tools
* Identify vulnerabilities and produce reproducible Proofs of Concept (PoCs)
* Analyze application source code using Semgrep (SAST)
* Write custom Semgrep rules to detect logic-based vulnerabilities
* Apply secure coding patterns in Node.js / Express applications
* Validate security fixes through before-and-after testing

---

## Target Application

* **Base Repository:**
  [https://github.com/SirAppSec/vuln-node.js-express.js-app](https://github.com/SirAppSec/vuln-node.js-express.js-app)

* **Technology Stack:**

  * Node.js
  * Express.js
  * SQLite + Sequelize
  * Nunjucks Template Engine

> All testing was conducted locally in a controlled lab environment only.

---

## Installation & Running the Application

### 1️⃣ Clone the Repository

```bash
git clone https://github.com/SirAppSec/vuln-node.js-express.js-app.git
cd vuln-node.js-express.js-app
```

### 2️⃣ Install Dependencies

```bash
npm install
```

### 3️⃣ Run the Application

```bash
npm run dev
```

The application will be available at:

```
http://localhost:5000
```

---

## Phase A – Dynamic Testing (DAST)

### Tools Used

* OWASP ZAP (Automated scanning)
* Web browser and curl (Manual testing)

### Confirmed Vulnerabilities

| ID | Vulnerability   | Endpoint                   | OWASP Top 10 Category                               |
| -- | --------------- | -------------------------- | --------------------------------------------------- |
| V1 | IDOR            | GET /profile?id=           | A01 – Broken Access Control                         |
| V2 | Reflected XSS   | GET /profile?message=      | A03 – Injection                                     |
| V3 | Open Redirect   | GET /v1/redirect/?url=     | A01 – Broken Access Control                         |
| V4 | SSTI            | GET /?message={{...}}      | A03 – Injection                                     |
| V5 | RCE             | GET /v1/status/{input}     | A03 – Injection                                     |
| V6 | Path Traversal  | GET /v1/beer-pic/?picture= | A01 – Broken Access Control                         |
| V7 | XXE             | POST /v1/new-beer-xml/     | A05 – Security Misconfiguration                     |
| V8 | SSRF            | GET /v1/test/?url=         | A10 – Server-Side Request Forgery                   |
| V9 | Mass Assignment | PUT /v1/user/{id}          | A01 – Broken Access Control / A04 – Insecure Design |

Each vulnerability includes a working PoC, impact explanation, and OWASP mapping, fully documented in the security report.

---

## Phase B – Static Analysis (SAST)

### Semgrep Built-in Rules

```bash
semgrep --config "p/javascript" --config "p/nodejs" --config "p/owasp-top-ten"
```

* Baseline scan detected common issues such as XSS and Path Traversal
* Logic vulnerabilities (IDOR, RCE, SSRF, Mass Assignment) required custom rules

### Custom Semgrep Rules

Custom Semgrep rules were written to detect:

* Insecure Direct Object Reference (IDOR)
* Remote Code Execution (dangerous command execution)
* Server-Side Request Forgery (SSRF)
* XML External Entity Injection (XXE)
* Mass Assignment vulnerabilities

Custom rules location:

```
semgrep-rules/custom-rules.yaml
```

---

## Phase C – Fix & Harden

All discovered vulnerabilities were remediated using secure coding best practices, including:

* Session-based access control validation
* Input validation and output encoding
* Removal of dangerous system execution APIs
* Allowlists for command and URL inputs
* Secure template rendering
* Safe filesystem path handling
* Prevention of mass assignment and privilege escalation

Each fix includes file location, line numbers, and a clear security justification, documented in detail in the report.

---

## Re-Testing & Verification

### DAST Re-Test

* All original attack payloads fail after applying fixes
* Malicious input is rejected, sanitized, or blocked

### SAST Re-Test

* **Before fixes:** 10 High/Critical findings
* **After fixes:** 0 findings using both built-in and custom Semgrep rules

This confirms the effectiveness of the applied security controls.

---

## Demonstration Video

A short video (≤ 3 minutes) demonstrates:

* Exploiting a real vulnerability
* Verifying that the exploit fails after remediation

---

## Conclusion

This project demonstrates a complete secure software development lifecycle, combining offensive security testing, static code analysis, custom security tooling, and secure remediation. The final result is a significantly hardened application that aligns with OWASP Top 10 guidelines and industry best practices.
