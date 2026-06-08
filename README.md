# Week 5 – Ethical Hacking & Exploiting Vulnerabilities

**Intern:** Syed Saim Ahmed
**ID:** DHC-1014
**Date:** june 2026

## What was done in Week 5

### 1. Ethical Hacking & Reconnaissance
- Used Nmap for port scanning and service discovery
- Identified open ports and running services
- Documented network topology

### 2. SQL Injection Testing & Fixes
- **SQLMap** used to test for SQL injection vulnerabilities
- Original query was vulnerable to SQL injection
- **Fixed** by using parameterized queries / prepared statements
- SQLMap re-run after fix — no injection point found

### 3. CSRF Protection
- Identified CSRF vulnerability using **Burp Suite**
- Implemented CSRF protection using **csurf middleware**
- CSRF tokens required on all POST/DELETE requests
- Burp Suite re-test confirmed CSRF was blocked

## Packages installed

```bash
npm install csurf cookie-parser
# (express-rate-limit, cors, helmet already installed in Week 4)
```

## How to Run

```bash
git clone https://github.com/YourUsername/Week5-Ethical-Hacking-SQLi-CSRF
cd Week5-Ethical-Hacking-SQLi-CSRF
npm install
cp .env.example .env  # Configure your database
node index.js
```

## Security Improvements in Week 5

### SQL Injection Fix
**Before (VULNERABLE):**
```javascript
const query = "SELECT * FROM admin WHERE username = '" + username + "'";
pool.query(query, ...);
```

**After (SAFE):**
```javascript
pool.query('SELECT * FROM admin WHERE username = ?', [username], ...);
```

### CSRF Protection
- Added `csurf` middleware for token-based CSRF protection
- Tokens embedded in forms and required for state-changing requests
- Invalid/missing tokens result in 403 Forbidden response

## Testing Results

### SQLMap Testing
| Test | Before Fix | After Fix |
|---|---|---|
| SQL Injection Detected | ✅ Yes | ❌ No |
| Database Accessible | ✅ Yes | ❌ No |
| Status | Vulnerable | **Secured** |

### Burp Suite CSRF Testing
| Test | Before Fix | After Fix |
|---|---|---|
| CSRF Attack Successful | ✅ Yes | ❌ No |
| CSRF Token Required | ❌ No | ✅ Yes |
| Status | Vulnerable | **Secured** |

## Tools Used
- **Nmap** — Reconnaissance and port scanning
- **SQLMap** — Automated SQL injection detection
- **Burp Suite** — Manual CSRF testing and HTTP interception
- **Browser DevTools** — Request/response inspection

## Files
- `index.js` — Main server with SQL fix + CSRF protection
- `middleware/authenticateToken.js` — JWT verification
- `middleware/checkApiKey.js` — API key verification
- `middleware/csrfProtection.js` — CSRF token middleware
- `.env.example` — Environment variables template
- `security.log` — Sample security events log

## Security Checklist - Week 5
- [x] SQL injection testing performed with SQLMap
- [x] SQL injection vulnerability confirmed in original code
- [x] Parameterized queries implemented in all database calls
- [x] SQLMap re-test shows 0 injection points
- [x] CSRF vulnerability identified using Burp Suite
- [x] CSRF protection via csurf middleware implemented
- [x] CSRF tokens required on all POST/DELETE routes
- [x] Burp Suite CSRF PoC generation blocked
- [x] All previous week's fixes still in place

