# Tester

A powerful Docker-based website testing tool that performs SEO, security, accessibility, performance, and QA testing using industry-standard tools.

## 🔧 Tools Included

### Accessibility
- **Pa11y** - Automated accessibility testing (WCAG 2.1 compliance)
- **Lighthouse Accessibility** - Google's accessibility audits

### Performance
- **Lighthouse Performance** - Core Web Vitals and performance metrics
- **Page load analysis** - Timing and resource metrics

### SEO
- **Lighthouse SEO** - Search engine optimization audits
- **Robots.txt Analysis** - Checks for robots.txt presence and configuration
- **Sitemap Analysis** - Validates sitemap.xml existence and structure
- **DNS Records** - Analyzes DNS configuration (A, AAAA, MX, TXT, NS, CAA, DNSSEC)

### Security
- **sslyze** - SSL/TLS configuration analyzer
- **testssl.sh** - Comprehensive SSL/TLS testing
- **Mozilla Observatory** - Security headers analysis
- **OWASP ZAP** - Automated security vulnerability scanner (optional)
- **Nuclei** - Fast vulnerability scanner with 1000+ templates (optional)

### Quality Assurance
- **W3C HTML Validator** - HTML markup validation
- **Lighthouse Best Practices** - Code quality and best practices

## 📋 Prerequisites

- Docker
- Docker Compose (optional, but recommended)

## 🚀 Quick Start

### Option 1: Using Docker Compose (Recommended)

1. **Build the image:**

```bash
docker compose build
```

2. **Run a test:**

```bash
docker compose run --rm tester https://example.com -o /output/report.pdf
```

### Option 2: Using Docker directly

1. **Build the image:**

```bash
docker build -t tester .
```

2. **Run a test:**

```bash
docker run --rm -v $(pwd)/reports:/output tester https://example.com -o /output
```

## 📖 Usage

### Basic Usage

```bash
docker run --rm -v $(pwd)/reports:/output tester https://example.com
```

### Advanced Options

```bash
# Custom output directory
docker run --rm -v $(pwd)/my-reports:/output tester https://example.com -o /output

# Save JSON results
docker run --rm -v $(pwd)/reports:/output tester https://example.com -j /output/results.json

# Adjust parallel workers
docker run --rm -v $(pwd)/reports:/output tester https://example.com -w 8

# Combine options
docker run --rm -v $(pwd)/reports:/output tester https://example.com -o /output -j /output/data.json -w 10
```

### Command Line Arguments

| Argument | Description | Default |
|----------|-------------|---------|
| `url` | Website URL to test (required) | - |
| `-o, --output` | Output directory for reports | /output |
| `-j, --json` | Save JSON results to file | - |
| `-w, --workers` | Number of parallel workers | 5 |
| `-h, --help` | Show help message | - |

## 📊 Output

The tool generates a comprehensive PDF report containing:

### Executive Summary
- Total accessibility violations
- Security header status and grade
- SSL certificate status
- HTML validation errors
- Key metrics overview

### Separate Lighthouse HTML Report
- Comprehensive performance analysis in lighthouse_report.html
- Core Web Vitals, accessibility, SEO, and best practices audits
- Detailed recommendations and optimization suggestions
- Interactive charts and visualizations
- Full-page screenshot and network analysis

### Detailed Sections

1. **Lighthouse HTML Report**
   - Separate comprehensive HTML report (lighthouse_report.html)
   - Performance metrics, accessibility, SEO, and best practices
   - Detailed recommendations with screenshots
   - Interactive charts and full analysis

2. **Accessibility Analysis (axe-core)**
   - Violations by severity (Critical, Serious, Moderate, Minor)
   - Detailed violation descriptions with affected elements
   - CSS selectors for each issue
   - Remediation guidance links

3. **Security Analysis**
   - Mozilla Observatory grade and score
   - Security headers status (present/missing)
   - SSL/TLS configuration (protocols, ciphers)
   - Certificate validity and details
   - Weak protocol detection

4. **SSL/TLS Analysis (testssl.sh)**
   - Comprehensive SSL/TLS vulnerability scan
   - Protocol-level issues
   - CVE references

5. **HTML Validation (W3C)**
   - Markup errors and warnings
   - Line numbers and descriptions
   - Standards compliance

6. **SEO Analysis**
   - Robots.txt presence and configuration
   - Sitemap.xml validation
   - URL count in sitemap

7. **DNS Analysis**
   - DNS record types (A, AAAA, MX, TXT, NS, CNAME)
   - CAA record check
   - DNSSEC status

8. **Vulnerability Scans** (when enabled)
   - OWASP ZAP findings
   - Nuclei vulnerabilities

## 🔍 Tests Performed

| Category | Tool | What It Tests |
|----------|------|---------------|
| **Performance** | Lighthouse | FCP, LCP, TBT, CLS, Speed Index, Resource loading |
| **Accessibility** | Pa11y | WCAG 2.1 compliance, ARIA, Color contrast, Keyboard nav |
| **Accessibility** | Lighthouse | Accessibility best practices, Labels, Alt text |
| **SEO** | Lighthouse | Meta tags, Structured data, Mobile-friendliness |
| **SEO** | Custom | Robots.txt, Sitemap.xml, DNS records |
| **Security** | sslyze | SSL/TLS versions, Cipher suites, Certificate validity |
| **Security** | testssl.sh | SSL/TLS vulnerabilities, Protocol weaknesses |
| **Security** | Mozilla Observatory | Security headers (CSP, HSTS, X-Frame-Options, etc.) |
| **Security** | OWASP ZAP* | XSS, SQL injection, CSRF, Insecure configs |
| **Security** | Nuclei* | CVEs, Misconfigurations, Exposed panels |
| **Quality** | W3C Validator | HTML5 syntax, Markup errors, Standards compliance |
| **Quality** | Lighthouse | Best practices, Modern APIs, Console errors |
| **DNS** | dnspython | A, AAAA, MX, TXT, NS, CAA, DNSSEC |

*Optional tests - uncomment in `tester.py` to enable

## ⚡ Performance Tips

### Enable Additional Scans

To enable OWASP ZAP and Nuclei scans, edit `tester.py` and uncomment these lines in `run_all_tests()`:

```python
# ('OWASP ZAP Security Scan', self.run_owasp_zap),
# ('Nuclei Vulnerability Scanner', self.run_nuclei),
```

Note: OWASP ZAP requires Docker socket access. Update `docker-compose.yml` accordingly.

### Parallel Processing

Increase workers for faster execution:

```bash
docker run --rm -v $(pwd)/reports:/output tester https://example.com -w 10
```

### Resource Allocation

Allocate more resources to Docker:

```bash
docker run --rm --cpus="4" --memory="4g" -v $(pwd)/reports:/output tester https://example.com
```

## 🐛 Troubleshooting

### Chromium Issues

If Lighthouse fails with Chromium errors:

```bash
# Rebuild with --no-cache
docker build --no-cache -t tester .
```

### Permission Issues

If you encounter permission errors:

```bash
# Linux/Mac
sudo chown -R $USER:$USER reports/

# Or run with user flag
docker run --user $(id -u):$(id -g) --rm -v $(pwd)/reports:/output tester https://example.com
```

### Timeout Issues

For large sites, increase timeouts in the code:

```python
# In individual test methods, change:
timeout=300  # to timeout=600 or higher
```

### Memory Issues

If tests fail due to memory:

```bash
docker run --memory="8g" --rm -v $(pwd)/reports:/output tester https://example.com
```

## 📁 Project Structure

```
.
├── tester.py             # Main testing script
├── Dockerfile            # Docker image configuration
├── environment.yml       # Conda environment specification
├── docker-compose.yml    # Docker Compose configuration
├── README.MD             # This file
└── reports/              # Output directory (created automatically)
    ├── report.pdf        # Main PDF report
    ├── lighthouse_report.html  # Lighthouse HTML report
    └── results.json      # Raw JSON data
```

## 🔐 Security Notes

- This tool performs active scanning which may trigger security alerts
- Always get permission before scanning websites you don't own
- Some tests (OWASP ZAP, Nuclei) are intrusive and may be flagged by WAFs
- Use responsibly and ethically

## 📝 Example Report Sections

### Lighthouse Performance
```
Performance Score: 85/100
First Contentful Paint: 1.2s
Largest Contentful Paint: 2.4s
Total Blocking Time: 150ms
Cumulative Layout Shift: 0.05
Speed Index: 2.1s
```

### axe-core Violations
```
Total Violations: 12
Critical: 2 | Serious: 4 | Moderate: 5 | Minor: 1

1. [SERIOUS] color-contrast
   Ensures the contrast between foreground and background colors meets WCAG 2 AA
   Affected elements: 8
   → #header > nav > ul > li:nth-child(3)

2. [CRITICAL] label
   Ensures every form element has a label
   Affected elements: 3
```

### Security Headers
```
Mozilla Observatory Grade: B
Score: 65/100
Tests Passed: 8/12

Missing Headers:
• Content-Security-Policy
• Permissions-Policy

Present Headers:
✓ Strict-Transport-Security
✓ X-Frame-Options
✓ X-Content-Type-Options
```

### DNS Analysis
```
Hostname: example.com

A Records:
  • 93.184.216.34

MX Records:
  • 10 mail.example.com

✓ CAA records configured
⚠ DNSSEC not detected
```

## 🤝 Contributing

Feel free to submit issues, fork the repository, and create pull requests for any improvements.

## 📄 License

MIT License - feel free to use this tool for personal and commercial projects.

## ⚠️ Disclaimer

This tool is provided as-is. Always obtain proper authorization before testing websites. The authors are not responsible for misuse of this tool.

## 🔗 Tool Documentation

- [Lighthouse](https://developers.google.com/web/tools/lighthouse)
- [Pa11y](https://pa11y.org/)
- [OWASP ZAP](https://www.zaproxy.org/)
- [Nuclei](https://nuclei.projectdiscovery.io/)
- [sslyze](https://github.com/nabla-c0d3/sslyze)
- [testssl.sh](https://testssl.sh/)
- [Mozilla Observatory](https://observatory.mozilla.org/)
- [W3C Validator](https://validator.w3.org/)
- [dnspython](https://www.dnspython.org/)
