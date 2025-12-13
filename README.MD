# Tester

A comprehensive testing suite that checks your website for SEO, security, accessibility, performance, and code quality issues. Built with industry-standard tools and packaged in Docker for easy deployment.

## What's Tested

### Accessibility
- **Pa11y** - Checks WCAG 2.1 compliance and finds accessibility barriers
- **Lighthouse** - Google's automated accessibility audits

### Performance
- **Lighthouse** - Measures Core Web Vitals and overall speed
- **Load Analysis** - Tracks how quickly pages load and render

### SEO
- **Lighthouse** - SEO best practices and mobile-friendliness
- **Robots.txt** - Ensures crawlers can properly access your site
- **Sitemap** - Validates your XML sitemap structure
- **DNS Records** - Checks A, AAAA, MX, TXT, NS, CAA records and DNSSEC

### Security
- **sslyze** - SSL/TLS configuration analysis
- **testssl.sh** - Deep SSL/TLS vulnerability scanning
- **Mozilla Observatory** - Security headers check (CSP, HSTS, etc.)
- **OWASP ZAP** - Automated vulnerability scanning (optional)
- **Nuclei** - Fast CVE and misconfiguration detection (optional)

### Code Quality
- **W3C Validator** - HTML markup validation
- **Lighthouse** - Modern web standards and best practices

## Getting Started

You'll need Docker installed. Docker Compose makes things easier but isn't strictly required.

### Quick Test with Docker Compose

Build the image first:

```bash
docker compose build
```

Then test a website:

```bash
docker compose run --rm tester https://example.com
```

### Or Use Docker Directly

Build the image:

```bash
docker build -t tester .
```

Run your test:

```bash
docker run --rm -v $(pwd)/reports:/output tester https://example.com
```

## How to Use

### Simple Test

Just run it on any website:

```bash
docker run --rm -v $(pwd)/reports:/output tester https://example.com
```

### Command Options

| Flag | What it does | Default |
|------|-------------|---------|
| `url` | The website to test (required) | - |
| `-o, --output` | Where to save reports | /output |
| `-j, --json` | Save raw results as JSON | - |
| `-w, --workers` | How many tests to run at once | 5 |
| `-h, --help` | Show all options | - |

### Examples

```bash
# Test with custom output location
docker run --rm -v $(pwd)/my-reports:/output tester https://example.com -o /output

# Save results as JSON too
docker run --rm -v $(pwd)/reports:/output tester https://example.com -j /output/results.json

# Speed it up with more workers
docker run --rm -v $(pwd)/reports:/output tester https://example.com -w 8

# Everything combined
docker run --rm -v $(pwd)/reports:/output tester https://example.com -o /output -j /output/data.json -w 10
```

## What You Get

You'll receive two files in your output directory:

- **PDF Report** (`report.pdf`) - A complete summary with actionable insights
- **Lighthouse HTML Report** (`lighthouse_report.html`) - Google's detailed performance analysis with charts and screenshots

### PDF Report Contents

**Quick Overview**
- How many accessibility issues were found
- Your security grade and missing headers
- SSL certificate status
- HTML validation problems
- Key performance metrics

**Deep Dive Sections**

1. **Performance Details**
   - Load times, Core Web Vitals scores
   - What slows your site down
   - Optimization recommendations

2. **Accessibility Check**
   - WCAG compliance violations by severity
   - Which elements need fixing
   - CSS selectors for each problem

3. **Security Audit**
   - SSL/TLS configuration analysis
   - Missing security headers
   - Certificate validity checks

4. **SEO Analysis**
   - Robots.txt and sitemap validation
   - DNS record configuration
   - Search engine readiness

5. **Code Quality**
   - HTML validation errors
   - Modern web standards compliance

6. **Vulnerability Scans** (if enabled)
   - OWASP ZAP security findings
   - Known vulnerability detection

## Test Coverage

Here's what gets checked:

| Area | Tool | Details |
|------|------|---------|
| **Performance** | Lighthouse | Page speed, Core Web Vitals, loading bottlenecks |
| **Accessibility** | Pa11y | WCAG 2.1 compliance, screen readers, keyboard navigation |
| **Accessibility** | Lighthouse | Alt text, form labels, color contrast |
| **SEO** | Lighthouse | Meta tags, mobile optimization, structured data |
| **SEO** | Custom checks | Robots.txt, sitemaps, DNS configuration |
| **Security** | sslyze | SSL certificates, cipher suites, protocol support |
| **Security** | testssl.sh | SSL vulnerabilities, weak configurations |
| **Security** | Mozilla Observatory | Security headers, HTTPS enforcement |
| **Security** | OWASP ZAP* | XSS, SQL injection, CSRF attacks |
| **Security** | Nuclei* | Known vulnerabilities, exposed services |
| **Code Quality** | W3C Validator | HTML syntax, standards compliance |
| **Code Quality** | Lighthouse | Modern APIs, error handling, best practices |

*Some security tests are disabled by default - see below for how to enable them

## Making It Faster

### Enable Extra Security Checks

For thorough security testing, you can turn on OWASP ZAP and Nuclei scans. Just edit `tester.py` and uncomment these lines in the `run_all_tests()` method:

```python
# ('OWASP ZAP Security Scan', self.run_owasp_zap),
# ('Nuclei Vulnerability Scanner', self.run_nuclei),
```

**Note:** OWASP ZAP needs Docker socket access, so update your `docker-compose.yml` if using Compose.

### Speed Things Up

Run tests in parallel to finish faster:

```bash
# Use 10 workers instead of the default 5
docker run --rm -v $(pwd)/reports:/output tester https://example.com -w 10
```

Give Docker more resources for better performance:

```bash
docker run --rm --cpus="4" --memory="4g" -v $(pwd)/reports:/output tester https://example.com
```

## Common Issues

### Lighthouse Won't Run

If you see Chromium errors, try rebuilding the Docker image:

```bash
docker build --no-cache -t tester .
```

### File Permission Problems

Can't write to the reports folder? Fix the permissions:

```bash
# On Linux/Mac
sudo chown -R $USER:$USER reports/

# Or run Docker as your user
docker run --user $(id -u):$(id -g) --rm -v $(pwd)/reports:/output tester https://example.com
```

### Tests Take Too Long

For big sites, the tests might timeout. Increase the timeout values in `tester.py`:

```python
# Look for timeout=300 and change to:
timeout=600  # or even higher
```

### Out of Memory

Getting memory errors? Give Docker more RAM:

```bash
docker run --memory="8g" --rm -v $(pwd)/reports:/output tester https://example.com
```

## Project Files

```
.
├── tester.py             # The main testing script
├── Dockerfile            # Docker setup instructions
├── environment.yml       # Python environment definition
├── docker-compose.yml    # Easy Docker deployment
├── README.MD             # You're reading it
└── reports/              # Where results get saved
    ├── report.pdf        # Your main report
    ├── lighthouse_report.html  # Detailed performance analysis
    └── results.json      # Raw data if you want it
```

## Important Security Notice

This tool does active security testing, which might set off alarms on some systems. Always:

- Get permission before testing sites you don't own
- Be aware that OWASP ZAP and Nuclei can trigger web application firewalls
- Use responsibly and follow ethical guidelines

## Contributing

Found a bug or want to add a feature? Feel free to open an issue or submit a pull request. All contributions are welcome!

## License

This project uses the MIT License.

## Learn More

For details about the underlying tools:

- [Lighthouse](https://developers.google.com/web/tools/lighthouse) - Google's performance testing
- [Pa11y](https://pa11y.org/) - Accessibility testing
- [OWASP ZAP](https://www.zaproxy.org/) - Security scanning
- [Nuclei](https://nuclei.projectdiscovery.io/) - Vulnerability detection
- [sslyze](https://github.com/nabla-c0d3/sslyze) - SSL analysis
- [testssl.sh](https://testssl.sh/) - SSL testing
- [Mozilla Observatory](https://observatory.mozilla.org/) - Security headers
- [W3C Validator](https://validator.w3.org/) - HTML validation
- [dnspython](https://www.dnspython.org/) - DNS tools
