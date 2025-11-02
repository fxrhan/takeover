# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased] - 2024

### Added - Functionality Enhancements

#### Service Signatures
- **70+ Service Signatures** - Added modern cloud services:
  - Vercel, Netlify, Railway, Render
  - Azure, DigitalOcean, Cloudflare Pages
  - GitLab Pages, Firebase
  - Squarespace, Wix, Supabase
- **JSON Configuration** - `services.json` file for easy service signature updates
- **Custom Services Support** - Load custom service definitions via `-S` flag
- **Dynamic Service Loading** - Services loaded from JSON with fallback to defaults

#### DNS Resolution & Validation
- **DNS Resolution Checking** - Validates domains resolve before scanning
- **CNAME Validation** - Checks CNAME records match expected service patterns
- **False Positive Reduction** - DNS checks significantly reduce false positives
- **Optional DNS Checking** - Can be disabled with `-n` flag for faster scanning

#### Output Formats
- **CSV Export** - Structured data export for spreadsheet analysis
- **HTML Reports** - Beautiful, styled HTML reports with summary statistics
- **Enhanced JSON** - Improved JSON structure with metadata
- **Text Format** - Maintained original text output format

#### Rate Limiting
- **Configurable Rate Limiting** - Control requests per second with `-r` flag
- **Thread-Safe Implementation** - Works correctly with multi-threaded scanning
- **Prevents Blocking** - Avoid overwhelming targets or getting IP blocked

#### Testing & Quality
- **Unit Tests** - Comprehensive pytest test suite (test_takeover.py)
- **Test Coverage** - Tests for all major functions and edge cases
- **CI/CD Pipeline** - GitHub Actions workflow for automated testing
- **Multi-Platform Testing** - Tests run on Ubuntu, Windows, and macOS
- **Python Version Support** - Tested on Python 3.8, 3.9, 3.10, 3.11, 3.12

#### Documentation
- **requirements.txt** - Standard Python dependencies file
- **requirements-dev.txt** - Development dependencies for testing/linting
- **Enhanced README** - Comprehensive documentation with examples
- **Code Documentation** - Docstrings for all functions with type hints
- **Contributing Guide** - Instructions for contributors

### Changed - Code Quality & Maintainability

#### Architecture
- **Removed Global Variables** - Replaced with `ScanConfig` dataclass
- **Class-Based Design** - `TakeoverScanner` class for better organization
- **Type Hints** - Full type annotations throughout codebase
- **Dataclasses** - Modern Python dataclass for configuration

#### Error Handling
- **Specific Exception Handling** - Catches specific request exceptions
- **Informative Error Messages** - Clear error messages with context
- **Graceful Degradation** - Continues scanning on individual failures
- **Verbose Error Reporting** - Optional detailed error output

#### Code Standards
- **Named Constants** - HTTP status codes as named constants
- **Removed Magic Numbers** - All hardcoded values replaced with constants
- **Removed Redundant Code** - Cleaned up unnecessary assignments
- **Better Function Names** - More descriptive function names

#### Input Validation
- **Domain Validation** - Regex-based domain format validation
- **File Path Validation** - Validates file paths before reading
- **Invalid Domain Filtering** - Automatically filters invalid domains from lists
- **Early Validation** - Validates inputs before processing

### Security Improvements

#### SSL/TLS
- **Configurable SSL Verification** - Enable with `-s` flag
- **SSL Warnings** - Warns when SSL verification is disabled
- **Secure by Default** - Encourages SSL verification usage

#### User Agent
- **Updated User Agent** - Modern Chrome 120 user agent string
- **Configurable User Agent** - Custom user agents via `-u` flag

#### Dependencies
- **Security Scanning** - Bandit and Safety checks in CI/CD
- **Updated Dependencies** - Latest versions of requests and urllib3
- **Vulnerability Monitoring** - Automated dependency vulnerability checks

### Performance

#### Optimization
- **Connection Reuse** - Better connection handling
- **Efficient Threading** - Improved thread pool management
- **Rate Limiting** - Prevents resource exhaustion
- **DNS Caching** - DNS resolver with timeout configuration

### Developer Experience

#### CLI Improvements
- **Better Help Text** - Organized help with sections and examples
- **More Options** - Additional flags for fine-tuning behavior
- **Clear Examples** - Usage examples in help output

#### Code Quality Tools
- **Linting** - flake8 configuration
- **Formatting** - black code formatter
- **Type Checking** - mypy static type checking
- **Pre-commit Hooks** - Ready for pre-commit integration

### Files Added
- `services.json` - Service signature definitions
- `requirements.txt` - Python dependencies
- `requirements-dev.txt` - Development dependencies
- `test_takeover.py` - Unit test suite
- `.github/workflows/ci.yml` - CI/CD pipeline
- `CHANGELOG.md` - This file

### Files Modified
- `takeover.py` - Major refactoring with new features
- `README.md` - Comprehensive documentation update
- `setup.py` - Updated dependencies

## [0.2] - Previous Version

### Features
- Basic subdomain takeover detection
- Multiple service signatures
- Multi-threaded scanning
- Proxy support
- JSON and TXT output
- Verbose mode

---

## Migration Guide

### For Users

**Old Command:**
```bash
python takeover.py -d example.com -o output.json -v
```

**New Command (same functionality):**
```bash
python takeover.py -d example.com -o output.json -v
```

**New Features:**
```bash
# With DNS checking and rate limiting
python takeover.py -d example.com -o output.html -v -r 5

# With SSL verification
python takeover.py -d example.com -v -s

# With custom services
python takeover.py -d example.com -S my_services.json -v
```

### For Developers

**Breaking Changes:**
- None - All existing functionality maintained

**New APIs:**
- `load_services(services_file)` - Load services from JSON
- `check_dns_resolution(domain, verbose)` - Check DNS resolution
- `check_cname_match(cnames, service_cnames)` - Validate CNAME records
- `validate_domain(domain)` - Validate domain format
- `savecsv()`, `savehtml()` - New output formats

**Deprecated:**
- Global `_output` variable (replaced with parameter passing)
- Global `k_` dictionary (replaced with `ScanConfig` dataclass)

---

## Acknowledgments

- Original author: M'hamed (@m4ll0k) Outaadi
- Fork maintainer: [@edoardottt](https://github.com/edoardottt)
- Contributors: All who have submitted issues and pull requests
