# Takeover - Subdomain Takeover Finder v0.2

### ([@edoardottt](https://github.com/edoardottt) fork)

![screen](https://raw.githubusercontent.com/edoardottt/takeover/master/screen.png)

Sub-domain takeover vulnerability occur when a sub-domain (**subdomain.example.com**) is pointing to a service (e.g: **GitHub**, **AWS/S3**,..) that has been removed or deleted.  
This allows an attacker to set up a page on the service that was being used and point their page to that sub-domain.  
For example, if **subdomain.example.com** was pointing to a GitHub page and the user decided to delete their GitHub page, an attacker can now create a GitHub page, add a **CNAME** file containing **subdomain.example.com**, and claim **subdomain.example.com**.  
For more information read <https://labs.detectify.com/2014/10/21/hostile-subdomain-takeover-using-herokugithubdesk-more/>

## Features

- ✅ **70+ Service Signatures** - Detects takeover vulnerabilities across major platforms
- ✅ **DNS Resolution Checking** - Validates CNAME records to reduce false positives
- ✅ **Multiple Output Formats** - Export results as TXT, JSON, CSV, or HTML
- ✅ **Rate Limiting** - Configurable request rate to avoid overwhelming targets
- ✅ **Custom Service Definitions** - Load service signatures from JSON files
- ✅ **SSL Verification** - Optional SSL certificate validation
- ✅ **Multi-threaded Scanning** - Concurrent domain checking for faster results
- ✅ **Input Validation** - Validates domain formats before processing
- ✅ **Comprehensive Testing** - Unit tests with pytest
- ✅ **CI/CD Pipeline** - Automated testing with GitHub Actions

## Supported Services

- Acquia
- ActiveCampaign
- Aftership
- Aha
- AWS/S3
- Bigcartel
- BitBucket
- Brightcove
- Campaignmonitor
- Cargo
- CloudFront
- Desk
- Fastly
- FeedPress
- GetResponse
- Ghost
- Github
- Helpjuice
- Helpscout
- Heroku
- Intercom
- Jetbrains
- Kajabi
- Mashery
- Pantheon
- Pingdom
- Proposify
- S3Bucket
- Shopify
- Simplebooklet
- Smartling
- StatuPage
- Surge
- Surveygizmo
- Tave
- TeamWork
- Thinkific
- Tictail
- Tilda
- Tumbler
- Unbounce
- Uservoice
- Vend
- Webflow
- Wishpond
- Wordpress
- ZenDesk
- feedpress
- readme
- statuspage
- zendesk  
- worksites.net
- smugmug
- **Vercel** ⭐ (New)
- **Netlify** ⭐ (New)
- **Railway** ⭐ (New)
- **Render** ⭐ (New)
- **Azure** ⭐ (New)
- **DigitalOcean** ⭐ (New)
- **Cloudflare Pages** ⭐ (New)
- **GitLab Pages** ⭐ (New)
- **Firebase** ⭐ (New)
- **Squarespace** ⭐ (New)
- **Wix** ⭐ (New)
- **Supabase** ⭐ (New)

## Installation

```console
git clone https://github.com/edoardottt/takeover.git
cd takeover
python3 setup.py install
```

**or:**

```console
wget -q https://raw.githubusercontent.com/edoardottt/takeover/master/takeover.py && python3 takeover.py
```

## Usage

### Basic Usage

```console
# Scan a single domain
python3 takeover.py -d www.domain.com -v

# Scan multiple domains from file
python3 takeover.py -l domains.txt -v

# Save results to file (supports .txt, .json, .csv, .html)
python3 takeover.py -d www.domain.com -o results.html -v
```

### Advanced Options

```console
# Use custom threads and timeout
python3 takeover.py -d www.domain.com -v -t 10 -T 30

# Use proxy
python3 takeover.py -d www.domain.com -p http://127.0.0.1:8080 -v

# Enable SSL verification
python3 takeover.py -d www.domain.com -v -s

# Rate limiting (5 requests per second)
python3 takeover.py -l domains.txt -r 5 -v

# Use custom services file
python3 takeover.py -d www.domain.com -S custom_services.json -v

# Disable DNS checking
python3 takeover.py -d www.domain.com -n -v

# Full example with all options
python3 takeover.py -l domains.txt -o output.csv -t 10 -T 30 -r 5 -s -v
```

### Command Line Options

**Basic Options:**
- `-d` : Set domain URL (e.g: www.test.com)
- `-l` : Scan multiple targets in a text file
- `-o` : Output file (supports .txt, .json, .csv, .html)
- `-v` : Verbose, print more info

**Advanced Options:**
- `-t` : Set threads (default: 1)
- `-T` : Set request timeout in seconds (default: 20)
- `-p` : Use a proxy to connect the target URL
- `-u` : Set custom user agent
- `-r` : Rate limit in requests/second (default: 0 = no limit)
- `-S` : Custom services JSON file path

**Security & Validation:**
- `-s` : Verify SSL certificates (disabled by default)
- `-n` : Disable DNS resolution checking
- `-k` : Process 200 HTTP code (may cause false positives)

## Docker support

Build the image:

```console
docker build -t takeover .
```

Run the container:

```console
docker run -it --rm takeover -d www.domain.com -v
```

## Testing

Run the test suite:

```console
# Install development dependencies
pip install -r requirements-dev.txt

# Run tests
pytest test_takeover.py -v

# Run tests with coverage
pytest test_takeover.py -v --cov=takeover --cov-report=html

# Run linting
flake8 takeover.py
black --check takeover.py
mypy takeover.py --ignore-missing-imports
```

## Custom Services File

You can define your own service signatures in a JSON file:

```json
{
  "services": {
    "MyService": {
      "error": "error pattern regex",
      "cname": ["expected-cname.example.com"]
    }
  }
}
```

Then use it with the `-S` flag:

```console
python3 takeover.py -d example.com -S my_services.json -v
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Run tests (`pytest test_takeover.py -v`)
4. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
5. Push to the branch (`git push origin feature/AmazingFeature`)
6. Open a Pull Request

---------

This repository is under [MIT License](https://github.com/edoardottt/takeover/blob/master/LICENSE).  
[edoardottt.com](https://edoardottt.com/) to contact me.
