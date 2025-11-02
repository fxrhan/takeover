#!/usr/bin/env python3
# takeover - subdomain takeover finder
# coded by M'hamed (@m4ll0k) Outaadi
# edited by edoardottt (https://github.com/edoardottt/takeover)
# https://edoardottt.com/

import os
import json
import requests
import urllib.parse
import concurrent.futures as thread
import urllib3
import getopt
import sys
import re
import warnings
import time
import csv
from typing import Optional, Tuple, List, Dict, Any
from dataclasses import dataclass, field
from pathlib import Path

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False


# ANSI Color codes
r = "\033[1;31m"
g = "\033[1;32m"
y = "\033[1;33m"
b = "\033[1;34m"
r_ = "\033[0;31m"
g_ = "\033[0;32m"
y_ = "\033[0;33m"
b_ = "\033[0;34m"
e = "\033[0m"

# HTTP Status Code Constants
HTTP_OK = 200
HTTP_CREATED = 201
HTTP_MAX_ERROR = 599

# Default Configuration
DEFAULT_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
DEFAULT_TIMEOUT = 20
DEFAULT_THREADS = 1
DEFAULT_RATE_LIMIT = 0  # requests per second, 0 = no limit


@dataclass
class ScanConfig:
    """Configuration for the subdomain takeover scanner."""
    domain: Optional[str] = None
    threads: int = DEFAULT_THREADS
    d_list: Optional[str] = None
    proxy: Optional[str] = None
    output: Optional[str] = None
    timeout: Optional[int] = None
    process: bool = False
    user_agent: str = DEFAULT_USER_AGENT
    verbose: bool = False
    verify_ssl: bool = False
    check_dns: bool = True
    rate_limit: float = DEFAULT_RATE_LIMIT
    services_file: Optional[str] = None
    domains: List[str] = field(default_factory=list)
    dict_len: int = 0


class TakeoverScanner:
    """Main scanner class for subdomain takeover detection."""
    
    def __init__(self, config: ScanConfig):
        self.config = config
        self.output: List[Tuple[str, str, str]] = []


def percent(x: int, y: int) -> float:
    """Calculate percentage.
    
    Args:
        x: Current value
        y: Total value
        
    Returns:
        Percentage as float
    """
    return (float(x) / float(y)) * 100 if y != 0 else 0


def load_services(services_file: Optional[str] = None) -> Dict[str, Dict[str, Any]]:
    """Load service signatures from JSON file.
    
    Args:
        services_file: Path to custom services JSON file
        
    Returns:
        Dictionary of service signatures
    """
    # Try custom file first
    if services_file and os.path.exists(services_file):
        try:
            with open(services_file, 'r') as f:
                data = json.load(f)
                return data.get('services', {})
        except Exception as e:
            warn(f"Failed to load custom services file: {e}")
    
    # Try default services.json in same directory as script
    script_dir = Path(__file__).parent
    default_file = script_dir / 'services.json'
    
    if default_file.exists():
        try:
            with open(default_file, 'r') as f:
                data = json.load(f)
                return data.get('services', {})
        except Exception as e:
            warn(f"Failed to load default services file: {e}")
    
    # Fallback to hardcoded services
    return get_default_services()


def get_default_services() -> Dict[str, Dict[str, Any]]:
    """Get default hardcoded service signatures as fallback.
    
    Returns:
        Dictionary of service signatures
    """
    return {
        "AWS/S3": {"error": r"The specified bucket does not exist"},
        "BitBucket": {"error": r"Repository not found"},
        "Github": {"error": r"There isn\\'t a Github Pages site here\\.|a Github Pages site here"},
        "Shopify": {"error": r"Sorry\\, this (shop|store) is currently unavailable\\."},
        "Heroku": {"error": r"no-such-app.html|<title>no such app</title>|No such app"},
        "Netlify": {"error": r"Not Found - Request ID:|Page Not Found|404 - Page not found"},
        "Vercel": {"error": r"The deployment could not be found|404: NOT_FOUND"},
    }


def check_dns_resolution(domain: str, verbose: bool = False) -> Optional[Tuple[bool, List[str]]]:
    """Check if domain resolves and get CNAME records.
    
    Args:
        domain: Domain to check
        verbose: Verbose output
        
    Returns:
        Tuple of (has_cname, cname_list) or None if DNS check fails
    """
    if not DNS_AVAILABLE:
        return None
    
    try:
        # Remove protocol if present
        clean_domain = domain.replace('http://', '').replace('https://', '').split('/')[0]
        
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5
        
        # Try to get CNAME records
        try:
            cname_answers = resolver.resolve(clean_domain, 'CNAME')
            cnames = [str(rdata.target).rstrip('.') for rdata in cname_answers]
            return (True, cnames)
        except dns.resolver.NoAnswer:
            # No CNAME, but domain might still resolve via A record
            try:
                resolver.resolve(clean_domain, 'A')
                return (False, [])
            except:
                return (False, [])
        except dns.resolver.NXDOMAIN:
            # Domain doesn't exist
            if verbose:
                info(f"Domain does not exist: {clean_domain}")
            return (False, [])
        except Exception:
            return None
    except Exception as e:
        if verbose:
            warn(f"DNS check failed for {domain}: {str(e)}")
        return None


def check_cname_match(cnames: List[str], service_cnames: List[str]) -> bool:
    """Check if any CNAME matches service CNAME patterns.
    
    Args:
        cnames: List of CNAME records from DNS
        service_cnames: List of expected CNAME patterns for service
        
    Returns:
        True if match found
    """
    for cname in cnames:
        for service_cname in service_cnames:
            if service_cname in cname:
                return True
    return False


# Global services dictionary - will be loaded from JSON or defaults
services = {
    "AWS/S3": {"error": r"The specified bucket does not exist"},
    "BitBucket": {"error": r"Repository not found"},
    "Github": {
        "error": r"There isn\\\'t a Github Pages site here\.|a Github Pages site here"
    },
    "Shopify": {"error": r"Sorry\, this (shop|store) is currently unavailable\."},
    "Fastly": {"error": r"Fastly error\: unknown domain\:"},
    "Ghost": {
        "error": r"The thing you were looking for is no longer here\, or never was"
    },
    "Heroku": {
        "error": r"no-such-app.html|<title>no such app</title>|herokucdn.com/error-pages/no-such-app.html|No such app"
    },
    "Pantheon": {
        "error": r"The gods are wise, but do not know of the site which you seek|404 error unknown site"
    },
    "Tumbler": {
        "error": r"Whatever you were looking for doesn\\\'t currently exist at this address."
    },
    "Wordpress": {"error": r"Do you want to register"},
    "TeamWork": {"error": r"Oops - We didn\'t find your site."},
    "Helpjuice": {"error": r"We could not find what you\'re looking for."},
    "Helpscout": {"error": r"No settings were found for this company:"},
    "Cargo": {"error": r"<title>404 &mdash; File not found</title>"},
    "Uservoice": {"error": r"This UserVoice subdomain is currently available"},
    "Surge.sh": {"error": r"project not found"},
    "Intercom": {
        "error": r"This page is reserved for artistic dogs\.|Uh oh\. That page doesn\'t exist</h1>"
    },
    "Webflow": {
        "error": r"<p class=\"description\">The page you are looking for doesn\'t exist or has been \
moved.</p>|The page you are looking for doesn\'t exist or has been moved"
    },
    "Kajabi": {"error": r"<h1>The page you were looking for doesn\'t exist.</h1>"},
    "Thinkific": {
        "error": r"You may have mistyped the address or the page may have moved."
    },
    "Tave": {"error": r"<h1>Error 404: Page Not Found</h1>"},
    "Wishpond": {"error": r"<h1>https://www.wishpond.com/404?campaign=true"},
    "Aftership": {
        "error": r"Oops.</h2><p class=\"text-muted text-tight\">The page you\'re looking for doesn\'t exist."
    },
    "Aha": {"error": r"There is no portal here \.\.\. sending you back to Aha!"},
    "Tictail": {
        "error": r"to target URL: <a href=\"https://tictail.com|Start selling on Tictail."
    },
    "Brightcove": {"error": r"<p class=\"bc-gallery-error-code\">Error Code: 404</p>"},
    "Bigcartel": {"error": r"<h1>Oops! We couldn&#8217;t find that page.</h1>"},
    "ActiveCampaign": {"error": r"alt=\"LIGHTTPD - fly light.\""},
    "Campaignmonitor": {
        "error": r"Double check the URL or <a href=\"mailto:help@createsend.com|Trying to access your account"
    },
    "Acquia": {
        "error": r"The site you are looking for could not be found.|If you are an Acquia Cloud \
customer and expect to see your site at this address|Web Site Not Found"
    },
    "Proposify": {
        "error": r"If you need immediate assistance, please contact <a href=\"mailto:support@proposify.biz"
    },
    "Simplebooklet": {
        "error": r"We can\'t find this <a href=\"https://simplebooklet.com"
    },
    "GetResponse": {
        "error": r"With GetResponse Landing Pages, lead generation has never been easier"
    },
    "Vend": {"error": r"Looks like you\'ve traveled too far into cyberspace."},
    "Jetbrains": {"error": r"is not a registered InCloud YouTrack."},
    "Smartling": {"error": r"Domain is not configured"},
    "Pingdom": {"error": r"pingdom|Sorry, couldn\'t find the status page"},
    "Tilda": {"error": r"Domain has been assigned|Please renew your subscription"},
    "Surveygizmo": {"error": r"data-html-name"},
    "Mashery": {"error": r"Unrecognized domain <strong>|Unrecognized domain"},
    "Divio": {"error": r"Application not responding"},
    "feedpress": {"error": r"The feed has not been found."},
    "Readme.io": {"error": r"Project doesnt exist... yet!"},
    "statuspage": {"error": r"You are being <a href=\'https>"},
    "zendesk": {"error": r"Help Center Closed"},
    "worksites.net": {"error": r"Hello! Sorry, but the webs>"},
    "Agile CRM": {"error": r"this page is no longer available"},
    "Anima": {
        "error": r"try refreshing in a minute|this is your website and you've just created it"
    },
    "Fly.io": {"error": r"404 Not Found"},
    "Gemfury": {"error": r"This page could not be found"},
    "HatenaBlog": {"error": r"404 Blog is not found"},
    "Kinsta": {"error": r"No Site For Domain"},
    "LaunchRock": {
        "error": r"It looks like you may have taken a wrong turn somewhere|worry...it happens to all of us"
    },
    "Ngrok": {"error": r"ngrok.io not found"},
    "SmartJobBoard": {
        "error": r"This job board website is either expired or its domain name is invalid"
    },
    "Strikingly": {"error": r"page not found"},
    "Tumblr": {
        "error": r"Whatever you were looking for doesn\'t currently exist at this address"
    },
    "Uberflip": {
        "error": r"hub domain\, The URL you\'ve accessed does not provide a hub"
    },
    "Unbounce": {"error": r"The requested URL was not found on this server"},
    "Uptimerobot": {"error": r"page not found"},
}


def plus(string: str) -> None:
    """Print success message."""
    print("{0}[ + ]{1} {2}".format(g, e, string))


def warn(string: str, exit: bool = False) -> None:
    """Print warning message and optionally exit.
    
    Args:
        string: Warning message
        exit: Whether to exit after warning
    """
    print("{0}[ ! ]{1} {2}".format(r, e, string))
    if exit:
        sys.exit(1)


def info(string: str) -> None:
    """Print info message."""
    print("{0}[ i ]{1} {2}".format(y, e, string))


def _info() -> str:
    """Return formatted info prefix."""
    return "{0}[ i ]{1} ".format(y, e)


def err(string: str) -> None:
    """Print error regex pattern."""
    print(r"  |= [REGEX]: {0}{1}{2}".format(y_, string, e))


def validate_domain(domain: str) -> bool:
    """Validate domain format.
    
    Args:
        domain: Domain to validate
        
    Returns:
        True if valid, False otherwise
    """
    if not domain or not isinstance(domain, str):
        return False
    
    # Remove protocol if present
    domain_part = domain.replace('http://', '').replace('https://', '').split('/')[0]
    
    # Basic domain validation regex
    domain_pattern = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    )
    
    return bool(domain_pattern.match(domain_part)) or domain_part == 'localhost'


def request(domain: str, proxy: Optional[str], timeout: Optional[int], 
            user_agent: str, verify_ssl: bool = False) -> Optional[Tuple[int, bytes]]:
    """Make HTTP request to domain.
    
    Args:
        domain: Target domain
        proxy: Proxy URL if any
        timeout: Request timeout in seconds
        user_agent: User agent string
        verify_ssl: Whether to verify SSL certificates
        
    Returns:
        Tuple of (status_code, content) or None on failure
    """
    url = checkurl(domain)
    proxies = {"http": proxy, "https": proxy} if proxy else None
    headers = {"User-Agent": user_agent}
    
    try:
        # Disable SSL warnings if verification is disabled
        if not verify_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        req = requests.get(
            url=url,
            headers=headers,
            verify=verify_ssl,
            allow_redirects=True,
            timeout=timeout if timeout is not None else DEFAULT_TIMEOUT,
            proxies=proxies,
        )
        return req.status_code, req.content
    except requests.exceptions.Timeout:
        if verify_ssl:
            warn(f"Timeout connecting to: {domain}")
        return None
    except requests.exceptions.ConnectionError:
        if verify_ssl:
            warn(f"Connection error for: {domain}")
        return None
    except requests.exceptions.RequestException as e:
        if verify_ssl:
            warn(f"Request failed for {domain}: {str(e)}")
        return None
    except Exception as e:
        warn(f"Unexpected error for {domain}: {str(e)}")
        return None


def find(status: int, content: bytes, ok: bool) -> Optional[Tuple[str, str]]:
    """Find matching service based on response.
    
    Args:
        status: HTTP status code
        content: Response content
        ok: Whether to process 200 status codes
        
    Returns:
        Tuple of (service_name, error_pattern) or None
    """
    min_status = HTTP_OK if ok else HTTP_CREATED
    content_str = str(content)
    
    for service in services:
        for values in services[service].items():
            if (
                re.findall(str(values[1]), content_str, re.I)
                and min_status <= int(status) <= HTTP_MAX_ERROR
                and "nginx" not in content_str
                and "openresty" not in content_str  # avoid false positives (Cargo mainly)
            ):
                return str(service), str(values[1])
    return None


def banner() -> None:
    """Print application banner."""
    print("\n   /~\\")
    print("  C oo   ---------------")
    print(" _( ^)  |T|A|K|E|O|V|E|R|")
    print("/   ~\\  ----------------")
    print("#> by M'hamed (@m4ll0k) Outaadi")
    print("#> https://github.com/m4ll0k")
    print("#> forked by https://github.com/edoardottt")
    print("-" * 40)
    print()


def help(_exit_: bool = False) -> None:
    """Print help message.
    
    Args:
        _exit_: Whether to exit after printing help
    """
    banner()
    print("Usage: %s [OPTION]\n" % sys.argv[0])
    print("Basic Options:")
    print("\t-d\tSet domain URL (e.g: www.test.com)")
    print("\t-l\tScan multiple targets in a text file")
    print("\t-o\tOutput file (supports .txt, .json, .csv, .html)")
    print("\t-v\tVerbose, print more info\n")
    print("Advanced Options:")
    print("\t-t\tSet threads (default: 1)")
    print("\t-T\tSet request timeout in seconds (default: 20)")
    print("\t-p\tUse a proxy to connect the target URL")
    print("\t-u\tSet custom user agent (e.g: takeover-bot)")
    print("\t-r\tRate limit in requests/second (default: 0 = no limit)")
    print("\t-S\tCustom services JSON file path\n")
    print("Security & Validation:")
    print("\t-s\tVerify SSL certificates (disabled by default)")
    print("\t-n\tDisable DNS resolution checking")
    print("\t-k\tProcess 200 HTTP code (may cause false positives)\n")
    print("Examples:")
    print("\tpython takeover.py -d example.com -v")
    print("\tpython takeover.py -l domains.txt -o results.html -v -s")
    print("\tpython takeover.py -d example.com -r 5 -t 10 -o output.csv\n")
    if _exit_:
        sys.exit()


def checkpath(path: str) -> str:
    """Check if path exists and is valid.
    
    Args:
        path: File path to check
        
    Returns:
        The path if valid
        
    Raises:
        SystemExit: If path is invalid
    """
    if os.path.exists(path):
        if os.path.isdir(path):
            warn('"%s" is directory!' % path, True)
        return path
    else:
        warn('"%s" not exists!' % path, True)
    return path


def readfile(path: str) -> List[str]:
    """Read domains from file.
    
    Args:
        path: Path to file containing domains
        
    Returns:
        List of domain strings
    """
    info('Read wordlist... "%s"' % path)
    validated_path = checkpath(path)
    with open(validated_path, "r") as f:
        domains = [x.strip() for x in f if x.strip()]
    
    # Validate domains
    invalid_domains = [d for d in domains if not validate_domain(d)]
    if invalid_domains:
        warn(f"Warning: {len(invalid_domains)} invalid domains found and will be skipped")
    
    return [d for d in domains if validate_domain(d)]


def checkurl(url: str) -> str:
    """Normalize and validate URL.
    
    Args:
        url: URL to check
        
    Returns:
        Normalized URL with scheme
    """
    o = urllib.parse.urlsplit(url)
    if o.scheme not in ["http", "https", ""]:
        warn('Scheme "%s" not supported!' % o.scheme, True)
    if o.netloc == "":
        return "http://" + o.path
    elif o.netloc:
        return o.scheme + "://" + o.netloc
    else:
        return "http://" + o.netloc


def print_(string: str) -> None:
    """Print string with terminal control codes for updating same line.
    
    Args:
        string: String to print
    """
    sys.stdout.write("\033[1K")
    sys.stdout.write("\033[0G")
    sys.stdout.write(string)
    sys.stdout.flush()


def runner(config: ScanConfig, output_list: List[Tuple[str, str, str]]) -> None:
    """Run the scanner with thread pool.
    
    Args:
        config: Scanner configuration
        output_list: List to store results
    """
    threadpool = thread.ThreadPoolExecutor(max_workers=config.threads)
    if config.verbose:
        info("Set %s threads.." % config.threads)
        if not config.verify_ssl:
            warn("SSL verification is disabled. Use -s flag to enable.")
        if config.check_dns and not DNS_AVAILABLE:
            warn("DNS checking disabled: dnspython not installed")
        if config.rate_limit > 0:
            info(f"Rate limiting enabled: {config.rate_limit} requests/second")
    
    # Rate limiting setup
    request_interval = 1.0 / config.rate_limit if config.rate_limit > 0 else 0
    last_request_time = [0.0]  # Use list to allow modification in closure
    
    def rate_limited_submit(domain):
        """Submit with rate limiting."""
        if request_interval > 0:
            current_time = time.time()
            time_since_last = current_time - last_request_time[0]
            if time_since_last < request_interval:
                time.sleep(request_interval - time_since_last)
            last_request_time[0] = time.time()
        
        return threadpool.submit(
            requester,
            domain,
            config.proxy,
            config.timeout,
            config.user_agent,
            config.output,
            config.process,
            config.verbose,
            config.verify_ssl,
            config.check_dns,
            output_list,
            config.d_list,
        )
    
    futures = [rate_limited_submit(domain) for domain in config.domains]
    
    for i, _ in enumerate(thread.as_completed(futures)):
        if config.verbose and config.d_list:
            str_ = "{i}{b:.2f}% Domain: {d}".format(
                i=_info(),
                b=percent(int(i), int(config.dict_len)),
                d=config.domains[i],
            )
            print_(str_)


def requester(domain: str, proxy: Optional[str], timeout: Optional[int], 
              user_agent: str, output: Optional[str], ok: bool, verbose: bool,
              verify_ssl: bool, check_dns: bool, output_list: List[Tuple[str, str, str]], 
              d_list: Optional[str]) -> None:
    """Make request and check for takeover vulnerability.
    
    Args:
        domain: Target domain
        proxy: Proxy URL
        timeout: Request timeout
        user_agent: User agent string
        output: Output file path
        ok: Process 200 status codes
        verbose: Verbose output
        verify_ssl: Verify SSL certificates
        check_dns: Check DNS resolution
        output_list: List to append results
        d_list: Domain list file path
    """
    # Validate domain before processing
    if not validate_domain(domain):
        if verbose:
            warn(f"Invalid domain format: {domain}")
        return
    
    # Check DNS resolution if enabled
    dns_result = None
    if check_dns and DNS_AVAILABLE:
        dns_result = check_dns_resolution(domain, verbose)
        if dns_result and not dns_result[0] and not dns_result[1]:
            # Domain doesn't resolve and has no CNAME
            if verbose:
                info(f"Skipping {domain} - no DNS resolution")
            return
    
    result = request(domain, proxy, timeout, user_agent, verify_ssl)
    if result is None:
        return
    
    code, html = result
    match = find(code, html, ok)
    
    if match:
        service, error = match
        
        # Additional CNAME validation if DNS checking is enabled
        if check_dns and dns_result and dns_result[0]:
            # Has CNAME, check if it matches the service
            service_info = services.get(service, {})
            service_cnames = service_info.get('cname', [])
            
            if service_cnames and not check_cname_match(dns_result[1], service_cnames):
                # CNAME doesn't match expected service, might be false positive
                if verbose:
                    warn(f"CNAME mismatch for {domain} - expected {service_cnames}, got {dns_result[1]}")
                return
        
        if output:
            output_list.append((domain, service, error))
            if verbose and not d_list:
                plus(
                    "%s service found! Potential domain takeover found! - %s"
                    % (service, domain)
                )
            elif verbose and d_list:
                print("")
                plus(
                    "%s service found! Potential domain takeover found! - %s"
                    % (service, domain)
                )
        else:
            if d_list:
                print("")
                plus(
                    "%s service found! Potential domain takeover found! - %s"
                    % (service, domain)
                )
            elif not d_list:
                plus(
                    "%s service found! Potential domain takeover found! - %s"
                    % (service, domain)
                )
            if verbose:
                err(error)


def savejson(path: str, content: List[Tuple[str, str, str]], 
             verbose: bool, d_list: Optional[str]) -> None:
    """Save results to JSON file.
    
    Args:
        path: Output file path
        content: List of (domain, service, error) tuples
        verbose: Verbose output
        d_list: Domain list file path
    """
    if verbose and not d_list:
        info("Writing file..")
    elif verbose and d_list:
        print("")
        info("Writing file..")
    
    domains_dict = {}
    for domain, service, error in content:
        domains_dict[domain] = {"service": service, "error": error}
    
    output_data = {"domains": domains_dict}
    
    with open(path, "w+") as outjsonfile:
        json.dump(output_data, outjsonfile, indent=4)
    
    info("Saved at " + path + "..")


def savetxt(path: str, content: List[Tuple[str, str, str]], 
            verbose: bool, d_list: Optional[str]) -> None:
    """Save results to text file.
    
    Args:
        path: Output file path
        content: List of (domain, service, error) tuples
        verbose: Verbose output
        d_list: Domain list file path
    """
    if verbose and not d_list:
        info("Writing file..")
    elif verbose and d_list:
        print("")
        info("Writing file..")
    
    br = "-" * 40
    bf = "=" * 40
    out = br + "\n"
    
    for domain, service, error in content:
        out += "Domain\t: %s\n" % domain
        out += "Service\t: %s\n" % service
        out += "Error\t: %s\n" % error
        out += bf + "\n"
    
    out += br + "\n"
    
    with open(path, "w+") as outtxtfile:
        outtxtfile.write(out)
    
    info("Saved at " + path + "..")


def savecsv(path: str, content: List[Tuple[str, str, str]], 
            verbose: bool, d_list: Optional[str]) -> None:
    """Save results to CSV file.
    
    Args:
        path: Output file path
        content: List of (domain, service, error) tuples
        verbose: Verbose output
        d_list: Domain list file path
    """
    if verbose and not d_list:
        info("Writing file..")
    elif verbose and d_list:
        print("")
        info("Writing file..")
    
    with open(path, "w+", newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['Domain', 'Service', 'Error Pattern'])
        for domain, service, error in content:
            writer.writerow([domain, service, error])
    
    info("Saved at " + path + "..")


def savehtml(path: str, content: List[Tuple[str, str, str]], 
             verbose: bool, d_list: Optional[str]) -> None:
    """Save results to HTML file.
    
    Args:
        path: Output file path
        content: List of (domain, service, error) tuples
        verbose: Verbose output
        d_list: Domain list file path
    """
    if verbose and not d_list:
        info("Writing file..")
    elif verbose and d_list:
        print("")
        info("Writing file..")
    
    html_template = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Takeover Scan Results</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 20px;
            background-color: #f5f5f5;
        }}
        h1 {{
            color: #333;
            border-bottom: 3px solid #4CAF50;
            padding-bottom: 10px;
        }}
        .summary {{
            background-color: #fff;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            background-color: #fff;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        th {{
            background-color: #4CAF50;
            color: white;
            font-weight: bold;
        }}
        tr:hover {{
            background-color: #f5f5f5;
        }}
        .vulnerable {{
            color: #d32f2f;
            font-weight: bold;
        }}
        .service {{
            color: #1976d2;
            font-weight: bold;
        }}
        .timestamp {{
            color: #666;
            font-size: 0.9em;
        }}
    </style>
</head>
<body>
    <h1>🔍 Subdomain Takeover Scan Results</h1>
    <div class="summary">
        <p><strong>Total Vulnerabilities Found:</strong> {count}</p>
        <p class="timestamp"><strong>Scan Date:</strong> {timestamp}</p>
    </div>
    <table>
        <thead>
            <tr>
                <th>#</th>
                <th>Domain</th>
                <th>Service</th>
                <th>Error Pattern</th>
            </tr>
        </thead>
        <tbody>
{rows}
        </tbody>
    </table>
</body>
</html>"""
    
    rows = ""
    for i, (domain, service, error) in enumerate(content, 1):
        rows += f"""            <tr>
                <td>{i}</td>
                <td class="vulnerable">{domain}</td>
                <td class="service">{service}</td>
                <td><code>{error[:100]}...</code></td>
            </tr>
"""
    
    from datetime import datetime
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    html_content = html_template.format(
        count=len(content),
        timestamp=timestamp,
        rows=rows
    )
    
    with open(path, "w+", encoding='utf-8') as htmlfile:
        htmlfile.write(html_content)
    
    info("Saved at " + path + "..")


def main() -> None:
    """Main entry point for the application."""
    global services
    
    if len(sys.argv) < 2:
        help(True)
    
    # Initialize configuration
    config = ScanConfig()
    
    try:
        opts, _ = getopt.getopt(
            sys.argv[1:],
            "d:l:p:o:t:T::u:r:S:kvsnD",
            ["d=", "l=", "p=", "v", "o=", "t=", "T=", "u=", "r=", "S=", "k", "s", "n", "D"],
        )
    except Exception as e:
        warn(str(e), True)
    
    for o, a in opts:
        if o == "-d":
            config.domain = a
        elif o == "-t":
            config.threads = int(a)
        elif o == "-l":
            config.d_list = a
        elif o == "-p":
            config.proxy = a
        elif o == "-o":
            config.output = a
        elif o == "-T":
            config.timeout = int(a)
        elif o == "-k":
            config.process = True
        elif o == "-u":
            config.user_agent = a
        elif o == "-v":
            config.verbose = True
        elif o == "-s":
            config.verify_ssl = True
        elif o == "-r":
            config.rate_limit = float(a)
        elif o == "-S":
            config.services_file = a
        elif o == "-n":
            config.check_dns = False
        elif o == "-D":
            # Debug: show DNS info only
            if config.verbose:
                info(f"DNS library available: {DNS_AVAILABLE}")

    if config.domain or config.d_list:
        banner()
        
        # Load services from JSON or defaults
        services = load_services(config.services_file)
        if config.verbose:
            info(f"Loaded {len(services)} service signatures")
        
        domains: List[str] = []
        
        if config.verbose:
            info("Starting..")

        if config.d_list:
            domains.extend(readfile(config.d_list))
        else:
            if config.domain:
                if not validate_domain(config.domain):
                    warn(f"Invalid domain format: {config.domain}", True)
                domains.append(config.domain)
        
        config.domains = domains
        config.dict_len = len(domains)
        
        # Create output list
        output_list: List[Tuple[str, str, str]] = []
        
        runner(config, output_list)
        
        if config.output:
            if ".txt" in config.output:
                savetxt(config.output, output_list, config.verbose, config.d_list)
            elif ".json" in config.output:
                savejson(config.output, output_list, config.verbose, config.d_list)
            elif ".csv" in config.output:
                savecsv(config.output, output_list, config.verbose, config.d_list)
            elif ".html" in config.output or ".htm" in config.output:
                savehtml(config.output, output_list, config.verbose, config.d_list)
            else:
                extension = config.output.split(".")[-1] if "." in config.output else "unknown"
                warn(
                    "Output Error: %s extension not supported, only .txt, .json, .csv, or .html" % extension,
                    True,
                )
    else:
        help(True)


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt) as e:
        print(e)
        sys.exit(0)
