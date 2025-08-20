from urllib.parse import urlparse, urlunparse, parse_qs, urlencode
import re
import tempfile
import datetime
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager
from typing import Any, Dict

# Temporarily disable selenium-wire due to compatibility issues
SELENIUM_WIRE_AVAILABLE = False
print("[crawler] selenium-wire temporarily disabled; using plain selenium (network capture limited).")
from selenium import webdriver as _plain_webdriver  # type: ignore

# Unified alias so later annotations/logic can refer to webdriver safely
try:
    if SELENIUM_WIRE_AVAILABLE:
        webdriver = _wire_webdriver  # type: ignore
    else:
        webdriver = _plain_webdriver  # type: ignore
except NameError:
    pass

class CrawlerConfig:
    """
    A class to hold all configuration settings for the crawler.
    """
    def __init__(self, include_subdomains=False, respect_robots_txt=True):
        # 1-1. Origin and Scope Control
        self.include_subdomains = include_subdomains

        # 1-2. Path-Based Exclusions (Blacklists)
        self.path_blacklist = [
            "/admin", "/administrator", "/wp-admin", "/manager",
            "/login?logout", "/logout"
        ]
        self.destructive_paths = [
            "/delete", "/destroy", "/purchase", "/checkout", "/payment"
        ]
        self.extension_blacklist = [
            ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".svg", ".mp4", ".avi",
            ".mov", ".wmv", ".zip", ".tar", ".gz", ".7z", ".dmg", ".exe", ".msi", ".pdf"
        ]

        # 1-3. Content-Type Filter
        self.allowed_content_types = [
            "text/html", "application/json", "text/javascript",
            "application/javascript", "application/xhtml+xml", "application/xml"
        ]

        # 2-1. Rate Limiting and Concurrency
        self.qps_per_origin = 1.0
        self.concurrency = 1
        self.retry_policy = {
            "max_retries": 2, "backoff_factor": 0.5, "backoff_max": 8.0
        }

        # 2-2. Bot, CAPTCHA, and Blocking Signals
        self.respect_robots_txt = respect_robots_txt
        self.blocking_policy = 'slow_down' # or 'stop'
        
        # 3-2. Network
        self.ignore_tls_errors = False # Should be False for security analysis
       
        # 6-2. Masking Rules
        self.masking_regex = re.compile(
            r'(?i)\b(api[-_]?key|secret|token|bearer|password|session|authorization)\b'
        )
        self.masking_replacement = "[REDACTED]"
        print("CrawlerConfig initialized with detailed settings.")
        
        self.params_to_remove = [
            "utm_source","utm_medium","utm_campaign","utm_term","utm_content",
            "gclid","fbclid","msclkid","PHPSESSID","JSESSIONID","ASPSESSIONID"
        ]


# --- Utility Functions ---

# 3-1. Cache/Storage Strategy
def setup_driver_session(config: CrawlerConfig):
    """
    Sets up a new Selenium-Wire WebDriver instance with an isolated profile.
    """
    # Ensure a uniquely named profile dir (Chrome in containers sometimes misdetect reuse)
    user_data_dir = tempfile.mkdtemp(prefix="shield4u_chrome_")
    print(f"Created temporary user data directory for session: {user_data_dir}")

    chrome_options = Options()
    chrome_options.add_argument("--headless=new")
    chrome_options.add_argument("--disable-gpu")
    chrome_options.add_argument("--window-size=1920,1080")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")  # mitigate /dev/shm size limits
    chrome_options.add_argument("--disable-setuid-sandbox")
    chrome_options.add_argument("--disable-extensions")
    chrome_options.add_argument("--disable-background-networking")
    chrome_options.add_argument("--disable-sync")
    chrome_options.add_argument("--disable-default-apps")
    chrome_options.add_argument("--disable-notifications")
    chrome_options.add_argument("--user-agent=Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36")
    chrome_options.add_argument(f"--user-data-dir={user_data_dir}")
    
    service = Service(ChromeDriverManager().install())
    if SELENIUM_WIRE_AVAILABLE:
        seleniumwire_options = {
            'ignore_http_methods': ['OPTIONS', 'HEAD'],
            'disable_capture': False,
        }
        driver = _wire_webdriver.Chrome(service=service, options=chrome_options, seleniumwire_options=seleniumwire_options)
    else:
        driver = _plain_webdriver.Chrome(service=service, options=chrome_options)
    
    return driver, user_data_dir

# 6-1. Data Collection Items (Browser/Network Level)
def collect_browser_data(driver: Any, initial_url: str, config: CrawlerConfig) -> Dict[str, Any]:
    """
    Collects data that can only be gathered from the browser/network level,
    not from static HTML parsing.
    """
    data = {
        "meta": {},
        "security_headers": {},
        "storage_keys": {"local_storage": [], "session_storage": []},
        "network_summary": []
    }

    # --- Meta Data ---
    data["meta"]["url"] = initial_url
    data["meta"]["final_url"] = driver.current_url
    data["meta"]["title"] = driver.title
    data["meta"]["timestamp"] = datetime.datetime.utcnow().isoformat()

    # Find the main document request to get status and headers (only if selenium-wire is available)
    if SELENIUM_WIRE_AVAILABLE and hasattr(driver, 'requests'):
        try:
            main_request = next((r for r in reversed(driver.requests) if r.url == data["meta"]["final_url"] and r.response), None)
            if main_request:
                data["meta"]["status"] = main_request.response.status_code
                
                # --- Security Headers ---
                headers_to_check = ['content-security-policy', 'x-frame-options', 'x-content-type-options', 
                                    'strict-transport-security', 'referrer-policy', 'access-control-allow-origin', 'set-cookie']
                for header in headers_to_check:
                    if header in main_request.response.headers:
                        data["security_headers"][header] = main_request.response.headers[header]
        except Exception as e:
            print(f"Could not retrieve network data from selenium-wire: {e}")
            data["meta"]["status"] = 200  # Default assumption
    else:
        data["meta"]["status"] = 200  # Default assumption when selenium-wire is not available

    # --- Storage Keys ---
    try:
        data["storage_keys"]["local_storage"] = driver.execute_script("return Object.keys(window.localStorage);")
        data["storage_keys"]["session_storage"] = driver.execute_script("return Object.keys(window.sessionStorage);")
    except Exception as e:
        print(f"Could not retrieve storage keys: {e}")

    # --- Network Summary (HAR-lite) ---
    if SELENIUM_WIRE_AVAILABLE and hasattr(driver, 'requests'):
        try:
            for request in driver.requests:
                if request.response:
                    net_entry = {
                        "url": request.url,
                        "method": request.method,
                        "status": request.response.status_code,
                        "mime_type": request.response.headers.get('Content-Type', 'N/A'),
                        "cors": 'access-control-allow-origin' in request.response.headers
                    }
                    if request.response.body:
                        body_sample = request.response.body[:1024].decode('utf-8', 'ignore')
                        if "password" in body_sample or "token" in body_sample:
                            body_sample = config.masking_replacement
                        net_entry["body_sample"] = body_sample
                    data["network_summary"].append(net_entry)
        except Exception as e:  # noqa: BLE001
            print(f"[crawler] network capture partial failure: {e}")
    else:
        data["network_summary_note"] = "selenium-wire not available; network capture skipped"

    return data


def is_within_scope(base_url: str, target_url: str, config: CrawlerConfig) -> bool:
    """Checks if a target URL is within the scope defined by the base URL and config."""
    if not target_url: return False
    base_parts = urlparse(base_url)
    target_parts = urlparse(target_url)
    if config.include_subdomains:
        if not (target_parts.hostname == base_parts.hostname or (target_parts.hostname and target_parts.hostname.endswith(f".{base_parts.hostname}"))):
            return False
    else:
        if target_parts.scheme != base_parts.scheme or target_parts.hostname != base_parts.hostname or target_parts.port != base_parts.port:
            return False
    path = target_parts.path or "/"
    if any(blacklisted in path for blacklisted in config.path_blacklist) or \
       any(path.lower().endswith(ext) for ext in config.extension_blacklist):
        return False
    return True

def normalize_url(url: str, config: CrawlerConfig, trailing_slash=False) -> str:
    """Cleans and standardizes a URL according to the configuration rules."""
    # This function is simplified for this example. A full implementation would use config.params_to_remove
    parts = urlparse(url)
    scheme = parts.scheme.lower()
    hostname = parts.hostname.lower() if parts.hostname else None
    netloc = hostname
    if parts.port and not ((scheme == 'http' and parts.port == 80) or (scheme == 'https' and parts.port == 443)):
        netloc = f"{hostname}:{parts.port}"
        
    raw_qs = parse_qs(parts.query, keep_blank_values=True)
    filtered = {k: v for k, v in raw_qs.items() if k not in config.params_to_remove}
    sorted_qs = sorted(filtered.items())
    
    path = parts.path or "/"
    if trailing_slash and not path.endswith('/'): path += '/'
    elif not trailing_slash and path != '/' and path.endswith('/'): path = path.rstrip('/')
    new_parts = parts._replace(
        scheme=scheme, netloc=netloc, path=path,
        query=urlencode(sorted_qs, doseq=True), fragment=""
    )
    return urlunparse(new_parts)

def mask_sensitive_value(key: str, value: str, config: CrawlerConfig) -> str:
    """Masks a value if its corresponding key matches the sensitive pattern."""
    if config.masking_regex.search(key):
        return config.masking_replacement
    return value