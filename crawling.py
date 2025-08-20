import re
import json
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup, Comment

# Assuming you import the necessary classes and functions from 'crawler_config.py'
from crawler_config import CrawlerConfig, setup_driver_session, collect_browser_data


_PATH_KV_PAT = re.compile(r'([a-zA-Z0-9_\-]+)=([^/]+)')

def _parse_url_structured(base_url: str, raw_url: str) -> dict:
    """Makes the original URL absolute and structures it by component."""
    abs_url = urljoin(base_url, raw_url)
    p = urlparse(abs_url)
    query_dict = {k: v for k, v in parse_qs(p.query, keep_blank_values=True).items()}
    # Also extracts key=value segments from the path (e.g., /k=..., /m=a,b,c)
    path_params = {}
    for seg in (p.path or "/").split('/'):
        m = _PATH_KV_PAT.fullmatch(seg)
        if m:
            val = m.group(2)
            path_params[m.group(1)] = val.split(',') if ',' in val else val
    data = {
        "full": abs_url,
        "scheme": p.scheme,
        "host": p.hostname,
        "path": p.path or "/",
        "query": query_dict,          # Empty dict if no query
        "fragment": p.fragment or ""
    }
    if path_params:
        data["path_params"] = path_params
    return data

def _as_structured_list(base_url: str, urls: list[str]) -> list[dict]:
    """Converts a list of URL strings into a list of structured dictionaries (with duplicates removed)."""
    dedup = list(dict.fromkeys(urls))  # Deduplicate while preserving order
    return [_parse_url_structured(base_url, u) for u in dedup]


class PageParser:
    """
    A class that uses BeautifulSoup to parse HTML page source and extract data
    according to a defined structure.
    """
    def __init__(self, base_url: str, page_source: str):
        self.base_url = base_url
        self.soup = BeautifulSoup(page_source, 'html.parser')

    def parse_all(self) -> dict:
        """Executes all parsing methods and consolidates the results."""
        return {
            "dom": self._parse_dom(),
            "fingerprints": self._parse_fingerprints(),
            "panel_login_signals": self._parse_panel_login_signals(),
            "osint_exposure": self._parse_osint_exposure(),
        }

    def _parse_dom(self) -> dict:
        """Extracts DOM-related information."""
        # 1. Title
        title = self.soup.title.string.strip() if self.soup.title else ""

        # 2. Meta tags
        meta_tags = []
        for tag in self.soup.find_all("meta"):
            meta_tags.append({
                "name": tag.get("name"),
                "property": tag.get("property"),
                "content": tag.get("content"),
            })

        # 3. Scripts & Links (CSS)
        def parse_url(u):
            parsed = urlparse(urljoin(self.base_url, u))
            return {
                "full": parsed.geturl(),
                "path": parsed.path,
                "query": parse_qs(parsed.query)
            }
        scripts = [urljoin(self.base_url, s.get('src')) for s in self.soup.find_all('script') if s.get('src')]
        links = [urljoin(self.base_url, l.get('href')) for l in self.soup.find_all('link') if l.get('href')]

        # 4. Visible Links
        visible_links = [urljoin(self.base_url, a.get('href')) for a in self.soup.find_all('a') if a.get('href')]
        
        # 5. Forms
        forms = []
        for form in self.soup.find_all('form'):
            forms.append({
                "action": urljoin(self.base_url, form.get('action', '')),
                "method": form.get('method', 'GET').upper(),
                "inputs": [i.get('name') for i in form.find_all('input') if i.get('name')]
            })
            
        # 6. Comments and Text Leaks
        comments = self.soup.find_all(string=lambda text: isinstance(text, Comment))
        text_content = self.soup.get_text()
        text_leaks = re.findall(r'(?i)(API_KEY[\s=:]+[\w-]+|DEBUG\s*=\s*True|Exception:|Warning:)', text_content)

        return {
            "title": title,
            "meta": meta_tags,
            "scripts": scripts,
            "links": links,
            "visible_links": list(set(visible_links)),
            "forms": forms,
            "comments_or_text_leaks": list(set(comments + text_leaks)),
            "visible_text_sample": ' '.join(text_content.split())[:500] + "..."
        }

    def _parse_fingerprints(self) -> dict:
        """Extracts web technology and CMS information."""
        fingerprints = {"cms": [], "plugins": [], "tech": []}
        page_content = str(self.soup)

        # CMS (WordPress, etc.)
        if self.soup.find('meta', {'name': 'generator'}):
            fingerprints["cms"].append(self.soup.find('meta', {'name': 'generator'}).get('content'))
        if "/wp-content/" in page_content or "/wp-includes/" in page_content:
            fingerprints["cms"].append("WordPress")
            
        # Plugins (e.g., WordPress version strings)
        version_pattern = re.compile(r'[\?&](ver|v)=(\d+\.[\d\.]+)')
        for url in self._parse_dom()['scripts'] + self._parse_dom()['links']:
            match = version_pattern.search(url)
            if match:
                fingerprints["plugins"].append(f"{url.split('?')[0].split('/')[-1]}? (v{match.group(2)})")
        
        # Tech
        if "jquery.js" in page_content or "jQuery" in page_content:
            fingerprints["tech"].append("jQuery")
        if any(".php?id=" in a for a in self._parse_dom()['visible_links']):
            fingerprints["tech"].append("PHP?")

        return fingerprints

    def _parse_panel_login_signals(self) -> dict:
        """Finds clues related to login/admin pages."""
        signals = {"candidate_urls": [], "keywords_found": []}
        login_patterns = ['/admin', '/login', '/signin', '/manager', '/wp-login.php']
        keyword_patterns = re.compile(r'(?i)(Login|Admin|Sign In|Dashboard)')

        # Detect URL patterns
        for link in self._parse_dom()['visible_links']:
            for pattern in login_patterns:
                if pattern in link:
                    signals["candidate_urls"].append(link)
        
        # Detect text keywords
        text_to_search = self._parse_dom()['title'] + " " + " ".join(h.get_text() for h in self.soup.find_all(['h1', 'h2', 'h3']))
        found_keywords = keyword_patterns.findall(text_to_search)
        if found_keywords:
            signals["keywords_found"].extend(found_keywords)

        signals["candidate_urls"] = list(set(signals["candidate_urls"]))
        return signals

    def _parse_osint_exposure(self) -> dict:
        """Detects exposure of personal info, cloud resources, etc. (OSINT)."""
        exposures = {"emails": [], "cloud_links": [], "social_links": [], "open_directory": []}
        text_content = self.soup.get_text()
        links = self._parse_dom()['visible_links']

        # Emails
        exposures["emails"] = list(set(re.findall(r'[\w\.-]+@[\w\.-]+', text_content)))

        # Cloud and Social Media links
        cloud_patterns = ['s3.amazonaws.com', 'storage.googleapis.com', 'blob.core.windows.net']
        social_patterns = ['twitter.com/', 'facebook.com/', 'linkedin.com/', 'instagram.com/']
        for link in links:
            if any(p in link for p in cloud_patterns):
                exposures["cloud_links"].append(link)
            if any(p in link for p in social_patterns):
                exposures["social_links"].append(link)

        # Open Directory
        if self.soup.find('a', string=re.compile(r'Index of /')):
             exposures["open_directory"].append(self.base_url)

        return exposures


# --- Main Crawler Function ---
def crawl_and_parse(api_input: dict) -> dict:
    """
    Takes an API input, performs crawling and parsing, and returns the result.
    """
    target_url = api_input["target_url"]
    cookies = api_input.get("cookies", {})
    max_depth = api_input.get("max_depth", 0)

    # 1. Initialize crawler config and driver (using previous code)
    config = CrawlerConfig()
    driver, user_data_dir = setup_driver_session(config)
    
    result = {}
    
    try:
        # 2. Set cookies
        # The driver must first visit the domain to have context for the cookies.
        driver.get(target_url) 
        for name, value in cookies.items():
            driver.add_cookie({"name": name, "value": value})
        
        # Reload the page after applying cookies
        driver.get(target_url)
        
        # 3. Collect browser/network level data (using previous code)
        browser_data = collect_browser_data(driver, target_url, config)

        # 4. Pass the page source to the parser for analysis
        page_source = driver.page_source
        parser = PageParser(base_url=driver.current_url, page_source=page_source)
        parsed_data = parser.parse_all()

        # 5. Consolidate results
        result = {
            "request_info": {"target_url": target_url, "max_depth": max_depth},
            "browser_data": browser_data,
            "parsed_data": parsed_data,
        }

    except Exception as e:
        print(f"An error occurred during crawling {target_url}: {e}")
        result = {"error": str(e), "target_url": target_url}
    finally:
        # 6. Clean up driver and temporary directory
        driver.quit()
        # Uncomment the line below for actual use to remove the temp folder.
        # shutil.rmtree(user_data_dir) 
        print(f"Cleaned up session for {target_url}")

    return result