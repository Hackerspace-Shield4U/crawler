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
    def __init__(self, base_url: str, page_source: str, collect_links: bool = True):
        self.base_url = base_url
        self.soup = BeautifulSoup(page_source, 'html.parser')
        self.collect_links = collect_links

    def parse_all(self) -> dict:
        """Executes all parsing methods and consolidates the results."""
        return {
            "dom": self._parse_dom(),
            "fingerprints": self._parse_fingerprints(),
            "panel_login_signals": self._parse_panel_login_signals(),
            "osint_exposure": self._parse_osint_exposure(),
        }

    def _parse_dom(self) -> dict:
        """Extracts DOM-related information in LLM-compatible format."""
        # 1. Title
        title = self.soup.title.string.strip() if self.soup.title else ""

        # 2. Meta tags - extract generator specifically and convert to dict format
        meta_dict = {}
        for tag in self.soup.find_all("meta"):
            name = tag.get("name") or tag.get("property")
            content = tag.get("content")
            if name and content:
                if name.lower() == "generator":
                    meta_dict["generator"] = content
                else:
                    meta_dict[name] = content

        # 3. Scripts & Links (CSS)  
        scripts = [urljoin(self.base_url, s.get('src')) for s in self.soup.find_all('script') if s.get('src')]
        links = [urljoin(self.base_url, l.get('href')) for l in self.soup.find_all('link') if l.get('href')]

        # 4. Visible Links - only collect if we need them for further crawling
        if self.collect_links:
            visible_links = [urljoin(self.base_url, a.get('href')) for a in self.soup.find_all('a') if a.get('href')]
        else:
            visible_links = []  # Don't collect links if max_depth is 0
        
        # 5. Forms - format to match LLM spec
        forms = []
        for form in self.soup.find_all('form'):
            form_data = {
                "action": urljoin(self.base_url, form.get('action', '')),
                "method": form.get('method', 'GET').upper(),
                "enctype": form.get('enctype', 'application/x-www-form-urlencoded'),
                "inputs": [i.get('name') for i in form.find_all('input') if i.get('name')]
            }
            forms.append(form_data)
            
        # 6. Comments and Text Leaks - format as structured objects
        comments = self.soup.find_all(string=lambda text: isinstance(text, Comment))
        text_content = self.soup.get_text()
        
        comments_or_text_leaks = []
        # Add HTML comments
        for comment in comments:
            comment_text = comment.strip()
            if comment_text:
                comments_or_text_leaks.append({
                    "type": "html_comment", 
                    "snippet": comment_text[:200]
                })
        
        # Look for various types of leaks
        api_keys = re.findall(r'(?i)API[_\s]*KEY[\s=:]+([a-zA-Z0-9\-_]{20,})', text_content)
        for key in api_keys:
            comments_or_text_leaks.append({
                "type": "api_key",
                "snippet": f"API_KEY={key[:10]}..."
            })
            
        debug_flags = re.findall(r'(?i)DEBUG\s*=\s*(true|1|yes)', text_content)
        for flag in debug_flags:
            comments_or_text_leaks.append({
                "type": "debug",
                "snippet": f"DEBUG={flag}"
            })
            
        stack_traces = re.findall(r'(?i)(PHP Warning:|Exception:|Error:|Traceback)', text_content)
        for trace in stack_traces:
            comments_or_text_leaks.append({
                "type": "stack",
                "snippet": trace
            })

        return {
            "title": title,
            "meta": meta_dict,
            "scripts": scripts,
            "links": links,
            "comments_or_text_leaks": comments_or_text_leaks,
            "forms": forms,
            "visible_links": list(set(visible_links)),
            "visible_text_sample": ' '.join(text_content.split())[:500] + ("..." if len(text_content) > 500 else "")
        }

    def _parse_fingerprints(self) -> dict:
        """Extracts web technology and CMS information in LLM-compatible format."""
        fingerprints = {"cms": [], "plugins": [], "tech": []}
        page_content = str(self.soup)

        # CMS Detection
        generator_meta = self.soup.find('meta', {'name': 'generator'})
        if generator_meta:
            generator_content = generator_meta.get('content', '')
            if "wordpress" in generator_content.lower():
                # Extract version if present
                version_match = re.search(r'(\d+\.\d+(?:\.\d+)?)', generator_content)
                if version_match:
                    fingerprints["cms"].append(f"wordpress {version_match.group(1)}")
                else:
                    fingerprints["cms"].append("wordpress")
            else:
                fingerprints["cms"].append(generator_content.lower())
        
        # Additional WordPress detection
        if "/wp-content/" in page_content or "/wp-includes/" in page_content:
            if not any("wordpress" in cms for cms in fingerprints["cms"]):
                fingerprints["cms"].append("wordpress")
            
        # Plugin Detection - get script and link URLs directly
        scripts = [urljoin(self.base_url, s.get('src')) for s in self.soup.find_all('script') if s.get('src')]
        links = [urljoin(self.base_url, l.get('href')) for l in self.soup.find_all('link') if l.get('href')]
        
        version_pattern = re.compile(r'[\?&](ver|v)=(\d+\.[\d\.]+)')
        plugin_urls = scripts + links
        
        for url in plugin_urls:
            # WordPress plugins
            wp_plugin_match = re.search(r'/wp-content/plugins/([^/]+)/', url)
            if wp_plugin_match:
                plugin_name = wp_plugin_match.group(1)
                version_match = version_pattern.search(url)
                if version_match:
                    fingerprints["plugins"].append({
                        "name": plugin_name, 
                        "version": version_match.group(2)
                    })
                else:
                    fingerprints["plugins"].append({
                        "name": plugin_name, 
                        "version": "unknown"
                    })
        
        # Technology Detection
        if "jquery.js" in page_content or "jQuery" in page_content:
            fingerprints["tech"].append("jquery")
            
        # Check for PHP indicators
        php_indicators = [".php", "PHPSESSID"]
        if any(indicator in page_content for indicator in php_indicators):
            fingerprints["tech"].append("php")
            
        # Apache detection
        server_headers = self.soup.find_all('meta', {'name': 'server'})
        for header in server_headers:
            content = header.get('content', '').lower()
            if 'apache' in content:
                fingerprints["tech"].append("apache?")
                break

        return fingerprints

    def _parse_panel_login_signals(self) -> dict:
        """Finds clues related to login/admin pages in LLM-compatible format."""
        login_patterns = ['/admin', '/login', '/signin', '/manager', '/wp-login.php', '/administrator', '/dashboard']
        keyword_patterns = re.compile(r'(?i)(login|admin|sign[\s\-]*in|dashboard|control[\s\-]*panel|management)')

        # Get visible links directly
        visible_links = [urljoin(self.base_url, a.get('href')) for a in self.soup.find_all('a') if a.get('href')]
        
        # Detect URL patterns in visible links
        candidates = []
        for link in visible_links:
            for pattern in login_patterns:
                if pattern.lower() in link.lower():
                    candidates.append(link)
        
        # Check if current page looks admin-like based on title and headers
        title = self.soup.title.string.strip() if self.soup.title else ""
        header_text = " ".join(h.get_text() for h in self.soup.find_all(['h1', 'h2', 'h3']))
        text_to_search = title + " " + header_text
        
        is_admin_like = bool(keyword_patterns.search(text_to_search))
        
        # Add current page forms that might be login forms
        for form in self.soup.find_all('form'):
            inputs = [i.get('name') for i in form.find_all('input') if i.get('name')]
            # Check for typical login form inputs
            has_password = any('password' in inp.lower() for inp in inputs)
            has_user_field = any(field in inp.lower() for inp in inputs for field in ['user', 'email', 'login'])
            
            if has_password and has_user_field:
                action = urljoin(self.base_url, form.get('action', ''))
                if action and action not in candidates:
                    candidates.append(action)

        return {
            "is_admin_like": is_admin_like,
            "candidates": list(set(candidates))
        }

    def _parse_osint_exposure(self) -> dict:
        """Detects exposure of personal info, cloud resources, etc. (OSINT) in LLM-compatible format."""
        text_content = self.soup.get_text()
        # Get visible links directly
        links = [urljoin(self.base_url, a.get('href')) for a in self.soup.find_all('a') if a.get('href')]

        # Email extraction with validation
        email_pattern = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
        emails = list(set(email_pattern.findall(text_content)))

        # Phone numbers
        phone_pattern = re.compile(r'(\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}')
        phones = list(set(phone_pattern.findall(text_content)))

        # Social media links
        social_patterns = {
            'twitter.com': 'twitter',
            'facebook.com': 'facebook', 
            'linkedin.com': 'linkedin',
            'instagram.com': 'instagram',
            'github.com': 'github',
            'youtube.com': 'youtube'
        }
        socials = []
        for link in links:
            for pattern, platform in social_patterns.items():
                if pattern in link.lower():
                    socials.append(link)
                    break

        # Cloud storage links
        cloud_patterns = ['s3.amazonaws.com', 'storage.googleapis.com', 'blob.core.windows.net', 
                         'dropbox.com', 'drive.google.com', 'onedrive.live.com']
        cloud_links = []
        for link in links:
            if any(pattern in link.lower() for pattern in cloud_patterns):
                cloud_links.append(link)

        # Open directory detection
        open_directory_ui = []
        # Check for Apache directory listing
        if self.soup.find('title', string=re.compile(r'Index of')):
            open_directory_ui.append(self.base_url)
        # Check for common directory listing patterns
        if self.soup.find('a', string=re.compile(r'Parent Directory')):
            open_directory_ui.append(self.base_url)
        # Look for URLs that end with / and might be directories
        for link in links:
            if link.endswith('/') and any(indicator in link.lower() for indicator in ['/public/', '/files/', '/uploads/', '/documents/']):
                open_directory_ui.append(link)

        return {
            "emails": emails,
            "phones": phones,
            "socials": socials,
            "open_directory_ui": list(set(open_directory_ui)),
            "cloud_links": cloud_links
        }


# --- Main Crawler Function ---
def crawl_and_parse(api_input: dict) -> dict:
    """
    Takes an API input, performs crawling and parsing, and returns the result.
    """
    parent_guid = api_input["parent_guid"]
    target_url = api_input["target_url"]
    cookies = api_input.get("cookies", {})
    max_depth = api_input.get("max_depth", 0)  # Legacy, keep for backwards compatibility
    remaining_depth = api_input.get("remaining_depth", max_depth)  # Use remaining_depth as primary
    current_depth = api_input.get("current_depth", 0)

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
        print(f"[DEBUG] Page source length: {len(page_source)}")
        print(f"[DEBUG] Max depth: {max_depth}, Remaining depth: {remaining_depth}, Current depth: {current_depth}")
        
        # Only collect links for further crawling if we have remaining depth > 0
        collect_links_for_crawling = remaining_depth > 0
        
        parser = PageParser(base_url=driver.current_url, page_source=page_source, collect_links=collect_links_for_crawling)
        parsed_data = parser.parse_all()
        print(f"[DEBUG] Parsed data keys: {list(parsed_data.keys())}")
        print(f"[DEBUG] DOM data keys: {list(parsed_data.get('dom', {}).keys()) if parsed_data.get('dom') else []}")
        print(f"[DEBUG] Links collected: {len(parsed_data.get('dom', {}).get('visible_links', []))}")
        print(f"[DEBUG] Links will be processed with remaining_depth: {remaining_depth - 1}")

        # 5. Consolidate results in LLM-compatible format
        result = {
            "url": driver.current_url,  # Use final URL after redirects
            "dom": parsed_data.get("dom", {}),
            "fingerprints": parsed_data.get("fingerprints", {}),
            "panel_login_signals": parsed_data.get("panel_login_signals", {}),
            "osint_exposure": parsed_data.get("osint_exposure", {}),
            # Keep internal metadata for controller processing
            "_internal": {
                "request_info": {
                    "parent_guid": parent_guid,
                    "target_url": target_url,
                    "final_url": driver.current_url,
                    "max_depth": max_depth,
                    "remaining_depth": remaining_depth,
                    "current_depth": current_depth
                },
                "browser_data": browser_data
            }
        }
        print(f"[DEBUG] Final result structure: {json.dumps(result, indent=2, default=str)}")

    except Exception as e:
        print(f"An error occurred during crawling {target_url}: {e}")
        result = {
            "error": str(e), 
            "target_url": target_url,
            "_internal": {
                "request_info": {
                    "parent_guid": parent_guid,
                    "target_url": target_url,
                    "max_depth": max_depth,
                    "remaining_depth": remaining_depth,
                    "current_depth": current_depth
                }
            }
        }
    finally:
        # 6. Clean up driver and temporary directory
        driver.quit()
        # Uncomment the line below for actual use to remove the temp folder.
        # shutil.rmtree(user_data_dir) 
        print(f"Cleaned up session for {target_url}")

    return result