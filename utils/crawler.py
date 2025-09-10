import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import time
from typing import List, Set

class WebCrawler:
    def __init__(self, max_depth=2, max_urls=50, delay=1):
        """
        Initialize the web crawler
        
        Args:
            max_depth: Maximum crawl depth
            max_urls: Maximum number of URLs to crawl
            delay: Delay between requests in seconds
        """
        self.max_depth = max_depth
        self.max_urls = max_urls
        self.delay = delay
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
    
    def crawl_site(self, start_url: str, max_depth: int = None) -> List[str]:
        """
        Crawl a website to find all unique URLs within the same domain
        
        Args:
            start_url: Starting URL for the crawl
            max_depth: Override default max depth
            
        Returns:
            List of unique URLs found
        """
        if max_depth is None:
            max_depth = self.max_depth
            
        visited_urls: Set[str] = set()
        urls_to_visit: List[tuple] = [(start_url, 0)]  # (url, depth)
        found_urls: List[str] = []
        
        # Get the domain of the starting URL
        try:
            domain = urlparse(start_url).netloc.lower()
        except Exception:
            print(f"[!] Invalid starting URL: {start_url}")
            return [start_url]
        
        print(f"[*] Starting crawl on domain: {domain}")
        print(f"[*] Max depth: {max_depth}, Max URLs: {self.max_urls}")
        
        while urls_to_visit and len(found_urls) < self.max_urls:
            current_url, depth = urls_to_visit.pop(0)
            
            # Skip if already visited or depth exceeded
            if current_url in visited_urls or depth > max_depth:
                continue
                
            visited_urls.add(current_url)
            found_urls.append(current_url)
            
            print(f"[+] Crawling (depth {depth}): {current_url}")
            
            try:
                # Make request with timeout
                response = self.session.get(current_url, timeout=10, verify=False)
                response.raise_for_status()
                
                # Only process HTML content
                content_type = response.headers.get('content-type', '').lower()
                if 'text/html' not in content_type:
                    continue
                
                # Parse HTML and extract links
                soup = BeautifulSoup(response.content, 'html.parser')
                links = self._extract_links(soup, current_url, domain)
                
                # Add new links to crawl queue
                for link in links:
                    if link not in visited_urls and len(found_urls) < self.max_urls:
                        urls_to_visit.append((link, depth + 1))
                
                # Rate limiting
                if self.delay > 0:
                    time.sleep(self.delay)
                    
            except requests.RequestException as e:
                print(f"[!] Error crawling {current_url}: {str(e)}")
                continue
            except Exception as e:
                print(f"[!] Unexpected error crawling {current_url}: {str(e)}")
                continue
        
        print(f"[*] Crawl completed. Found {len(found_urls)} unique URLs")
        return found_urls
    
    def _extract_links(self, soup: BeautifulSoup, base_url: str, target_domain: str) -> List[str]:
        """
        Extract valid links from HTML soup
        
        Args:
            soup: BeautifulSoup object
            base_url: Base URL for resolving relative links
            target_domain: Target domain to stay within
            
        Returns:
            List of valid URLs within the target domain
        """
        links = []
        
        # Find all anchor tags with href
        for link_tag in soup.find_all('a', href=True):
            href = link_tag['href'].strip()
            
            # Skip empty hrefs, javascript, mailto, tel links
            if not href or href.startswith(('#', 'javascript:', 'mailto:', 'tel:')):
                continue
            
            try:
                # Convert relative URLs to absolute
                absolute_url = urljoin(base_url, href)
                parsed_url = urlparse(absolute_url)
                
                # Only include HTTP/HTTPS URLs from the same domain
                if (parsed_url.scheme in ['http', 'https'] and 
                    parsed_url.netloc.lower() == target_domain):
                    
                    # Clean the URL (remove fragment)
                    clean_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
                    if parsed_url.query:
                        clean_url += f"?{parsed_url.query}"
                    
                    if clean_url not in links:
                        links.append(clean_url)
                        
            except Exception:
                # Skip malformed URLs
                continue
        
        return links
    
    def crawl_with_params(self, start_url: str) -> List[str]:
        """
        Crawl site specifically looking for URLs with parameters
        
        Args:
            start_url: Starting URL
            
        Returns:
            List of URLs that contain query parameters
        """
        all_urls = self.crawl_site(start_url)
        param_urls = []
        
        for url in all_urls:
            parsed = urlparse(url)
            if parsed.query:  # Has query parameters
                param_urls.append(url)
        
        print(f"[*] Found {len(param_urls)} URLs with parameters")
        return param_urls if param_urls else [start_url]

# Simple function wrapper for backwards compatibility
def crawl_site(start_url: str, max_depth: int = 2) -> List[str]:
    """
    Simple wrapper function for crawling
    
    Args:
        start_url: URL to start crawling from
        max_depth: Maximum depth to crawl
        
    Returns:
        List of found URLs
    """
    crawler = WebCrawler(max_depth=max_depth)
    return crawler.crawl_site(start_url)
