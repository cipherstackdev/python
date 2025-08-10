#!/usr/bin/env python3
"""

Link Verifier Script
Checks if URLs are accessible and returns their status codes.
# Check specific URLs
python link_verifier.py -u https://example.com https://google.com

# Check URLs in files
python link_verifier.py -f document.md README.txt

# Mixed approach - files and direct URLs
python link_verifier.py document.html -u https://example.com

# Verbose output (shows working URLs too)
python link_verifier.py -f myfile.md --verbose

# Adjust timeout and concurrency
python link_verifier.py -f links.txt --timeout 5 --workers 20

"""

import requests
import re
import argparse
import sys
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import time

class LinkVerifier:
    def __init__(self, timeout=10, max_workers=10):
        self.timeout = timeout
        self.max_workers = max_workers
        self.session = requests.Session()
        # Set a user agent to avoid being blocked by some sites
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
    
    def extract_urls_from_text(self, text):
        """Extract URLs from text using regex."""
        url_pattern = re.compile(
            r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        )
        return url_pattern.findall(text)
    
    def extract_urls_from_file(self, filepath):
        """Extract URLs from a file."""
        try:
            with open(filepath, 'r', encoding='utf-8') as file:
                content = file.read()
                return self.extract_urls_from_text(content)
        except Exception as e:
            print(f"Error reading file {filepath}: {e}")
            return []
    
    def check_single_url(self, url):
        """Check a single URL and return its status."""
        try:
            # Validate URL format
            parsed = urlparse(url)
            if not parsed.scheme or not parsed.netloc:
                return {
                    'url': url,
                    'status_code': None,
                    'status': 'Invalid URL format',
                    'response_time': None,
                    'error': 'Invalid URL format'
                }
            
            start_time = time.time()
            response = self.session.head(url, timeout=self.timeout, allow_redirects=True)
            response_time = round(time.time() - start_time, 2)
            
            return {
                'url': url,
                'status_code': response.status_code,
                'status': 'OK' if response.status_code < 400 else 'Error',
                'response_time': response_time,
                'error': None
            }
            
        except requests.exceptions.Timeout:
            return {
                'url': url,
                'status_code': None,
                'status': 'Timeout',
                'response_time': None,
                'error': f'Timeout after {self.timeout}s'
            }
        except requests.exceptions.ConnectionError:
            return {
                'url': url,
                'status_code': None,
                'status': 'Connection Error',
                'response_time': None,
                'error': 'Cannot connect to server'
            }
        except requests.exceptions.RequestException as e:
            return {
                'url': url,
                'status_code': None,
                'status': 'Request Error',
                'response_time': None,
                'error': str(e)
            }
        except Exception as e:
            return {
                'url': url,
                'status_code': None,
                'status': 'Unknown Error',
                'response_time': None,
                'error': str(e)
            }
    
    def check_urls(self, urls, show_progress=True):
        """Check multiple URLs concurrently."""
        results = []
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all tasks
            future_to_url = {executor.submit(self.check_single_url, url): url for url in urls}
            
            # Process completed tasks
            completed = 0
            for future in as_completed(future_to_url):
                result = future.result()
                results.append(result)
                completed += 1
                
                if show_progress:
                    print(f"Progress: {completed}/{len(urls)} URLs checked", end='\r')
        
        if show_progress:
            print()  # New line after progress
        
        return results
    
    def print_results(self, results, verbose=False):
        """Print results in a formatted way."""
        print(f"\n{'='*80}")
        print(f"LINK VERIFICATION RESULTS")
        print(f"{'='*80}")
        
        ok_count = sum(1 for r in results if r['status'] == 'OK')
        error_count = len(results) - ok_count
        
        print(f"Total URLs checked: {len(results)}")
        print(f"✅ Working: {ok_count}")
        print(f"❌ Broken: {error_count}")
        print(f"{'='*80}")
        
        # Group results by status
        working_urls = [r for r in results if r['status'] == 'OK']
        broken_urls = [r for r in results if r['status'] != 'OK']
        
        if verbose and working_urls:
            print(f"\n✅ WORKING URLS ({len(working_urls)}):")
            print("-" * 40)
            for result in working_urls:
                print(f"[{result['status_code']}] {result['url']} ({result['response_time']}s)")
        
        if broken_urls:
            print(f"\n❌ BROKEN URLS ({len(broken_urls)}):")
            print("-" * 40)
            for result in broken_urls:
                status_info = f"[{result['status_code']}]" if result['status_code'] else f"[{result['status']}]"
                print(f"{status_info} {result['url']}")
                if verbose and result['error']:
                    print(f"    Error: {result['error']}")
        
        return error_count == 0

def main():
    parser = argparse.ArgumentParser(description='Verify links from files or command line')
    parser.add_argument('inputs', nargs='*', help='URLs or file paths to check')
    parser.add_argument('-f', '--file', action='append', help='File(s) to extract URLs from')
    parser.add_argument('-u', '--url', action='append', help='Individual URL(s) to check')
    parser.add_argument('-t', '--timeout', type=int, default=10, help='Request timeout in seconds (default: 10)')
    parser.add_argument('-w', '--workers', type=int, default=10, help='Number of concurrent workers (default: 10)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Show detailed output including working URLs')
    parser.add_argument('--no-progress', action='store_true', help='Disable progress indicator')
    
    args = parser.parse_args()
    
    # Collect all URLs to check
    all_urls = set()
    
    # URLs from command line arguments
    if args.url:
        all_urls.update(args.url)
    
    # Files specified with -f flag
    verifier = LinkVerifier(timeout=args.timeout, max_workers=args.workers)
    
    if args.file:
        for filepath in args.file:
            urls = verifier.extract_urls_from_file(filepath)
            all_urls.update(urls)
            print(f"Found {len(urls)} URLs in {filepath}")
    
    # Process positional arguments (could be URLs or files)
    for item in args.inputs:
        if item.startswith(('http://', 'https://')):
            all_urls.add(item)
        else:
            # Assume it's a file
            urls = verifier.extract_urls_from_file(item)
            all_urls.update(urls)
            print(f"Found {len(urls)} URLs in {item}")
    
    # If no URLs provided, show usage
    if not all_urls:
        print("No URLs provided. Usage examples:")
        print("  python link_verifier.py -u https://example.com https://google.com")
        print("  python link_verifier.py -f document.md README.txt")
        print("  python link_verifier.py document.html -u https://example.com")
        return 1
    
    all_urls = list(all_urls)
    print(f"\nChecking {len(all_urls)} unique URLs...")
    
    # Check all URLs
    results = verifier.check_urls(all_urls, show_progress=not args.no_progress)
    
    # Print results
    all_working = verifier.print_results(results, verbose=args.verbose)
    
    # Return appropriate exit code
    return 0 if all_working else 1

if __name__ == "__main__":
    sys.exit(main())