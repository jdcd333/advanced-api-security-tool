#!/usr/bin/env python3

"""
Description: An advanced Python tool for detecting Insecure Direct Object Reference (IDOR) vulnerabilities in REST and GraphQL APIs through comprehensive testing and analysis.
Author: jdcd333
Version: 1.0
"""

import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
import argparse
import json
import time
from urllib.parse import urlparse, parse_qs, urljoin
import random
import re
import os
from bs4 import BeautifulSoup

# Expanded global configuration
CONFIG = {
    'user_agents': [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36',
        'PostmanRuntime/7.28.4',  # API User-Agent
        'curl/7.77.0'
    ],
    'rate_limit_delay': 0.3,
    'timeout': 20,
    'max_redirects': 3,
    'test_values': [0, 1, 2, 100, 12345, -1, 999999, "NaN", "null", "true", "false"],
    'common_params': ['id', 'user_id', 'account', 'document', 'file', 'order', 'uid', 'uuid', 'number', 'reference'],
    'api_paths': ['/api/', '/graphql', '/rest/', '/v1/', '/v2/', '/json/', '/soap/'],
    'sensitive_keywords': ['password', 'secret', 'token', 'key', 'auth', 'credit', 'ssn', 'private', 'email', 'address'],
    'output_dir': 'idor_api_scan_results',
    'jwt_regex': r'^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]*$',
    'graphql_keywords': ['query', 'mutation', '{', '}', '__typename'],
    'http_methods': ['GET', 'POST', 'PUT', 'PATCH', 'DELETE']
}

class APIDORScanner:
    def __init__(self):
        self.session = requests.Session()
        self.session.max_redirects = CONFIG['max_redirects']
        self.rate_limit_tracker = {}
        self.results = []
        self.api_endpoints_found = []
        self.create_output_dir()
        self.auth_tokens = {}
        self.debug = False

    def create_output_dir(self):
        if not os.path.exists(CONFIG['output_dir']):
            os.makedirs(CONFIG['output_dir'])

    def random_user_agent(self, api=False):
        if api:
            return random.choice([ua for ua in CONFIG['user_agents'] if 'api' in ua.lower() or 'curl' in ua.lower()])
        return random.choice(CONFIG['user_agents'])

    def rate_limit(self, domain):
        now = time.time()
        if domain in self.rate_limit_tracker:
            elapsed = now - self.rate_limit_tracker[domain]
            if elapsed < CONFIG['rate_limit_delay']:
                time.sleep(CONFIG['rate_limit_delay'] - elapsed)
        self.rate_limit_tracker[domain] = now

    def get_headers(self, api=False, content_type='application/json'):
        headers = {
            'User-Agent': self.random_user_agent(api=api),
            'Accept': 'application/json' if api else 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
        }
        if api:
            headers['Content-Type'] = content_type
            if 'Authorization' in self.auth_tokens:
                headers['Authorization'] = self.auth_tokens['Authorization']
        return headers

    def is_api_endpoint(self, url, response=None):
        """Determine if a URL is an API endpoint"""
        parsed = urlparse(url)
        
        # By path
        if any(api_path in parsed.path for api_path in CONFIG['api_paths']):
            return True
            
        # By content-type
        if response and 'application/json' in response.headers.get('Content-Type', '').lower():
            return True
            
        # By extension
        if parsed.path.endswith(('.json', '.xml')):
            return True
            
        return False

    def is_graphql_endpoint(self, url, response=None):
        """Identify GraphQL endpoints"""
        parsed = urlparse(url)
        
        # By common path
        if '/graphql' in parsed.path.lower():
            return True
            
        # By response
        if response:
            try:
                content = response.text.lower()
                return any(keyword in content for keyword in CONFIG['graphql_keywords'])
            except:
                pass
                
        return False

    def generate_idor_test_cases(self, original_value=None):
        """Generate IDOR test cases based on original value"""
        test_cases = set(CONFIG['test_values'])
        
        if original_value:
            try:
                original_num = int(original_value)
                test_cases.update([
                    original_num + 1,
                    original_num - 1,
                    original_num * 2,
                    original_num // 2,
                    0,
                    -original_num,
                    original_num + 100,
                    original_num - 100
                ])
            except ValueError:
                pass
                
        return list(test_cases)

    def test_rest_api_idor(self, url, method='GET', params=None, json_data=None):
        """Test for IDOR in REST API endpoints"""
        domain = urlparse(url).netloc
        self.rate_limit(domain)
        
        vulnerabilities = []
        tested_params = set()
        
        # Test URL parameters
        if params:
            for param, value in params.items():
                if param in tested_params:
                    continue
                    
                test_cases = self.generate_idor_test_cases(value)
                for test_value in test_cases:
                    try:
                        test_params = params.copy()
                        test_params[param] = test_value
                        
                        if method.upper() == 'GET':
                            response = self.session.get(
                                url,
                                params=test_params,
                                headers=self.get_headers(api=True),
                                timeout=CONFIG['timeout']
                            )
                        else:
                            response = self.session.request(
                                method.upper(),
                                url,
                                json=test_params,
                                headers=self.get_headers(api=True),
                                timeout=CONFIG['timeout']
                            )
                            
                        vuln = self.analyze_api_response(response, url, param, test_value, method)
                        if vuln:
                            vulnerabilities.append(vuln)
                            
                    except Exception as e:
                        if self.debug:
                            print(f"[-] Error testing {url} ({method}): {str(e)}")
        
        # Test JSON body parameters
        if json_data and isinstance(json_data, dict):
            for key, value in json_data.items():
                if key.lower() in tested_params or not str(value).strip():
                    continue
                    
                test_cases = self.generate_idor_test_cases(str(value))
                for test_value in test_cases:
                    try:
                        test_data = json_data.copy()
                        test_data[key] = test_value
                        
                        response = self.session.request(
                            method.upper(),
                            url,
                            json=test_data,
                            headers=self.get_headers(api=True),
                            timeout=CONFIG['timeout']
                        )
                        
                        vuln = self.analyze_api_response(response, url, key, test_value, method)
                        if vuln:
                            vulnerabilities.append(vuln)
                            
                    except Exception as e:
                        if self.debug:
                            print(f"[-] Error testing {url} ({method}): {str(e)}")
        
        return vulnerabilities

    def analyze_api_response(self, response, url, param, test_value, method):
        """Analyze API responses for IDOR detection"""
        if response.status_code in (200, 201, 403, 401):
            try:
                response_data = response.json()
                
                # Sensitive data detection
                sensitive_data = self.find_sensitive_data(response_data)
                
                # Verify if response is different than expected
                is_different = True  # Implement more sophisticated logic
                
                if is_different or sensitive_data:
                    return {
                        'type': 'API_IDOR',
                        'url': url,
                        'method': method,
                        'parameter': param,
                        'test_value': test_value,
                        'status_code': response.status_code,
                        'response_length': len(response.text),
                        'sensitive_data_found': sensitive_data,
                        'timestamp': time.strftime("%Y-%m-%d %H:%M:%S")
                    }
                    
            except ValueError:
                # Not JSON, but could be another response type
                pass
                
        return None

    def find_sensitive_data(self, data):
        """Find sensitive data in API responses"""
        sensitive_items = []
        
        if isinstance(data, dict):
            for key, value in data.items():
                key_lower = str(key).lower()
                if any(sensitive in key_lower for sensitive in CONFIG['sensitive_keywords']):
                    sensitive_items.append({key: value})
                elif isinstance(value, (dict, list)):
                    nested = self.find_sensitive_data(value)
                    if nested:
                        sensitive_items.extend(nested)
                        
        elif isinstance(data, list):
            for item in data:
                nested = self.find_sensitive_data(item)
                if nested:
                    sensitive_items.extend(nested)
                    
        return sensitive_items if sensitive_items else None

    def test_graphql_idor(self, endpoint, query=None):
        """Test for IDOR in GraphQL endpoints"""
        if not query:
            # Default query for IDOR detection
            query = """
            query {
                user(id: "%s") {
                    id
                    username
                    email
                }
            }
            """
            
        test_cases = self.generate_idor_test_cases()
        vulnerabilities = []
        
        for test_value in test_cases:
            try:
                formatted_query = query % test_value
                payload = {'query': formatted_query}
                
                response = self.session.post(
                    endpoint,
                    json=payload,
                    headers=self.get_headers(api=True),
                    timeout=CONFIG['timeout']
                )
                
                if response.status_code == 200:
                    try:
                        response_data = response.json()
                        if 'errors' not in response_data and 'data' in response_data:
                            if response_data['data'] and response_data['data'].get('user'):
                                vuln = {
                                    'type': 'GRAPHQL_IDOR',
                                    'endpoint': endpoint,
                                    'test_value': test_value,
                                    'user_data': response_data['data']['user'],
                                    'timestamp': time.strftime("%Y-%m-%d %H:%M:%S")
                                }
                                vulnerabilities.append(vuln)
                    except ValueError:
                        pass
                        
            except Exception as e:
                if self.debug:
                    print(f"[-] Error testing GraphQL {endpoint}: {str(e)}")
        
        return vulnerabilities

    def discover_api_endpoints(self, base_url):
        """Discover API endpoints from a base URL"""
        endpoints = []
        
        # Common API paths
        common_paths = [
            'api', 'api/v1', 'api/v2', 'graphql', 'rest', 'json',
            'users', 'account', 'admin', 'data', 'export'
        ]
        
        for path in common_paths:
            test_url = urljoin(base_url, path)
            try:
                response = self.session.get(
                    test_url,
                    headers=self.get_headers(api=True),
                    timeout=CONFIG['timeout'],
                    allow_redirects=False
                )
                
                if response.status_code in (200, 201, 401, 403):
                    if self.is_api_endpoint(test_url, response):
                        endpoints.append({
                            'url': test_url,
                            'method': 'GET',
                            'status': response.status_code,
                            'type': 'discovered'
                        })
                        
            except Exception as e:
                if self.debug:
                    print(f"[-] Error discovering {test_url}: {str(e)}")
        
        return endpoints

    def scan_api_endpoint(self, url, method='GET', params=None, json_data=None):
        """Scan a complete API endpoint"""
        vulnerabilities = []
        
        # 1. Test IDOR directly on the endpoint
        vulns = self.test_rest_api_idor(url, method, params, json_data)
        vulnerabilities.extend(vulns)
        
        # 2. If GraphQL, test specifically
        if self.is_graphql_endpoint(url):
            vulns = self.test_graphql_idor(url)
            vulnerabilities.extend(vulns)
        
        # 3. Test other HTTP methods
        if method.upper() == 'GET':
            for other_method in ['POST', 'PUT', 'PATCH', 'DELETE']:
                vulns = self.test_rest_api_idor(url, other_method, params, json_data)
                vulnerabilities.extend(vulns)
        
        return vulnerabilities

    def save_results(self, filename):
        """Save results in JSON format"""
        filepath = os.path.join(CONFIG['output_dir'], filename)
        with open(filepath, 'w') as f:
            json.dump({
                'metadata': {
                    'date': time.strftime("%Y-%m-%d %H:%M:%S"),
                    'config': CONFIG
                },
                'results': self.results,
                'api_endpoints': self.api_endpoints_found
            }, f, indent=2)
        print(f"[+] Results saved to {filepath}")

    def run(self, targets_file, output_file, threads=10, auth_token=None):
        """Run complete scan"""
        if auth_token:
            self.auth_tokens['Authorization'] = auth_token
            
        with open(targets_file, 'r') as f:
            targets = [line.strip() for line in f if line.strip()]
        
        print(f"[*] Starting API IDOR scan on {len(targets)} targets")
        
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = []
            
            for target in targets:
                if target.startswith(('http://', 'https://')):
                    url = target
                else:
                    url = f"https://{target}"
                
                futures.append(executor.submit(self.process_target, url))
            
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        self.results.extend(result)
                except Exception as e:
                    print(f"[-] Error processing target: {str(e)}")
        
        self.save_results(output_file)
        print(f"[+] Scan completed. Found {len(self.results)} potential IDOR vulnerabilities")

    def process_target(self, url):
        """Process an individual target"""
        target_results = []
        
        try:
            # 1. Discover API endpoints
            discovered_apis = self.discover_api_endpoints(url)
            self.api_endpoints_found.extend(discovered_apis)
            
            # 2. Scan each found endpoint
            for endpoint in discovered_apis:
                vulns = self.scan_api_endpoint(
                    endpoint['url'],
                    endpoint.get('method', 'GET'),
                    endpoint.get('params'),
                    endpoint.get('json')
                )
                target_results.extend(vulns)
                
        except Exception as e:
            if self.debug:
                print(f"[-] Error processing {url}: {str(e)}")
        
        return target_results

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Advanced API IDOR Scanner')
    parser.add_argument('-f', '--file', required=True, help='File containing targets (URLs or domains)')
    parser.add_argument('-o', '--output', default='api_idor_results.json', help='Output file for results')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of concurrent threads')
    parser.add_argument('-a', '--auth', help='Authorization token (e.g., "Bearer token123")')
    parser.add_argument('--debug', action='store_true', help='Enable debug output')
    args = parser.parse_args()
    
    scanner = APIDORScanner()
    scanner.debug = args.debug
    scanner.run(args.file, args.output, args.threads, args.auth)
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
import argparse
import json
import time
from urllib.parse import urlparse, parse_qs, urljoin
import random
import re
import os
from bs4 import BeautifulSoup

# Expanded global configuration
CONFIG = {
    'user_agents': [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36',
        'PostmanRuntime/7.28.4',  # API User-Agent
        'curl/7.77.0'
    ],
    'rate_limit_delay': 0.3,
    'timeout': 20,
    'max_redirects': 3,
    'test_values': [0, 1, 2, 100, 12345, -1, 999999, "NaN", "null", "true", "false"],
    'common_params': ['id', 'user_id', 'account', 'document', 'file', 'order', 'uid', 'uuid', 'number', 'reference'],
    'api_paths': ['/api/', '/graphql', '/rest/', '/v1/', '/v2/', '/json/', '/soap/'],
    'sensitive_keywords': ['password', 'secret', 'token', 'key', 'auth', 'credit', 'ssn', 'private', 'email', 'address'],
    'output_dir': 'idor_api_scan_results',
    'jwt_regex': r'^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]*$',
    'graphql_keywords': ['query', 'mutation', '{', '}', '__typename'],
    'http_methods': ['GET', 'POST', 'PUT', 'PATCH', 'DELETE']
}

class APIDORScanner:
    def __init__(self):
        self.session = requests.Session()
        self.session.max_redirects = CONFIG['max_redirects']
        self.rate_limit_tracker = {}
        self.results = []
        self.api_endpoints_found = []
        self.create_output_dir()
        self.auth_tokens = {}
        self.debug = False

    def create_output_dir(self):
        if not os.path.exists(CONFIG['output_dir']):
            os.makedirs(CONFIG['output_dir'])

    def random_user_agent(self, api=False):
        if api:
            return random.choice([ua for ua in CONFIG['user_agents'] if 'api' in ua.lower() or 'curl' in ua.lower()])
        return random.choice(CONFIG['user_agents'])

    def rate_limit(self, domain):
        now = time.time()
        if domain in self.rate_limit_tracker:
            elapsed = now - self.rate_limit_tracker[domain]
            if elapsed < CONFIG['rate_limit_delay']:
                time.sleep(CONFIG['rate_limit_delay'] - elapsed)
        self.rate_limit_tracker[domain] = now

    def get_headers(self, api=False, content_type='application/json'):
        headers = {
            'User-Agent': self.random_user_agent(api=api),
            'Accept': 'application/json' if api else 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
        }
        if api:
            headers['Content-Type'] = content_type
            if 'Authorization' in self.auth_tokens:
                headers['Authorization'] = self.auth_tokens['Authorization']
        return headers

    def is_api_endpoint(self, url, response=None):
        """Determine if a URL is an API endpoint"""
        parsed = urlparse(url)
        
        # By path
        if any(api_path in parsed.path for api_path in CONFIG['api_paths']):
            return True
            
        # By content-type
        if response and 'application/json' in response.headers.get('Content-Type', '').lower():
            return True
            
        # By extension
        if parsed.path.endswith(('.json', '.xml')):
            return True
            
        return False

    def is_graphql_endpoint(self, url, response=None):
        """Identify GraphQL endpoints"""
        parsed = urlparse(url)
        
        # By common path
        if '/graphql' in parsed.path.lower():
            return True
            
        # By response
        if response:
            try:
                content = response.text.lower()
                return any(keyword in content for keyword in CONFIG['graphql_keywords'])
            except:
                pass
                
        return False

    def generate_idor_test_cases(self, original_value=None):
        """Generate IDOR test cases based on original value"""
        test_cases = set(CONFIG['test_values'])
        
        if original_value:
            try:
                original_num = int(original_value)
                test_cases.update([
                    original_num + 1,
                    original_num - 1,
                    original_num * 2,
                    original_num // 2,
                    0,
                    -original_num,
                    original_num + 100,
                    original_num - 100
                ])
            except ValueError:
                pass
                
        return list(test_cases)

    def test_rest_api_idor(self, url, method='GET', params=None, json_data=None):
        """Test for IDOR in REST API endpoints"""
        domain = urlparse(url).netloc
        self.rate_limit(domain)
        
        vulnerabilities = []
        tested_params = set()
        
        # Test URL parameters
        if params:
            for param, value in params.items():
                if param in tested_params:
                    continue
                    
                test_cases = self.generate_idor_test_cases(value)
                for test_value in test_cases:
                    try:
                        test_params = params.copy()
                        test_params[param] = test_value
                        
                        if method.upper() == 'GET':
                            response = self.session.get(
                                url,
                                params=test_params,
                                headers=self.get_headers(api=True),
                                timeout=CONFIG['timeout']
                            )
                        else:
                            response = self.session.request(
                                method.upper(),
                                url,
                                json=test_params,
                                headers=self.get_headers(api=True),
                                timeout=CONFIG['timeout']
                            )
                            
                        vuln = self.analyze_api_response(response, url, param, test_value, method)
                        if vuln:
                            vulnerabilities.append(vuln)
                            
                    except Exception as e:
                        if self.debug:
                            print(f"[-] Error testing {url} ({method}): {str(e)}")
        
        # Test JSON body parameters
        if json_data and isinstance(json_data, dict):
            for key, value in json_data.items():
                if key.lower() in tested_params or not str(value).strip():
                    continue
                    
                test_cases = self.generate_idor_test_cases(str(value))
                for test_value in test_cases:
                    try:
                        test_data = json_data.copy()
                        test_data[key] = test_value
                        
                        response = self.session.request(
                            method.upper(),
                            url,
                            json=test_data,
                            headers=self.get_headers(api=True),
                            timeout=CONFIG['timeout']
                        )
                        
                        vuln = self.analyze_api_response(response, url, key, test_value, method)
                        if vuln:
                            vulnerabilities.append(vuln)
                            
                    except Exception as e:
                        if self.debug:
                            print(f"[-] Error testing {url} ({method}): {str(e)}")
        
        return vulnerabilities

    def analyze_api_response(self, response, url, param, test_value, method):
        """Analyze API responses for IDOR detection"""
        if response.status_code in (200, 201, 403, 401):
            try:
                response_data = response.json()
                
                # Sensitive data detection
                sensitive_data = self.find_sensitive_data(response_data)
                
                # Verify if response is different than expected
                is_different = True  # Implement more sophisticated logic
                
                if is_different or sensitive_data:
                    return {
                        'type': 'API_IDOR',
                        'url': url,
                        'method': method,
                        'parameter': param,
                        'test_value': test_value,
                        'status_code': response.status_code,
                        'response_length': len(response.text),
                        'sensitive_data_found': sensitive_data,
                        'timestamp': time.strftime("%Y-%m-%d %H:%M:%S")
                    }
                    
            except ValueError:
                # Not JSON, but could be another response type
                pass
                
        return None

    def find_sensitive_data(self, data):
        """Find sensitive data in API responses"""
        sensitive_items = []
        
        if isinstance(data, dict):
            for key, value in data.items():
                key_lower = str(key).lower()
                if any(sensitive in key_lower for sensitive in CONFIG['sensitive_keywords']):
                    sensitive_items.append({key: value})
                elif isinstance(value, (dict, list)):
                    nested = self.find_sensitive_data(value)
                    if nested:
                        sensitive_items.extend(nested)
                        
        elif isinstance(data, list):
            for item in data:
                nested = self.find_sensitive_data(item)
                if nested:
                    sensitive_items.extend(nested)
                    
        return sensitive_items if sensitive_items else None

    def test_graphql_idor(self, endpoint, query=None):
        """Test for IDOR in GraphQL endpoints"""
        if not query:
            # Default query for IDOR detection
            query = """
            query {
                user(id: "%s") {
                    id
                    username
                    email
                }
            }
            """
            
        test_cases = self.generate_idor_test_cases()
        vulnerabilities = []
        
        for test_value in test_cases:
            try:
                formatted_query = query % test_value
                payload = {'query': formatted_query}
                
                response = self.session.post(
                    endpoint,
                    json=payload,
                    headers=self.get_headers(api=True),
                    timeout=CONFIG['timeout']
                )
                
                if response.status_code == 200:
                    try:
                        response_data = response.json()
                        if 'errors' not in response_data and 'data' in response_data:
                            if response_data['data'] and response_data['data'].get('user'):
                                vuln = {
                                    'type': 'GRAPHQL_IDOR',
                                    'endpoint': endpoint,
                                    'test_value': test_value,
                                    'user_data': response_data['data']['user'],
                                    'timestamp': time.strftime("%Y-%m-%d %H:%M:%S")
                                }
                                vulnerabilities.append(vuln)
                    except ValueError:
                        pass
                        
            except Exception as e:
                if self.debug:
                    print(f"[-] Error testing GraphQL {endpoint}: {str(e)}")
        
        return vulnerabilities

    def discover_api_endpoints(self, base_url):
        """Discover API endpoints from a base URL"""
        endpoints = []
        
        # Common API paths
        common_paths = [
            'api', 'api/v1', 'api/v2', 'graphql', 'rest', 'json',
            'users', 'account', 'admin', 'data', 'export'
        ]
        
        for path in common_paths:
            test_url = urljoin(base_url, path)
            try:
                response = self.session.get(
                    test_url,
                    headers=self.get_headers(api=True),
                    timeout=CONFIG['timeout'],
                    allow_redirects=False
                )
                
                if response.status_code in (200, 201, 401, 403):
                    if self.is_api_endpoint(test_url, response):
                        endpoints.append({
                            'url': test_url,
                            'method': 'GET',
                            'status': response.status_code,
                            'type': 'discovered'
                        })
                        
            except Exception as e:
                if self.debug:
                    print(f"[-] Error discovering {test_url}: {str(e)}")
        
        return endpoints

    def scan_api_endpoint(self, url, method='GET', params=None, json_data=None):
        """Scan a complete API endpoint"""
        vulnerabilities = []
        
        # 1. Test IDOR directly on the endpoint
        vulns = self.test_rest_api_idor(url, method, params, json_data)
        vulnerabilities.extend(vulns)
        
        # 2. If GraphQL, test specifically
        if self.is_graphql_endpoint(url):
            vulns = self.test_graphql_idor(url)
            vulnerabilities.extend(vulns)
        
        # 3. Test other HTTP methods
        if method.upper() == 'GET':
            for other_method in ['POST', 'PUT', 'PATCH', 'DELETE']:
                vulns = self.test_rest_api_idor(url, other_method, params, json_data)
                vulnerabilities.extend(vulns)
        
        return vulnerabilities

    def save_results(self, filename):
        """Save results in JSON format"""
        filepath = os.path.join(CONFIG['output_dir'], filename)
        with open(filepath, 'w') as f:
            json.dump({
                'metadata': {
                    'date': time.strftime("%Y-%m-%d %H:%M:%S"),
                    'config': CONFIG
                },
                'results': self.results,
                'api_endpoints': self.api_endpoints_found
            }, f, indent=2)
        print(f"[+] Results saved to {filepath}")

    def run(self, targets_file, output_file, threads=10, auth_token=None):
        """Run complete scan"""
        if auth_token:
            self.auth_tokens['Authorization'] = auth_token
            
        with open(targets_file, 'r') as f:
            targets = [line.strip() for line in f if line.strip()]
        
        print(f"[*] Starting API IDOR scan on {len(targets)} targets")
        
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = []
            
            for target in targets:
                if target.startswith(('http://', 'https://')):
                    url = target
                else:
                    url = f"https://{target}"
                
                futures.append(executor.submit(self.process_target, url))
            
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        self.results.extend(result)
                except Exception as e:
                    print(f"[-] Error processing target: {str(e)}")
        
        self.save_results(output_file)
        print(f"[+] Scan completed. Found {len(self.results)} potential IDOR vulnerabilities")

    def process_target(self, url):
        """Process an individual target"""
        target_results = []
        
        try:
            # 1. Discover API endpoints
            discovered_apis = self.discover_api_endpoints(url)
            self.api_endpoints_found.extend(discovered_apis)
            
            # 2. Scan each found endpoint
            for endpoint in discovered_apis:
                vulns = self.scan_api_endpoint(
                    endpoint['url'],
                    endpoint.get('method', 'GET'),
                    endpoint.get('params'),
                    endpoint.get('json')
                )
                target_results.extend(vulns)
                
        except Exception as e:
            if self.debug:
                print(f"[-] Error processing {url}: {str(e)}")
        
        return target_results

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Advanced API IDOR Scanner')
    parser.add_argument('-f', '--file', required=True, help='File containing targets (URLs or domains)')
    parser.add_argument('-o', '--output', default='api_idor_results.json', help='Output file for results')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of concurrent threads')
    parser.add_argument('-a', '--auth', help='Authorization token (e.g., "Bearer token123")')
    parser.add_argument('--debug', action='store_true', help='Enable debug output')
    args = parser.parse_args()
    
    scanner = APIDORScanner()
    scanner.debug = args.debug
    scanner.run(args.file, args.output, args.threads, args.auth)
