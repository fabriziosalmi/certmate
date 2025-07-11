#!/usr/bin/env python3
"""
Comprehensive API Endpoint Test Script for CertMate
Tests all API endpoints and provides a quick terminal pass/fail report.
Run this before committing to ensure all endpoints are working.
"""

import requests
import json
import sys
import time
from datetime import datetime
from typing import Dict, List, Tuple
import argparse

# ANSI color codes for terminal output
class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    RESET = '\033[0m'

class EndpointTester:
    def __init__(self, base_url: str = "http://127.0.0.1:8000", api_token: str = None):
        self.base_url = base_url.rstrip('/')
        self.api_token = api_token
        self.results = []
        self.session = requests.Session()
        
        # Set default headers
        if self.api_token:
            self.session.headers.update({
                'Authorization': f'Bearer {self.api_token}',
                'Content-Type': 'application/json'
            })
    
    def test_endpoint(self, method: str, path: str, description: str, 
                     data: dict = None, expected_codes: List[int] = None, 
                     requires_auth: bool = True) -> Tuple[bool, str, int]:
        """Test a single endpoint and return (success, message, status_code)"""
        
        if expected_codes is None:
            expected_codes = [200, 201]
        
        url = f"{self.base_url}{path}"
        
        try:
            # Prepare headers
            headers = {}
            if requires_auth and self.api_token:
                headers['Authorization'] = f'Bearer {self.api_token}'
            if data:
                headers['Content-Type'] = 'application/json'
            
            # Make request
            if method.upper() == 'GET':
                response = self.session.get(url, headers=headers, timeout=10)
            elif method.upper() == 'POST':
                response = self.session.post(url, json=data, headers=headers, timeout=10)
            elif method.upper() == 'PUT':
                response = self.session.put(url, json=data, headers=headers, timeout=10)
            elif method.upper() == 'DELETE':
                response = self.session.delete(url, headers=headers, timeout=10)
            else:
                return False, f"Unsupported method: {method}", 0
            
            # Check if status code is expected
            if response.status_code in expected_codes:
                return True, f"✓ {response.status_code}", response.status_code
            elif response.status_code == 401 and requires_auth:
                return False, f"✗ 401 Unauthorized (check API token)", response.status_code
            elif response.status_code == 404:
                return False, f"✗ 404 Not Found", response.status_code
            elif response.status_code == 405:
                return False, f"✗ 405 Method Not Allowed", response.status_code
            else:
                # Try to get error message from response
                try:
                    error_data = response.json()
                    error_msg = error_data.get('message', error_data.get('error', 'Unknown error'))
                    return False, f"✗ {response.status_code} - {error_msg}", response.status_code
                except:
                    return False, f"✗ {response.status_code}", response.status_code
        
        except requests.exceptions.ConnectRefusedError:
            return False, "✗ Connection refused (server not running?)", 0
        except requests.exceptions.Timeout:
            return False, "✗ Request timeout", 0
        except requests.exceptions.RequestException as e:
            return False, f"✗ Request error: {str(e)}", 0
        except Exception as e:
            return False, f"✗ Unexpected error: {str(e)}", 0
    
    def run_all_tests(self):
        """Run all endpoint tests"""
        print(f"{Colors.BOLD}{Colors.CYAN}🚀 CertMate API Endpoint Test Suite{Colors.RESET}")
        print(f"{Colors.WHITE}Testing API at: {self.base_url}{Colors.RESET}")
        print(f"{Colors.WHITE}Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Colors.RESET}")
        print("=" * 80)
        
        # Test health endpoint first (no auth required)
        self._test_health_endpoints()
        
        # Check if we have API token for authenticated endpoints
        if not self.api_token:
            print(f"\n{Colors.YELLOW}⚠️  No API token provided. Testing public endpoints only.{Colors.RESET}")
            print(f"{Colors.YELLOW}   Use --token <your-token> to test authenticated endpoints.{Colors.RESET}")
        else:
            # Test authenticated endpoints
            self._test_settings_endpoints()
            self._test_certificate_endpoints()
            self._test_cache_endpoints()
            self._test_backup_endpoints()
            self._test_metrics_endpoints()
        
        # Test web interface endpoints (some require auth, some don't)
        self._test_web_endpoints()
        
        # Print summary and return result
        return self._print_summary()
    
    def _test_health_endpoints(self):
        """Test health check endpoints"""
        print(f"\n{Colors.BOLD}{Colors.BLUE}🏥 Health Check Endpoints{Colors.RESET}")
        
        tests = [
            ("GET", "/api/health", "API Health Check", None, [200], False),
            ("GET", "/health", "Web Health Check", None, [200], False),
        ]
        
        for method, path, desc, data, expected, auth in tests:
            success, message, status = self.test_endpoint(method, path, desc, data, expected, auth)
            self._record_result(method, path, desc, success, message, status)
    
    def _test_settings_endpoints(self):
        """Test settings-related endpoints"""
        print(f"\n{Colors.BOLD}{Colors.BLUE}⚙️  Settings Endpoints{Colors.RESET}")
        
        tests = [
            ("GET", "/api/settings", "Get Current Settings", None, [200]),
            ("GET", "/api/settings/dns-providers", "Get DNS Providers", None, [200]),
            ("POST", "/api/settings", "Update Settings", {"email": "test@example.com"}, [200, 400, 422]),
        ]
        
        for method, path, desc, data, expected in tests:
            success, message, status = self.test_endpoint(method, path, desc, data, expected)
            self._record_result(method, path, desc, success, message, status)
    
    def _test_certificate_endpoints(self):
        """Test certificate-related endpoints"""
        print(f"\n{Colors.BOLD}{Colors.BLUE}🔒 Certificate Endpoints{Colors.RESET}")
        
        tests = [
            ("GET", "/api/certificates", "List All Certificates", None, [200]),
            ("POST", "/api/certificates/create", "Create Certificate", 
             {"domain": "test.example.com"}, [200, 201, 400, 422]),
            ("GET", "/api/certificates/test.example.com/download", "Download Certificate", 
             None, [200, 404]),
            ("POST", "/api/certificates/test.example.com/renew", "Renew Certificate", 
             None, [200, 404, 422]),
        ]
        
        for method, path, desc, data, expected in tests:
            success, message, status = self.test_endpoint(method, path, desc, data, expected)
            self._record_result(method, path, desc, success, message, status)
    
    def _test_cache_endpoints(self):
        """Test cache management endpoints"""
        print(f"\n{Colors.BOLD}{Colors.BLUE}💾 Cache Management Endpoints{Colors.RESET}")
        
        tests = [
            ("GET", "/api/cache/stats", "Get Cache Statistics", None, [200]),
            ("POST", "/api/cache/clear", "Clear Cache", None, [200]),
        ]
        
        for method, path, desc, data, expected in tests:
            success, message, status = self.test_endpoint(method, path, desc, data, expected)
            self._record_result(method, path, desc, success, message, status)
    
    def _test_backup_endpoints(self):
        """Test backup and restore endpoints"""
        print(f"\n{Colors.BOLD}{Colors.BLUE}💾 Backup & Restore Endpoints{Colors.RESET}")
        
        tests = [
            ("GET", "/api/backups", "List All Backups", None, [200]),
            ("POST", "/api/backups/create", "Create Manual Backup", 
             {"type": "settings", "reason": "api_test"}, [200, 400]),
            ("POST", "/api/backups/cleanup", "Cleanup Old Backups", 
             {"type": "both", "force": False}, [200]),
        ]
        
        for method, path, desc, data, expected in tests:
            success, message, status = self.test_endpoint(method, path, desc, data, expected)
            self._record_result(method, path, desc, success, message, status)
    
    def _test_metrics_endpoints(self):
        """Test metrics and monitoring endpoints"""
        print(f"\n{Colors.BOLD}{Colors.BLUE}📊 Metrics & Monitoring Endpoints{Colors.RESET}")
        
        tests = [
            ("GET", "/api/metrics", "API Metrics Summary", None, [200]),
            ("GET", "/metrics", "Prometheus Metrics", None, [200, 503]),  # 503 if prometheus_client not available
        ]
        
        for method, path, desc, data, expected in tests:
            success, message, status = self.test_endpoint(method, path, desc, data, expected)
            self._record_result(method, path, desc, success, message, status)
    
    def _test_web_endpoints(self):
        """Test web interface endpoints"""
        print(f"\n{Colors.BOLD}{Colors.BLUE}🌐 Web Interface Endpoints{Colors.RESET}")
        
        # Test public web endpoints (no auth required)
        web_tests_public = [
            ("GET", "/", "Main Dashboard", None, [200], False),
            ("GET", "/settings", "Settings Page", None, [200], False),
            ("GET", "/help", "Help Page", None, [200], False),
            ("GET", "/docs/", "API Documentation", None, [200, 301, 302], False),
            ("GET", "/api/swagger.json", "Swagger JSON", None, [200], False),
        ]
        
        for method, path, desc, data, expected, auth in web_tests_public:
            success, message, status = self.test_endpoint(method, path, desc, data, expected, auth)
            self._record_result(method, path, desc, success, message, status)
        
        # Test web API endpoints (some require auth)
        if self.api_token:
            web_tests_auth = [
                ("GET", "/api/web/settings", "Web Settings API", None, [200, 401], False),  # No auth for initial setup
                ("GET", "/api/web/certificates", "Web Certificates API", None, [200, 401], True),
                ("GET", "/api/web/cache/stats", "Web Cache Stats", None, [200, 401], True),
                ("POST", "/api/web/cache/clear", "Web Cache Clear", None, [200, 401], True),
                ("GET", "/api/web/backups", "Web Backups List", None, [200, 401], True),
            ]
            
            for method, path, desc, data, expected, auth in web_tests_auth:
                success, message, status = self.test_endpoint(method, path, desc, data, expected, auth)
                self._record_result(method, path, desc, success, message, status)
    
    def _record_result(self, method: str, path: str, description: str, 
                      success: bool, message: str, status_code: int):
        """Record test result and print it"""
        self.results.append({
            'method': method,
            'path': path,
            'description': description,
            'success': success,
            'message': message,
            'status_code': status_code
        })
        
        # Print result
        color = Colors.GREEN if success else Colors.RED
        status_icon = "✅" if success else "❌"
        print(f"  {status_icon} {color}{method:4} {path:40} {description:30} {message}{Colors.RESET}")
    
    def _print_summary(self):
        """Print test summary"""
        total_tests = len(self.results)
        passed_tests = sum(1 for r in self.results if r['success'])
        failed_tests = total_tests - passed_tests
        
        print("\n" + "=" * 80)
        print(f"{Colors.BOLD}{Colors.CYAN}📊 Test Summary{Colors.RESET}")
        print(f"{Colors.WHITE}Total Tests: {total_tests}{Colors.RESET}")
        print(f"{Colors.GREEN}✅ Passed: {passed_tests}{Colors.RESET}")
        print(f"{Colors.RED}❌ Failed: {failed_tests}{Colors.RESET}")
        
        if failed_tests > 0:
            print(f"\n{Colors.BOLD}{Colors.RED}❌ Failed Tests:{Colors.RESET}")
            for result in self.results:
                if not result['success']:
                    print(f"  • {result['method']} {result['path']} - {result['message']}")
        
        # Overall status
        if failed_tests == 0:
            print(f"\n{Colors.BOLD}{Colors.GREEN}🎉 All tests passed! Ready to commit.{Colors.RESET}")
            return True
        else:
            print(f"\n{Colors.BOLD}{Colors.RED}🚫 Some tests failed. Review before committing.{Colors.RESET}")
            return False

def load_api_token_from_settings():
    """Try to load API token from settings.json"""
    try:
        with open('data/settings.json', 'r') as f:
            settings = json.load(f)
            return settings.get('api_bearer_token')
    except:
        return None

def main():
    parser = argparse.ArgumentParser(description='Test all CertMate API endpoints')
    parser.add_argument('--url', default='http://127.0.0.1:8000', 
                       help='Base URL for the API (default: http://127.0.0.1:8000)')
    parser.add_argument('--token', help='API Bearer token for authentication')
    parser.add_argument('--auto-token', action='store_true', 
                       help='Automatically load token from data/settings.json')
    parser.add_argument('--public-only', action='store_true', 
                       help='Test only public endpoints (no authentication required)')
    parser.add_argument('--quick', action='store_true', 
                       help='Run only essential endpoints for quick validation')
    
    args = parser.parse_args()
    
    # Determine API token
    api_token = None
    if not args.public_only:
        if args.token:
            api_token = args.token
        elif args.auto_token:
            api_token = load_api_token_from_settings()
            if api_token:
                print(f"{Colors.GREEN}✓ Loaded API token from settings.json{Colors.RESET}")
            else:
                print(f"{Colors.YELLOW}⚠️  Could not load API token from settings.json{Colors.RESET}")
    
    # Create tester instance
    tester = EndpointTester(base_url=args.url, api_token=api_token)
    
    # Run tests
    start_time = time.time()
    all_passed = tester.run_all_tests()
    end_time = time.time()
    
    print(f"\n{Colors.WHITE}Test completed in {end_time - start_time:.2f} seconds{Colors.RESET}")
    
    # Exit with appropriate code
    sys.exit(0 if all_passed else 1)

if __name__ == "__main__":
    main()
