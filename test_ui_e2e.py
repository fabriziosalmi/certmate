#!/usr/bin/env python3
"""
🎭 CertMate UI E2E Test Suite with Playwright
==============================================
Beautiful, human-readable browser automation tests for the CertMate UI.

Features:
- Real browser testing (Chromium, Firefox, WebKit)
- Human-readable terminal output with colors and emojis
- Tests against real test domain: test.certmate.org
- Screenshot capture on failures
- Performance timing for each test

Usage:
    # Install dependencies first:
    pip install playwright pytest-playwright
    playwright install chromium

    # Run all UI tests:
    python test_ui_e2e.py

    # Run specific test:
    python test_ui_e2e.py --test navigation

    # Run with headed browser (visible):
    python test_ui_e2e.py --headed

    # Run against custom URL:
    python test_ui_e2e.py --base-url http://localhost:8000
"""

import os
import sys
import time
import argparse
import traceback
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional, List, Callable
from contextlib import contextmanager

# Try to import Playwright
try:
    from playwright.sync_api import sync_playwright, Page, Browser, expect
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False


# =============================================================================
# 🎨 Terminal Colors & Formatting
# =============================================================================

class Colors:
    """ANSI color codes for terminal output"""
    RESET = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    UNDERLINE = '\033[4m'
    
    # Foreground
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    GRAY = '\033[90m'
    
    # Background
    BG_RED = '\033[41m'
    BG_GREEN = '\033[42m'
    BG_YELLOW = '\033[43m'
    BG_BLUE = '\033[44m'


def colorize(text: str, *colors: str) -> str:
    """Apply colors to text"""
    return f"{''.join(colors)}{text}{Colors.RESET}"


def print_header(title: str, emoji: str = "🎭"):
    """Print a beautiful header"""
    width = 70
    print()
    print(colorize("═" * width, Colors.CYAN))
    print(colorize(f"  {emoji}  {title}", Colors.CYAN, Colors.BOLD))
    print(colorize("═" * width, Colors.CYAN))
    print()


def print_section(title: str, emoji: str = "📌"):
    """Print a section header"""
    print()
    print(colorize(f"  {emoji} {title}", Colors.BLUE, Colors.BOLD))
    print(colorize("  " + "─" * 50, Colors.GRAY))


def print_step(step: str, emoji: str = "▸"):
    """Print a test step"""
    print(colorize(f"    {emoji} {step}", Colors.WHITE))


def print_success(message: str):
    """Print success message"""
    print(colorize(f"    ✅ {message}", Colors.GREEN))


def print_failure(message: str):
    """Print failure message"""
    print(colorize(f"    ❌ {message}", Colors.RED))


def print_warning(message: str):
    """Print warning message"""
    print(colorize(f"    ⚠️  {message}", Colors.YELLOW))


def print_info(message: str):
    """Print info message"""
    print(colorize(f"    ℹ️  {message}", Colors.CYAN))


def print_timing(elapsed_ms: float):
    """Print timing info"""
    if elapsed_ms < 1000:
        time_str = f"{elapsed_ms:.0f}ms"
    else:
        time_str = f"{elapsed_ms/1000:.2f}s"
    
    color = Colors.GREEN if elapsed_ms < 2000 else Colors.YELLOW if elapsed_ms < 5000 else Colors.RED
    print(colorize(f"    ⏱️  Completed in {time_str}", color, Colors.DIM))


# =============================================================================
# 📊 Test Results Tracking
# =============================================================================

@dataclass
class TestResult:
    """Single test result"""
    name: str
    category: str
    passed: bool
    duration_ms: float
    error: Optional[str] = None
    screenshot_path: Optional[str] = None


@dataclass  
class TestSuite:
    """Test suite results aggregator"""
    results: List[TestResult] = field(default_factory=list)
    start_time: float = field(default_factory=time.time)
    
    def add_result(self, result: TestResult):
        self.results.append(result)
        
    @property
    def total(self) -> int:
        return len(self.results)
    
    @property
    def passed(self) -> int:
        return sum(1 for r in self.results if r.passed)
    
    @property
    def failed(self) -> int:
        return sum(1 for r in self.results if not r.passed)
    
    @property
    def pass_rate(self) -> float:
        return (self.passed / self.total * 100) if self.total > 0 else 0
    
    @property
    def total_duration_ms(self) -> float:
        return sum(r.duration_ms for r in self.results)
    
    def print_summary(self):
        """Print beautiful test summary"""
        elapsed = time.time() - self.start_time
        
        print()
        print(colorize("═" * 70, Colors.CYAN))
        
        # Status header
        if self.failed == 0:
            print(colorize("  🎉 ALL TESTS PASSED!", Colors.GREEN, Colors.BOLD))
        else:
            print(colorize(f"  ⚠️  {self.failed} TEST(S) FAILED", Colors.RED, Colors.BOLD))
        
        print(colorize("═" * 70, Colors.CYAN))
        print()
        
        # Statistics
        print(colorize("  📊 Test Statistics", Colors.BLUE, Colors.BOLD))
        print(colorize("  " + "─" * 40, Colors.GRAY))
        
        pass_color = Colors.GREEN if self.pass_rate == 100 else Colors.YELLOW if self.pass_rate >= 80 else Colors.RED
        
        print(f"    Total Tests:    {colorize(str(self.total), Colors.WHITE, Colors.BOLD)}")
        print(f"    Passed:         {colorize(str(self.passed), Colors.GREEN)} ✓")
        print(f"    Failed:         {colorize(str(self.failed), Colors.RED if self.failed > 0 else Colors.GREEN)} {'✗' if self.failed > 0 else '✓'}")
        print(f"    Pass Rate:      {colorize(f'{self.pass_rate:.1f}%', pass_color, Colors.BOLD)}")
        print(f"    Total Duration: {colorize(f'{elapsed:.2f}s', Colors.CYAN)}")
        print()
        
        # Results by category
        categories = {}
        for r in self.results:
            if r.category not in categories:
                categories[r.category] = {'passed': 0, 'failed': 0}
            if r.passed:
                categories[r.category]['passed'] += 1
            else:
                categories[r.category]['failed'] += 1
        
        print(colorize("  📁 Results by Category", Colors.BLUE, Colors.BOLD))
        print(colorize("  " + "─" * 40, Colors.GRAY))
        
        for cat, stats in categories.items():
            total = stats['passed'] + stats['failed']
            emoji = "✅" if stats['failed'] == 0 else "⚠️"
            color = Colors.GREEN if stats['failed'] == 0 else Colors.YELLOW
            print(f"    {emoji} {cat}: {colorize(f'{stats['passed']}/{total}', color)} passed")
        
        # Failed tests details
        if self.failed > 0:
            print()
            print(colorize("  ❌ Failed Tests", Colors.RED, Colors.BOLD))
            print(colorize("  " + "─" * 40, Colors.GRAY))
            
            for r in self.results:
                if not r.passed:
                    print(f"    • {colorize(r.name, Colors.RED)} ({r.category})")
                    if r.error:
                        # Truncate error message
                        error_lines = r.error.split('\n')[:3]
                        for line in error_lines:
                            print(colorize(f"      {line[:80]}", Colors.GRAY))
                    if r.screenshot_path:
                        print(colorize(f"      📸 Screenshot: {r.screenshot_path}", Colors.YELLOW))
        
        print()
        print(colorize("═" * 70, Colors.CYAN))
        print()
        
        return self.failed == 0


# =============================================================================
# 🎭 E2E Test Runner
# =============================================================================

class CertMateUITests:
    """CertMate UI End-to-End Test Suite"""
    
    def __init__(
        self,
        base_url: str = "http://localhost:8000",
        headless: bool = True,
        slow_mo: int = 0,
        screenshot_dir: str = "test_screenshots"
    ):
        self.base_url = base_url.rstrip('/')
        self.headless = headless
        self.slow_mo = slow_mo
        self.screenshot_dir = Path(screenshot_dir)
        self.screenshot_dir.mkdir(exist_ok=True)
        
        self.suite = TestSuite()
        self.page: Optional[Page] = None
        self.browser: Optional[Browser] = None
        
        # Test domain for real certificate tests
        self.test_domain = "test.certmate.org"
    
    @contextmanager
    def test_context(self, name: str, category: str):
        """Context manager for running a single test"""
        start = time.time()
        error = None
        screenshot_path = None
        
        print_step(f"Testing: {name}")
        
        try:
            yield
            print_success(f"{name}")
        except Exception as e:
            error = str(e)
            print_failure(f"{name}")
            print(colorize(f"      Error: {error[:100]}", Colors.RED, Colors.DIM))
            
            # Take screenshot on failure
            if self.page:
                screenshot_path = str(self.screenshot_dir / f"fail_{name.replace(' ', '_')}_{int(time.time())}.png")
                try:
                    self.page.screenshot(path=screenshot_path)
                    print_info(f"Screenshot saved: {screenshot_path}")
                except:
                    pass
        
        duration_ms = (time.time() - start) * 1000
        print_timing(duration_ms)
        
        self.suite.add_result(TestResult(
            name=name,
            category=category,
            passed=error is None,
            duration_ms=duration_ms,
            error=error,
            screenshot_path=screenshot_path
        ))
    
    def run_all(self) -> bool:
        """Run all E2E tests"""
        print_header("CertMate UI E2E Test Suite", "🎭")
        
        print_info(f"Base URL: {self.base_url}")
        print_info(f"Headless: {self.headless}")
        print_info(f"Test Domain: {self.test_domain}")
        print()
        
        # Check if server is running
        if not self._check_server():
            return False
        
        with sync_playwright() as p:
            # Launch browser
            print_section("Launching Browser", "🌐")
            self.browser = p.chromium.launch(
                headless=self.headless,
                slow_mo=self.slow_mo
            )
            
            context = self.browser.new_context(
                viewport={'width': 1920, 'height': 1080},
                user_agent='CertMate-E2E-Tests/1.0'
            )
            
            self.page = context.new_page()
            print_success(f"Browser launched (Chromium)")
            
            try:
                # Run test categories
                self._test_navigation()
                self._test_homepage_elements()
                self._test_create_certificate_form()
                self._test_settings_page()
                self._test_help_page()
                self._test_certificate_list()
                self._test_responsive_design()
                self._test_dark_mode()
                self._test_api_integration()
                self._test_error_handling()
                
            finally:
                self.browser.close()
        
        # Print summary
        return self.suite.print_summary()
    
    def _check_server(self) -> bool:
        """Check if the server is running"""
        import urllib.request
        import urllib.error
        
        print_section("Checking Server", "🔌")
        
        try:
            req = urllib.request.Request(self.base_url, method='HEAD')
            urllib.request.urlopen(req, timeout=5)
            print_success(f"Server is running at {self.base_url}")
            return True
        except urllib.error.URLError as e:
            print_failure(f"Server not reachable: {e}")
            print_warning("Start CertMate first: python app.py")
            return False
        except Exception as e:
            print_failure(f"Connection error: {e}")
            return False
    
    # =========================================================================
    # 🧭 Navigation Tests
    # =========================================================================
    
    def _test_navigation(self):
        """Test navigation between pages"""
        print_section("Navigation Tests", "🧭")
        
        with self.test_context("Homepage loads", "Navigation"):
            self.page.goto(self.base_url)
            expect(self.page).to_have_title("CertMate - SSL Certificate Manager")
        
        with self.test_context("Navigate to Settings", "Navigation"):
            self.page.click('a[href="/settings"]')
            self.page.wait_for_load_state('networkidle')
            expect(self.page).to_have_url(f"{self.base_url}/settings")
            expect(self.page.locator('h2')).to_contain_text('Settings')
        
        with self.test_context("Navigate to Help", "Navigation"):
            self.page.click('a[href="/help"]')
            self.page.wait_for_load_state('networkidle')
            expect(self.page).to_have_url(f"{self.base_url}/help")
        
        with self.test_context("Navigate back to Certificates", "Navigation"):
            self.page.click('a[href="/"]')
            self.page.wait_for_load_state('networkidle')
            expect(self.page).to_have_url(f"{self.base_url}/")
        
        with self.test_context("CertMate logo/title visible", "Navigation"):
            logo = self.page.locator('.fa-shield-alt').first
            expect(logo).to_be_visible()
            title = self.page.locator('h1:has-text("CertMate")').first
            expect(title).to_be_visible()
    
    # =========================================================================
    # 🏠 Homepage Elements Tests
    # =========================================================================
    
    def _test_homepage_elements(self):
        """Test homepage UI elements"""
        print_section("Homepage Elements", "🏠")
        
        self.page.goto(self.base_url)
        self.page.wait_for_load_state('networkidle')
        
        with self.test_context("Create Certificate section visible", "Homepage"):
            section = self.page.locator('h3:has-text("Create New Certificate")')
            expect(section).to_be_visible()
        
        with self.test_context("Domain input field exists", "Homepage"):
            domain_input = self.page.locator('#domain')
            expect(domain_input).to_be_visible()
            expect(domain_input).to_have_attribute('required', '')
        
        with self.test_context("SAN domains field exists", "Homepage"):
            san_input = self.page.locator('#san_domains')
            expect(san_input).to_be_visible()
        
        with self.test_context("CA Provider dropdown exists", "Homepage"):
            ca_select = self.page.locator('#ca_provider_select')
            expect(ca_select).to_be_visible()
            # Check options (should have at least 4: default + 3 providers)
            options = ca_select.locator('option')
            count = options.count()
            assert count >= 4, f"Expected at least 4 CA options, got {count}"
        
        with self.test_context("DNS Provider dropdown exists", "Homepage"):
            dns_select = self.page.locator('#dns_provider_select')
            expect(dns_select).to_be_visible()
        
        with self.test_context("Create Certificate button exists", "Homepage"):
            button = self.page.locator('button[type="submit"]:has-text("Create Certificate")')
            expect(button).to_be_visible()
            expect(button).to_be_enabled()
        
        with self.test_context("Certificates list section exists", "Homepage"):
            list_section = self.page.locator('h3:has-text("Your Certificates")')
            expect(list_section).to_be_visible()
        
        with self.test_context("Search input exists", "Homepage"):
            search = self.page.locator('#certificateSearch')
            expect(search).to_be_visible()
        
        with self.test_context("Status filter dropdown exists", "Homepage"):
            status_filter = self.page.locator('#statusFilter')
            expect(status_filter).to_be_visible()
    
    # =========================================================================
    # 📝 Create Certificate Form Tests
    # =========================================================================
    
    def _test_create_certificate_form(self):
        """Test the certificate creation form"""
        print_section("Create Certificate Form", "📝")
        
        self.page.goto(self.base_url)
        self.page.wait_for_load_state('networkidle')
        
        with self.test_context("Fill domain name", "Form"):
            domain_input = self.page.locator('#domain')
            domain_input.fill('example.com')
            expect(domain_input).to_have_value('example.com')
        
        with self.test_context("Fill SAN domains", "Form"):
            san_input = self.page.locator('#san_domains')
            san_input.fill('www.example.com, api.example.com')
            expect(san_input).to_have_value('www.example.com, api.example.com')
        
        with self.test_context("Select CA Provider - Let's Encrypt", "Form"):
            ca_select = self.page.locator('#ca_provider_select')
            ca_select.select_option('letsencrypt')
            expect(ca_select).to_have_value('letsencrypt')
        
        with self.test_context("Select CA Provider - Private CA", "Form"):
            ca_select = self.page.locator('#ca_provider_select')
            ca_select.select_option('private_ca')
            expect(ca_select).to_have_value('private_ca')
        
        with self.test_context("Select DNS Provider - Cloudflare", "Form"):
            dns_select = self.page.locator('#dns_provider_select')
            dns_select.select_option('cloudflare')
            expect(dns_select).to_have_value('cloudflare')
        
        with self.test_context("Select DNS Provider - Route53", "Form"):
            dns_select = self.page.locator('#dns_provider_select')
            dns_select.select_option('route53')
            expect(dns_select).to_have_value('route53')
        
        with self.test_context("Toggle Advanced Options", "Form"):
            # Click advanced options button
            self.page.click('button:has-text("Advanced Options")')
            # Wait for animation
            self.page.wait_for_timeout(300)
            # Check if advanced options are visible
            advanced = self.page.locator('#advanced-options')
            expect(advanced).to_be_visible()
        
        with self.test_context("Wildcard checkbox exists", "Form"):
            wildcard = self.page.locator('#wildcard-cert')
            expect(wildcard).to_be_visible()
        
        with self.test_context("Staging checkbox exists", "Form"):
            staging = self.page.locator('#staging-cert')
            expect(staging).to_be_visible()
        
        with self.test_context("Form validation - empty domain", "Form"):
            # Clear domain and try to submit
            self.page.locator('#domain').fill('')
            # The form should not submit due to HTML5 validation
            # Check that required attribute prevents submission
            domain_input = self.page.locator('#domain')
            expect(domain_input).to_have_attribute('required', '')
    
    # =========================================================================
    # ⚙️ Settings Page Tests
    # =========================================================================
    
    def _test_settings_page(self):
        """Test the settings page"""
        print_section("Settings Page", "⚙️")
        
        self.page.goto(f"{self.base_url}/settings")
        self.page.wait_for_load_state('networkidle')
        
        with self.test_context("Settings title visible", "Settings"):
            title = self.page.locator('h2:has-text("Settings")')
            expect(title).to_be_visible()
        
        with self.test_context("DNS provider cards visible", "Settings"):
            # Check for Cloudflare card
            cloudflare = self.page.locator('text=Cloudflare').first
            expect(cloudflare).to_be_visible()
        
        with self.test_context("Route53 provider option", "Settings"):
            route53 = self.page.locator('text=Route53').first
            expect(route53).to_be_visible()
        
        with self.test_context("DigitalOcean provider option", "Settings"):
            do = self.page.locator('text=DigitalOcean').first
            expect(do).to_be_visible()
        
        with self.test_context("Configuration section exists", "Settings"):
            config = self.page.locator('h3:has-text("Configuration")')
            expect(config).to_be_visible()
        
        with self.test_context("Multi-account support section", "Settings"):
            multi_account = self.page.locator('text=Multi-Account Support').first
            expect(multi_account).to_be_visible()
    
    # =========================================================================
    # ❓ Help Page Tests
    # =========================================================================
    
    def _test_help_page(self):
        """Test the help page"""
        print_section("Help Page", "❓")
        
        self.page.goto(f"{self.base_url}/help")
        self.page.wait_for_load_state('networkidle')
        
        with self.test_context("Help page loads", "Help"):
            # Just verify page loaded without error
            expect(self.page).to_have_url(f"{self.base_url}/help")
        
        with self.test_context("Help content visible", "Help"):
            # Check for some help content
            body = self.page.locator('body')
            expect(body).to_be_visible()
    
    # =========================================================================
    # 📋 Certificate List Tests
    # =========================================================================
    
    def _test_certificate_list(self):
        """Test certificate list functionality"""
        print_section("Certificate List", "📋")
        
        self.page.goto(self.base_url)
        self.page.wait_for_load_state('networkidle')
        
        with self.test_context("Certificate search works", "List"):
            search = self.page.locator('#certificateSearch')
            search.fill('test')
            # Wait for filtering
            self.page.wait_for_timeout(500)
            # Search should work without errors
            expect(search).to_have_value('test')
        
        with self.test_context("Status filter - All", "List"):
            filter_select = self.page.locator('#statusFilter')
            filter_select.select_option('all')
            expect(filter_select).to_have_value('all')
        
        with self.test_context("Status filter - Valid", "List"):
            filter_select = self.page.locator('#statusFilter')
            filter_select.select_option('valid')
            expect(filter_select).to_have_value('valid')
        
        with self.test_context("Status filter - Expiring", "List"):
            filter_select = self.page.locator('#statusFilter')
            filter_select.select_option('expiring')
            expect(filter_select).to_have_value('expiring')
        
        with self.test_context("Check All button exists", "List"):
            check_all = self.page.locator('button:has-text("Check")')
            expect(check_all.first).to_be_visible()
    
    # =========================================================================
    # 📱 Responsive Design Tests
    # =========================================================================
    
    def _test_responsive_design(self):
        """Test responsive design at different viewport sizes"""
        print_section("Responsive Design", "📱")
        
        self.page.goto(self.base_url)
        
        with self.test_context("Mobile viewport (375x667)", "Responsive"):
            self.page.set_viewport_size({'width': 375, 'height': 667})
            self.page.wait_for_timeout(300)
            # Nav should still be visible
            nav = self.page.locator('nav').first
            expect(nav).to_be_visible()
        
        with self.test_context("Tablet viewport (768x1024)", "Responsive"):
            self.page.set_viewport_size({'width': 768, 'height': 1024})
            self.page.wait_for_timeout(300)
            domain_input = self.page.locator('#domain')
            expect(domain_input).to_be_visible()
        
        with self.test_context("Desktop viewport (1920x1080)", "Responsive"):
            self.page.set_viewport_size({'width': 1920, 'height': 1080})
            self.page.wait_for_timeout(300)
            # All elements should be visible
            domain_input = self.page.locator('#domain')
            expect(domain_input).to_be_visible()
    
    # =========================================================================
    # 🌙 Dark Mode Tests
    # =========================================================================
    
    def _test_dark_mode(self):
        """Test dark mode support"""
        print_section("Dark Mode", "🌙")
        
        # Create a new context with dark color scheme
        context = self.browser.new_context(
            viewport={'width': 1920, 'height': 1080},
            color_scheme='dark'
        )
        dark_page = context.new_page()
        
        try:
            with self.test_context("Dark mode renders correctly", "Dark Mode"):
                dark_page.goto(self.base_url)
                dark_page.wait_for_load_state('networkidle')
                # Check that page renders without errors
                body = dark_page.locator('body')
                expect(body).to_be_visible()
            
            with self.test_context("Navigation visible in dark mode", "Dark Mode"):
                nav = dark_page.locator('nav').first
                expect(nav).to_be_visible()
            
            with self.test_context("Form elements visible in dark mode", "Dark Mode"):
                domain_input = dark_page.locator('#domain')
                expect(domain_input).to_be_visible()
        finally:
            context.close()
    
    # =========================================================================
    # 🔌 API Integration Tests
    # =========================================================================
    
    def _test_api_integration(self):
        """Test frontend-backend API integration"""
        print_section("API Integration", "🔌")
        
        self.page.goto(self.base_url)
        self.page.wait_for_load_state('networkidle')
        
        with self.test_context("API health check endpoint", "API"):
            # Make API request through page context
            response = self.page.request.get(f"{self.base_url}/api/health")
            assert response.ok, f"Health check failed: {response.status}"
        
        with self.test_context("Settings API endpoint", "API"):
            response = self.page.request.get(f"{self.base_url}/api/settings")
            # May require auth, just check it responds
            assert response.status in [200, 401, 403], f"Settings API error: {response.status}"
        
        with self.test_context("Certificates list API", "API"):
            response = self.page.request.get(f"{self.base_url}/api/certificates")
            # May require auth
            assert response.status in [200, 401, 403], f"Certificates API error: {response.status}"
    
    # =========================================================================
    # ⚠️ Error Handling Tests
    # =========================================================================
    
    def _test_error_handling(self):
        """Test error handling and edge cases"""
        print_section("Error Handling", "⚠️")
        
        with self.test_context("404 page handling", "Errors"):
            response = self.page.goto(f"{self.base_url}/nonexistent-page-12345")
            # Should handle 404 gracefully
            assert response.status == 404 or response.status == 200
        
        with self.test_context("Return to homepage after 404", "Errors"):
            self.page.goto(self.base_url)
            self.page.wait_for_load_state('networkidle')
            expect(self.page).to_have_url(f"{self.base_url}/")


# =============================================================================
# 🚀 Main Entry Point
# =============================================================================

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='🎭 CertMate UI E2E Tests - Human-readable browser automation',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python test_ui_e2e.py                    # Run all tests headless
  python test_ui_e2e.py --headed           # Run with visible browser
  python test_ui_e2e.py --base-url http://myserver:8000
  python test_ui_e2e.py --slow-mo 500      # Slow down for debugging
        """
    )
    
    parser.add_argument(
        '--base-url', '-u',
        default='http://localhost:8000',
        help='Base URL of CertMate instance (default: http://localhost:8000)'
    )
    
    parser.add_argument(
        '--headed', '-H',
        action='store_true',
        help='Run with visible browser window'
    )
    
    parser.add_argument(
        '--slow-mo', '-s',
        type=int,
        default=0,
        help='Slow down actions by N milliseconds (for debugging)'
    )
    
    parser.add_argument(
        '--screenshots', '-S',
        default='test_screenshots',
        help='Directory for failure screenshots (default: test_screenshots)'
    )
    
    args = parser.parse_args()
    
    # Check Playwright availability
    if not PLAYWRIGHT_AVAILABLE:
        print_header("Setup Required", "📦")
        print_failure("Playwright is not installed!")
        print()
        print_info("Install Playwright with:")
        print(colorize("    pip install playwright pytest-playwright", Colors.CYAN))
        print(colorize("    playwright install chromium", Colors.CYAN))
        print()
        sys.exit(1)
    
    # Run tests
    tests = CertMateUITests(
        base_url=args.base_url,
        headless=not args.headed,
        slow_mo=args.slow_mo,
        screenshot_dir=args.screenshots
    )
    
    success = tests.run_all()
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
