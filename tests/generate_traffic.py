#!/usr/bin/env python3
import requests
import random
import time
import sys


def send_normal_request(base_url, endpoint="/backend/api/data"):
    try:
        requests.get(f"{base_url}{endpoint}", timeout=2)
    except:
        pass


def send_attack_request(base_url, attack_type="sqli"):
    attacks = {
        "sqli": ("/backend/login", "POST", {"username": "admin' OR '1'='1", "password": "x"}),
        "xss": ("/backend/search?q=<script>alert(1)</script>", "GET", None),
        "cmd": ("/backend/cmd", "POST", {"cmd": "cat /etc/passwd"}),
        "path": ("/backend/file?path=../../../etc/passwd", "GET", None),
    }
    
    path, method, data = attacks.get(attack_type, attacks["sqli"])
    
    try:
        if method == "GET":
            requests.get(f"{base_url}{path}", timeout=2)
        else:
            requests.post(f"{base_url}{path}", data=data, timeout=2)
    except:
        pass


def generate_traffic(base_url, duration_seconds=60):
    print(f"Generating traffic for {duration_seconds} seconds...")
    print(f"Target: {base_url}")
    print()
    
    start_time = time.time()
    request_count = 0
    attack_count = 0
    
    while time.time() - start_time < duration_seconds:
        if random.random() < 0.7:
            send_normal_request(base_url)
            request_count += 1
        else:
            attack_type = random.choice(["sqli", "xss", "cmd", "path"])
            send_attack_request(base_url, attack_type)
            attack_count += 1
        
        if request_count % 10 == 0:
            sys.stdout.write(f"\rRequests: {request_count} | Simulated Attacks: {attack_count}")
            sys.stdout.flush()
        
        time.sleep(random.uniform(0.1, 0.5))
    
    print()
    print()
    print(f"Done! Total requests: {request_count}")
    print(f"Simulated attacks: {attack_count}")
    print()
    print("Check the dashboard at:", base_url)


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="PhantomWall Traffic Generator")
    parser.add_argument("--url", default="http://127.0.0.1:8080", help="Target URL")
    parser.add_argument("--duration", type=int, default=30, help="Duration in seconds")
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("PhantomWall Traffic Generator")
    print("=" * 60)
    print()
    
    try:
        generate_traffic(args.url, args.duration)
    except KeyboardInterrupt:
        print("\nStopped by user")


if __name__ == "__main__":
    main()
