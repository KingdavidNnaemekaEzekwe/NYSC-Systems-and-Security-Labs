#!/usr/bin/env python3
import re
from collections import defaultdict

LOG_FILE = "evidence/sample_auth.log"
FAILED_THRESHOLD = 3

def analyze_ssh_logs():
    failure_tracker = defaultdict(int)
    targeted_users = defaultdict(set)
    
    ip_regex = r"from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
    user_regex = r"for (invalid user )?(\S+) from"

    print("[*] Starting Security Log Analysis Engine...")
    
    try:
        with open(LOG_FILE, "r") as file:
            for line in file:
                if "Failed password" in line or "Invalid user" in line:
                    ip_match = re.search(ip_regex, line)
                    user_match = re.search(user_regex, line)
                    
                    if ip_match:
                        source_ip = ip_match.group(1)
                        failure_tracker[source_ip] += 1
                        
                        if user_match:
                            username = user_match.group(2)
                            targeted_users[source_ip].add(username)

        print("\n=== DETECTED SECURITY EVENTS ===")
        incident_triggered = False
        
        for ip, count in failure_tracker.items():
            if count >= FAILED_THRESHOLD:
                incident_triggered = True
                users_list = ", ".join(targeted_users[ip])
                print(f"[!] ALERT: Potential Brute-Force Attack Detected!")
                print(f"    - Malicious Source IP: {ip}")
                print(f"    - Total Failed Attempts: {count}")
                print(f"    - Targeted Usernames: [{users_list}]")
                print(f"    - Action Recommended: Block IP via Firewall rule.")
                print("-" * 45)
        
        if not incident_triggered:
            print("[+] Scan complete. No anomalies detected.")
            
    except FileNotFoundError:
        print(f"[-] Error: Target file '{LOG_FILE}' not found.")

if __name__ == "__main__":
    analyze_ssh_logs()
