#!/usr/bin/env python3
"""
CertMate SOLIDserver DNS-01 challenge hook script.
This script is called by Certbot via --manual-auth-hook and --manual-cleanup-hook.
"""

import os
import sys
import time
import base64
import requests

# Disable InsecureRequestWarning for self-signed certificates
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def main():
    if len(sys.argv) < 2:
        print("Usage: solidserver_hook.py <auth|cleanup>")
        sys.exit(1)
        
    action = sys.argv[1]
    
    domain = os.environ.get("CERTBOT_DOMAIN")
    validation = os.environ.get("CERTBOT_VALIDATION")
    
    host = os.environ.get("SOLIDSERVER_HOST", "").rstrip("/")
    username = os.environ.get("SOLIDSERVER_USERNAME")
    password = os.environ.get("SOLIDSERVER_PASSWORD")
    dns_name = os.environ.get("SOLIDSERVER_DNS_NAME")
    
    if not all([domain, validation, host, username, password, dns_name]):
        print("Missing required environment variables for SOLIDserver.")
        sys.exit(1)
        
    rr_name = f"_acme-challenge.{domain}"
    
    user_b64 = base64.b64encode(username.encode()).decode()
    pass_b64 = base64.b64encode(password.encode()).decode()
    
    headers = {
        'x-ipm-username': user_b64,
        'x-ipm-password': pass_b64,
        'cache-control': 'no-cache'
    }
    
    params = {
        "rr_name": rr_name,
        "rr_type": "TXT",
        "value1": validation,
        "dns_name": dns_name
    }
    
    dnsview_name = os.environ.get("SOLIDSERVER_DNSVIEW_NAME")
    if dnsview_name:
        params["dnsview_name"] = dnsview_name
    
    # TLS verification is ON by default; allow opt-out for self-signed
    # SOLIDserver appliances via SOLIDSERVER_SSL_VERIFY=false (never hard-disabled).
    verify_ssl = os.environ.get("SOLIDSERVER_SSL_VERIFY", "true").lower() not in ("false", "0", "no")

    if action == "auth":
        url = f"https://{host}/rest/dns_rr_add"
        try:
            print(f"Adding TXT record {rr_name} for SOLIDserver DNS: {dns_name}" + (f" (View: {dnsview_name})" if dnsview_name else ""))
            res = requests.post(url, headers=headers, params=params, verify=verify_ssl)
            if res.status_code >= 400:
                print(f"Error adding record: HTTP {res.status_code} - {res.text}")
                sys.exit(1)
                
            # Wait for DNS propagation
            propagation_seconds = int(os.environ.get("CERTMATE_DNS_PROPAGATION_SECONDS", "120"))
            print(f"Waiting {propagation_seconds} seconds for DNS propagation...")
            time.sleep(propagation_seconds)
        except Exception as e:
            print(f"Failed to communicate with SOLIDserver: {e}")
            sys.exit(1)
            
    elif action == "cleanup":
        # Delete record
        url = f"https://{host}/rest/dns_rr_delete"
        try:
            print(f"Cleaning up TXT record {rr_name}")
            res = requests.delete(url, headers=headers, params=params, verify=verify_ssl)
            if res.status_code >= 400:
                print(f"Warning: Failed to cleanup record: HTTP {res.status_code} - {res.text}")
        except Exception as e:
            print(f"Warning: Failed to communicate with SOLIDserver for cleanup: {e}")

if __name__ == "__main__":
    main()
