import json
import os

def test_gulag_security(client_ip):
    if os.path.exists("test_gulag.json"):
        with open("test_gulag.json", "r") as f:
            ip_data = json.load(f)


    assert client_ip in ip_data['Blacklisted IPs']

test_gulag_security("129.234.54.34")