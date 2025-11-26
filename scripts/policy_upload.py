import os
import json
import requests
import urllib3

# Disable insecure request warnings for demo purposes
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

F5_HOST = os.getenv("F5_HOST", "https://bigip.example.com")
F5_USER = os.getenv("F5_USER", "admin")
F5_PASS = os.getenv("F5_PASS", "changeme")

POLICY_FILE = os.getenv("POLICY_FILE", "templates/base-waf-policy.json")


def load_policy(path: str) -> dict:
    """Load WAF policy JSON from file."""
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def upload_policy(policy: dict) -> None:
    """
    Example function to upload a WAF policy to F5 BIG-IP.

    NOTE: This is a simplified demo.
    In a real environment you should:
      - Use a service account
      - Store credentials securely (vault, env vars, etc.)
      - Handle errors and timeouts properly
    """
    url = f"{F5_HOST}/mgmt/tm/asm/policies"

    response = requests.post(
        url,
        auth=(F5_USER, F5_PASS),
        json=policy,
        verify=False,  # For demo only – use a valid certificate in production
        timeout=30,
    )

    print(f"Status code: {response.status_code}")
    try:
        print("Response:", response.json())
    except ValueError:
        print("Raw response:", response.text)


def main() -> None:
    print(f"Loading policy from: {POLICY_FILE}")
    policy = load_policy(POLICY_FILE)

    policy_name = policy.get("policy", {}).get("name", "<unknown>")
    print(f"Policy loaded: {policy_name}")

    # For safety, the actual upload is optional.
    # Uncomment the next line when you are ready to test against a lab BIG-IP.
    #
    # upload_policy(policy)


if __name__ == "__main__":
    main()
