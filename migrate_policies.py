import os
import sys
import requests
from dotenv import load_dotenv

load_dotenv()

STACK_URL_1 = os.getenv("PRISMA_CLOUD_STACK_URL_1", "").rstrip("/")
ACCESS_ID_1 = os.getenv("ACCESS_ID_1", "")
SECRET_KEY_1 = os.getenv("SECRET_KEY_1", "")

STACK_URL_2 = os.getenv("PRISMA_CLOUD_STACK_URL_2", "").rstrip("/")
ACCESS_ID_2 = os.getenv("ACCESS_ID_2", "")
SECRET_KEY_2 = os.getenv("SECRET_KEY_2", "")

MIGRATION_SUFFIX = "_AF_migration"


def authenticate(stack_url, access_id, secret_key):
    resp = requests.post(
        f"{stack_url}/login",
        json={"username": access_id, "password": secret_key},
        headers={"Content-Type": "application/json"},
    )
    resp.raise_for_status()
    token = resp.json().get("token")
    if not token:
        raise RuntimeError(f"No token returned from {stack_url}/login")
    return token


def get_auth_headers(token):
    return {
        "x-redlock-auth": token,
        "Content-Type": "application/json",
    }


def fetch_custom_policies(stack_url, token):
    resp = requests.get(
        f"{stack_url}/v2/policy",
        headers=get_auth_headers(token),
    )
    resp.raise_for_status()
    policies = resp.json()
    custom = []
    for p in policies:
        if p.get("policyMode") == "custom":
            custom.append(p)
    return custom


def fetch_policy_detail(stack_url, token, policy_id):
    resp = requests.get(
        f"{stack_url}/policy/{policy_id}",
        headers=get_auth_headers(token),
    )
    resp.raise_for_status()
    return resp.json()


def fetch_saved_search(stack_url, token, search_id):
    resp = requests.get(
        f"{stack_url}/search/history/{search_id}",
        headers=get_auth_headers(token),
    )
    resp.raise_for_status()
    return resp.json()


def build_saved_search_payload(search_data):
    READ_ONLY_FIELDS = [
        "alertId", "async", "asyncResultUrl", "cursor",
        "filters", "groupBy", "readOnly", "searchType",
        "timeGranularity",
    ]
    payload = {}
    for key, value in search_data.items():
        if key not in READ_ONLY_FIELDS:
            payload[key] = value
    payload["saved"] = True
    return payload


def create_saved_search(stack_url, token, search_id, search_data):
    payload = build_saved_search_payload(search_data)
    resp = requests.post(
        f"{stack_url}/search/history/{search_id}",
        headers=get_auth_headers(token),
        json=payload,
    )
    resp.raise_for_status()
    return resp.json()


def create_policy(stack_url, token, policy):
    resp = requests.post(
        f"{stack_url}/policy",
        headers=get_auth_headers(token),
        json=policy,
    )
    resp.raise_for_status()
    return resp.json()


def build_migration_payload(policy):
    payload = {
        "name": policy["name"] + MIGRATION_SUFFIX,
        "policyType": policy.get("policyType"),
        "severity": policy.get("severity"),
        "description": policy.get("description", ""),
        "rule": policy.get("rule"),
        "recommendation": policy.get("recommendation", ""),
        "enabled": policy.get("enabled", True),
        "labels": policy.get("labels", []),
        "complianceMetadata": policy.get("complianceMetadata", []),
    }
    if policy.get("policySubTypes"):
        payload["policySubTypes"] = policy["policySubTypes"]
    if policy.get("cloudType"):
        payload["cloudType"] = policy["cloudType"]
    return payload


def main():
    for var, name in [
        (STACK_URL_1, "PRISMA_CLOUD_STACK_URL_1"),
        (ACCESS_ID_1, "ACCESS_ID_1"),
        (SECRET_KEY_1, "SECRET_KEY_1"),
        (STACK_URL_2, "PRISMA_CLOUD_STACK_URL_2"),
        (ACCESS_ID_2, "ACCESS_ID_2"),
        (SECRET_KEY_2, "SECRET_KEY_2"),
    ]:
        if not var:
            print(f"Error: {name} is not set in .env")
            sys.exit(1)

    print("Authenticating to Tenant 1...")
    token1 = authenticate(STACK_URL_1, ACCESS_ID_1, SECRET_KEY_1)
    print("Authenticated to Tenant 1.")

    print("Authenticating to Tenant 2...")
    token2 = authenticate(STACK_URL_2, ACCESS_ID_2, SECRET_KEY_2)
    print("Authenticated to Tenant 2.")

    print("Fetching custom policies from Tenant 1...")
    custom_policies = fetch_custom_policies(STACK_URL_1, token1)
    print(f"Found {len(custom_policies)} custom policies.")

    if not custom_policies:
        print("No custom policies to migrate.")
        return

    migrated = 0
    failed = 0
    errors = []

    for policy in custom_policies:
        original_name = policy["name"]
        new_name = original_name + MIGRATION_SUFFIX
        try:
            policy_id = policy["policyId"]
            print(f"  Fetching details for {original_name} ({policy_id})...")
            full_policy = fetch_policy_detail(STACK_URL_1, token1, policy_id)

            rule = full_policy.get("rule", {})
            search_id = rule.get("criteria")
            if search_id:
                print(f"  Fetching saved search {search_id} from Tenant 1...")
                search_data = fetch_saved_search(STACK_URL_1, token1, search_id)
                print(f"  Creating saved search {search_id} in Tenant 2...")
                create_saved_search(STACK_URL_2, token2, search_id, search_data)

            payload = build_migration_payload(full_policy)
            create_policy(STACK_URL_2, token2, payload)
            print(f"  [OK] {new_name}")
            migrated += 1
        except requests.exceptions.HTTPError as e:
            detail = ""
            try:
                detail = e.response.text
            except Exception:
                pass
            print(f"  [FAIL] {new_name}: {e} - {detail}")
            errors.append((new_name, str(e), detail))
            failed += 1
        except Exception as e:
            print(f"  [FAIL] {new_name}: {e}")
            errors.append((new_name, str(e), ""))
            failed += 1

    print(f"\nMigration complete: {migrated} succeeded, {failed} failed out of {len(custom_policies)} policies.")
    if errors:
        print("\nFailed policies:")
        for name, err, detail in errors:
            print(f"  - {name}: {err}")
            if detail:
                print(f"    Detail: {detail}")


if __name__ == "__main__":
    main()
