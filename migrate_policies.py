import os
import sys
import time
from datetime import datetime
import requests
from dotenv import load_dotenv

load_dotenv()

LOG_FILE = None


def setup_logging():
    global LOG_FILE
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_filename = f"migration_{timestamp}.log"
    LOG_FILE = open(log_filename, "w")
    log(f"Logging to {log_filename}")


def log(message):
    print(message)
    if LOG_FILE:
        LOG_FILE.write(message + "\n")
        LOG_FILE.flush()


STACK_URL_1 = os.getenv("PRISMA_CLOUD_STACK_URL_1", "").rstrip("/")
ACCESS_ID_1 = os.getenv("ACCESS_ID_1", "")
SECRET_KEY_1 = os.getenv("SECRET_KEY_1", "")

STACK_URL_2 = os.getenv("PRISMA_CLOUD_STACK_URL_2", "").rstrip("/")
ACCESS_ID_2 = os.getenv("ACCESS_ID_2", "")
SECRET_KEY_2 = os.getenv("SECRET_KEY_2", "")

MIGRATION_SUFFIX = "_AF_migration"
TOKEN_REFRESH_SECONDS = 8 * 60  # refresh before 10-minute expiry


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


class TokenManager:
    def __init__(self, stack_url, access_id, secret_key):
        self.stack_url = stack_url
        self.access_id = access_id
        self.secret_key = secret_key
        self.token = None
        self.issued_at = 0

    def get_token(self):
        if (
            self.token is None
            or (time.time() - self.issued_at) >= TOKEN_REFRESH_SECONDS
        ):
            log(f"  Refreshing token for {self.stack_url}...")
            self.token = authenticate(self.stack_url, self.access_id, self.secret_key)
            self.issued_at = time.time()
        return self.token


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
        "alertId",
        "async",
        "asyncResultUrl",
        "cursor",
        "filters",
        "groupBy",
        "readOnly",
        "searchType",
        "timeGranularity",
    ]
    payload = {}
    for key, value in search_data.items():
        if key not in READ_ONLY_FIELDS:
            payload[key] = value
    payload["saved"] = True
    return payload


def run_search_on_tenant(stack_url, token, query, time_range):
    resp = requests.post(
        f"{stack_url}/search/config",
        headers=get_auth_headers(token),
        json={"query": query, "timeRange": time_range},
    )
    if resp.status_code != 200:
        log(f"  DEBUG run_search status: {resp.status_code}")
        log(f"  DEBUG run_search headers: {dict(resp.headers)}")
        log(f"  DEBUG run_search body: {resp.text}")
    resp.raise_for_status()
    return resp.json()


def save_search(stack_url, token, search_id, name, query, time_range):
    payload = {
        "name": name,
        "query": query,
        "timeRange": time_range,
        "saved": True,
    }
    resp = requests.post(
        f"{stack_url}/search/history/{search_id}",
        headers=get_auth_headers(token),
        json=payload,
    )
    if resp.status_code == 400:
        status_header = resp.headers.get("x-redlock-status", "")
        if "duplicate_search_name" in status_header:
            log(f"  Saved search '{name}' already exists, looking up existing ID...")
            existing_id = find_saved_search_by_name(stack_url, token, name)
            if existing_id:
                return {"id": existing_id}
            log(
                f"  WARNING: Could not find existing saved search by name, using current ID"
            )
            return {"id": search_id}
    if resp.status_code != 200:
        log(f"  DEBUG save_search status: {resp.status_code}")
        log(f"  DEBUG save_search headers: {dict(resp.headers)}")
        log(f"  DEBUG save_search body: {resp.text}")
    resp.raise_for_status()
    return resp.json()


def find_saved_search_by_name(stack_url, token, name):
    resp = requests.get(
        f"{stack_url}/search/history",
        headers=get_auth_headers(token),
        params={"filter": "saved"},
    )
    resp.raise_for_status()
    for search in resp.json():
        if search.get("name") == name:
            return search.get("id")
    return None


def create_policy(stack_url, token, policy):
    import json

    log(f"  DEBUG policy payload keys: {list(policy.keys())}")
    log(f"  DEBUG policy payload: {json.dumps(policy, indent=2, default=str)}")
    resp = requests.post(
        f"{stack_url}/policy",
        headers=get_auth_headers(token),
        json=policy,
    )
    if resp.status_code != 200:
        log(f"  DEBUG create_policy status: {resp.status_code}")
        log(f"  DEBUG create_policy headers: {dict(resp.headers)}")
        log(f"  DEBUG create_policy response: {resp.text}")
    resp.raise_for_status()
    return resp.json()


def update_rule_for_migration(rule, original_name, new_name):
    import copy

    rule = copy.deepcopy(rule)
    if rule.get("name") == original_name:
        rule["name"] = new_name
    children = rule.get("children", [])
    for child in children:
        metadata = child.get("metadata", {})
        code = metadata.get("code")
        if code and original_name in code:
            metadata["code"] = code.replace(original_name, new_name)
    return rule


def build_migration_payload(policy):
    original_name = policy["name"]
    new_name = original_name + MIGRATION_SUFFIX
    rule = policy.get("rule")
    if rule:
        rule = update_rule_for_migration(rule, original_name, new_name)
    payload = {
        "name": new_name,
        "policyType": policy.get("policyType"),
        "severity": policy.get("severity"),
        "description": policy.get("description", ""),
        "rule": rule,
        "recommendation": policy.get("recommendation", ""),
        "enabled": policy.get("enabled", True),
        "labels": policy.get("labels", []),
        "complianceMetadata": [],
    }
    if policy.get("policySubTypes"):
        payload["policySubTypes"] = policy["policySubTypes"]
    if policy.get("cloudType"):
        payload["cloudType"] = policy["cloudType"]
    return payload


def main():
    setup_logging()

    for var, name in [
        (STACK_URL_1, "PRISMA_CLOUD_STACK_URL_1"),
        (ACCESS_ID_1, "ACCESS_ID_1"),
        (SECRET_KEY_1, "SECRET_KEY_1"),
        (STACK_URL_2, "PRISMA_CLOUD_STACK_URL_2"),
        (ACCESS_ID_2, "ACCESS_ID_2"),
        (SECRET_KEY_2, "SECRET_KEY_2"),
    ]:
        if not var:
            log(f"Error: {name} is not set in .env")
            sys.exit(1)

    tm1 = TokenManager(STACK_URL_1, ACCESS_ID_1, SECRET_KEY_1)
    tm2 = TokenManager(STACK_URL_2, ACCESS_ID_2, SECRET_KEY_2)

    log("Authenticating to Tenant 1...")
    tm1.get_token()
    log("Authenticated to Tenant 1.")

    log("Authenticating to Tenant 2...")
    tm2.get_token()
    log("Authenticated to Tenant 2.")

    log("Fetching custom policies from Tenant 1...")
    custom_policies = fetch_custom_policies(STACK_URL_1, tm1.get_token())
    log(f"Found {len(custom_policies)} custom policies.")

    if not custom_policies:
        log("No custom policies to migrate.")
        return

    log("Fetching existing policies from Tenant 2...")
    existing_policies_t2 = fetch_custom_policies(STACK_URL_2, tm2.get_token())
    existing_names_t2 = set()
    for p in existing_policies_t2:
        existing_names_t2.add(p.get("name", ""))
    log(f"Found {len(existing_names_t2)} existing custom policies in Tenant 2.")

    migrated = 0
    skipped = 0
    failed = 0
    errors = []

    for policy in custom_policies:
        original_name = policy["name"]
        new_name = original_name + MIGRATION_SUFFIX
        try:
            # import ipdb
            # ipdb.set_trace()
            # if policy.get("policySubTypes") != ["run"]:
            #     continue
            if new_name in existing_names_t2:
                log(f"  [SKIP] {new_name} already exists in Tenant 2.")
                skipped += 1
                continue
            policy_id = policy["policyId"]
            log(f"  Fetching details for {original_name} ({policy_id})...")
            full_policy = fetch_policy_detail(STACK_URL_1, tm1.get_token(), policy_id)

            rule = full_policy.get("rule", {})
            search_id = rule.get("criteria")
            if search_id:
                log(f"  Fetching saved search {search_id} from Tenant 1...")
                search_data = fetch_saved_search(
                    STACK_URL_1, tm1.get_token(), search_id
                )
                query = search_data.get("query", "")
                time_range = search_data.get(
                    "timeRange",
                    {"type": "relative", "value": {"unit": "hour", "amount": 24}},
                )
                log(f"  Running search query on Tenant 2...")
                search_result = run_search_on_tenant(
                    STACK_URL_2, tm2.get_token(), query, time_range
                )
                new_search_id = search_result.get("id", search_id)
                search_name = search_data.get("name") or (
                    original_name + MIGRATION_SUFFIX
                )
                log(f"  Saving search {new_search_id} in Tenant 2...")
                save_result = save_search(
                    STACK_URL_2,
                    tm2.get_token(),
                    new_search_id,
                    search_name,
                    query,
                    time_range,
                )
                final_search_id = save_result.get("id", new_search_id)
                rule["criteria"] = final_search_id

            payload = build_migration_payload(full_policy)
            create_policy(STACK_URL_2, tm2.get_token(), payload)
            log(f"  [OK] {new_name}")
            migrated += 1
        except requests.exceptions.HTTPError as e:
            detail = ""
            try:
                detail = e.response.text
            except Exception:
                pass
            log(f"  [FAIL] {new_name}: {e} - {detail}")
            errors.append((new_name, str(e), detail))
            failed += 1
        except Exception as e:
            log(f"  [FAIL] {new_name}: {e}")
            errors.append((new_name, str(e), ""))
            failed += 1

    log(
        f"\nMigration complete: {migrated} succeeded, {skipped} skipped, {failed} failed out of {len(custom_policies)} policies."
    )
    if errors:
        log("\nFailed policies:")
        for name, err, detail in errors:
            log(f"  - {name}: {err}")
            if detail:
                log(f"    Detail: {detail}")


if __name__ == "__main__":
    main()
