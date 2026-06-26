import boto3
import json
import datetime
from rich import print
from rich.table import Table
from rich.panel import Panel
from rich import box

print(Panel("[bold cyan]AWS GRC Compliance Checker[/bold cyan]\n[dim]Phase 3 — IAM Compliance Check | OracleRecon[/dim]"))

session = boto3.Session()
iam = session.client('iam')

def check_password_policy():
    try:
        response = iam.get_account_password_policy()
        policy = response['PasswordPolicy']
        checks = {
            "min_length_8": policy.get('MinimumPasswordLength', 0) >= 8,
            "require_uppercase": policy.get('RequireUppercaseCharacters', False),
            "require_lowercase": policy.get('RequireLowercaseCharacters', False),
            "require_numbers": policy.get('RequireNumbers', False),
            "require_symbols": policy.get('RequireSymbols', False),
            "max_age_90": policy.get('MaxPasswordAge', 999) <= 90
        }
        passed = all(checks.values())
        return "PASS" if passed else "FAIL", checks
    except Exception:
        return "FAIL", {"error": "No password policy configured"}

def check_mfa_for_users():
    try:
        users = iam.list_users()['Users']
        if not users:
            return "PASS", "No IAM users found"
        
        mfa_results = []
        for user in users:
            username = user['UserName']
            mfa_devices = iam.list_mfa_devices(UserName=username)['MFADevices']
            mfa_results.append({
                "user": username,
                "mfa_enabled": len(mfa_devices) > 0
            })
        
        all_have_mfa = all(r['mfa_enabled'] for r in mfa_results)
        return "PASS" if all_have_mfa else "FAIL", mfa_results
    except Exception as e:
        return "FAIL", str(e)

def check_root_access_keys():
    try:
        response = iam.get_account_summary()
        summary = response['SummaryMap']
        root_keys = summary.get('AccountAccessKeysPresent', 0)
        return "PASS" if root_keys == 0 else "FAIL"
    except Exception:
        return "FAIL"

def check_inactive_users():
    try:
        users = iam.list_users()['Users']
        if not users:
            return "PASS", []
        
        inactive = []
        cutoff = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=90)
        
        for user in users:
            last_used = user.get('PasswordLastUsed')
            if last_used and last_used < cutoff:
                inactive.append(user['UserName'])
            elif not last_used:
                created = user['CreateDate']
                if created < cutoff:
                    inactive.append(user['UserName'])
        
        return "PASS" if not inactive else "FAIL", inactive
    except Exception as e:
        return "FAIL", str(e)

def run_iam_checks():
    print("\n[bold yellow]Running IAM Compliance Checks...[/bold yellow]\n")
    
    results = {}

    print("[dim]Checking password policy...[/dim]")
    pwd_status, pwd_details = check_password_policy()
    results['password_policy'] = {"status": pwd_status, "details": pwd_details}

    print("[dim]Checking MFA for IAM users...[/dim]")
    mfa_status, mfa_details = check_mfa_for_users()
    results['mfa'] = {"status": mfa_status, "details": mfa_details}

    print("[dim]Checking root account access keys...[/dim]")
    root_status = check_root_access_keys()
    results['root_access_keys'] = {"status": root_status}

    print("[dim]Checking for inactive users (90+ days)...[/dim]")
    inactive_status, inactive_details = check_inactive_users()
    results['inactive_users'] = {"status": inactive_status, "details": inactive_details}

    table = Table(title="IAM Compliance Report", box=box.ROUNDED)
    table.add_column("Check", style="cyan")
    table.add_column("Status", style="white")
    table.add_column("Details", style="dim")

    checks = [
        ("Password Policy", results['password_policy']['status'], "See JSON report for details"),
        ("MFA for All Users", results['mfa']['status'], str(mfa_details) if isinstance(mfa_details, str) else f"{len(mfa_details)} user(s) checked" if isinstance(mfa_details, list) else mfa_details),
        ("No Root Access Keys", results['root_access_keys']['status'], "Root account access keys check"),
        ("No Inactive Users 90d", results['inactive_users']['status'], f"{len(inactive_details)} inactive" if isinstance(inactive_details, list) else str(inactive_details))
    ]

    for check_name, status, detail in checks:
        status_style = "green" if status == "PASS" else "red"
        table.add_row(
            check_name,
            f"[{status_style}]{status}[/{status_style}]",
            detail
        )

    print(table)

    passed = sum(1 for _, s, _ in checks if s == "PASS")
    failed = sum(1 for _, s, _ in checks if s == "FAIL")

    print(f"\n[bold green]Passed:[/bold green] {passed}  [bold red]Failed:[/bold red] {failed}  [dim]Total: {len(checks)}[/dim]")

    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    report = {
        "report_type": "IAM Compliance Check",
        "timestamp": timestamp,
        "account": "868832438584",
        "results": results,
        "summary": {"passed": passed, "failed": failed, "total": len(checks)}
    }

    with open(f"iam_report_{timestamp}.json", "w") as f:
        json.dump(report, f, indent=2, default=str)

    print(f"\n[dim]Report saved to iam_report_{timestamp}.json[/dim]")
    print(Panel("[bold green]IAM Compliance Check Complete[/bold green]"))

    return results

if __name__ == "__main__":
    run_iam_checks()