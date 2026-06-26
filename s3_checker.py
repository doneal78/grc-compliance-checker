import boto3
import json
import datetime
from rich import print
from rich.table import Table
from rich.panel import Panel
from rich import box

print(Panel("[bold cyan]AWS GRC Compliance Checker[/bold cyan]\n[dim]Phase 2 — S3 Compliance Check | OracleRecon[/dim]"))

session = boto3.Session()
s3 = session.client('s3')

def check_encryption(bucket_name):
    try:
        response = s3.get_bucket_encryption(Bucket=bucket_name)
        return "PASS"
    except s3.exceptions.ClientError:
        return "FAIL"
    except Exception:
        return "FAIL"

def check_public_access(bucket_name):
    try:
        response = s3.get_public_access_block(Bucket=bucket_name)
        config = response['PublicAccessBlockConfiguration']
        if all([
            config.get('BlockPublicAcls', False),
            config.get('IgnorePublicAcls', False),
            config.get('BlockPublicPolicy', False),
            config.get('RestrictPublicBuckets', False)
        ]):
            return "PASS"
        return "FAIL"
    except Exception:
        return "FAIL"

def check_versioning(bucket_name):
    try:
        response = s3.get_bucket_versioning(Bucket=bucket_name)
        status = response.get('Status', '')
        if status == 'Enabled':
            return "PASS"
        return "FAIL"
    except Exception:
        return "FAIL"

def run_s3_checks():
    print("\n[bold yellow]Scanning S3 Buckets...[/bold yellow]\n")
    
    response = s3.list_buckets()
    buckets = response.get('Buckets', [])
    
    if not buckets:
        print("[dim]No S3 buckets found in this account.[/dim]")
        return []
    
    print(f"[dim]Found {len(buckets)} bucket(s). Running compliance checks...[/dim]\n")
    
    results = []
    
    for bucket in buckets:
        bucket_name = bucket['Name']
        
        encryption = check_encryption(bucket_name)
        public_access = check_public_access(bucket_name)
        versioning = check_versioning(bucket_name)
        
        overall = "PASS" if all(r == "PASS" for r in [encryption, public_access, versioning]) else "FAIL"
        
        results.append({
            "bucket": bucket_name,
            "encryption": encryption,
            "public_access": public_access,
            "versioning": versioning,
            "overall": overall
        })
    
    table = Table(title="S3 Compliance Report", box=box.ROUNDED)
    table.add_column("Bucket Name", style="cyan")
    table.add_column("Encryption", style="white")
    table.add_column("Public Access Blocked", style="white")
    table.add_column("Versioning", style="white")
    table.add_column("Overall", style="white")
    
    for r in results:
        enc_style = "green" if r["encryption"] == "PASS" else "red"
        pub_style = "green" if r["public_access"] == "PASS" else "red"
        ver_style = "green" if r["versioning"] == "PASS" else "red"
        overall_style = "green" if r["overall"] == "PASS" else "red"
        
        table.add_row(
            r["bucket"],
            f"[{enc_style}]{r['encryption']}[/{enc_style}]",
            f"[pub_style]{r['public_access']}[/pub_style]",
            f"[{ver_style}]{r['versioning']}[/{ver_style}]",
            f"[{overall_style}]{r['overall']}[/{overall_style}]"
        )
    
    print(table)
    
    passed = sum(1 for r in results if r["overall"] == "PASS")
    failed = sum(1 for r in results if r["overall"] == "FAIL")
    
    print(f"\n[bold green]Passed:[/bold green] {passed}  [bold red]Failed:[/bold red] {failed}  [dim]Total: {len(results)}[/dim]")
    
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    report = {
        "report_type": "S3 Compliance Check",
        "timestamp": timestamp,
        "account": "868832438584",
        "results": results,
        "summary": {"passed": passed, "failed": failed, "total": len(results)}
    }
    
    with open(f"s3_report_{timestamp}.json", "w") as f:
        json.dump(report, f, indent=2)
    
    print(f"\n[dim]Report saved to s3_report_{timestamp}.json[/dim]")
    print(Panel("[bold green]S3 Compliance Check Complete[/bold green]"))
    
    return results

if __name__ == "__main__":
    run_s3_checks()