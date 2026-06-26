import boto3
import json
import datetime
from rich import print
from rich.table import Table
from rich.panel import Panel
from rich.rule import Rule
from rich import box

from s3_checker import run_s3_checks
from iam_checker import run_iam_checks

print(Panel("[bold cyan]AWS GRC Compliance Checker[/bold cyan]\n[dim]Phase 4 — Unified Compliance Report | OracleRecon[/dim]"))

def run_full_compliance_check():
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    
    print(Rule("[bold yellow]S3 Compliance Checks[/bold yellow]"))
    s3_results = run_s3_checks()
    
    print(Rule("[bold yellow]IAM Compliance Checks[/bold yellow]"))
    iam_results = run_iam_checks()
    
    print(Rule("[bold yellow]Unified Compliance Summary[/bold yellow]"))
    
    s3_passed = sum(1 for r in s3_results if r["overall"] == "PASS")
    s3_failed = sum(1 for r in s3_results if r["overall"] == "FAIL")
    
    iam_passed = sum(1 for v in iam_results.values() if v["status"] == "PASS")
    iam_failed = sum(1 for v in iam_results.values() if v["status"] == "FAIL")
    
    total_passed = s3_passed + iam_passed
    total_failed = s3_failed + iam_failed
    total_checks = total_passed + total_failed
    
    summary_table = Table(title="Overall Compliance Summary", box=box.ROUNDED)
    summary_table.add_column("Category", style="cyan")
    summary_table.add_column("Passed", style="green")
    summary_table.add_column("Failed", style="red")
    summary_table.add_column("Total", style="white")
    summary_table.add_column("Score", style="white")
    
    s3_score = f"{round((s3_passed / max(len(s3_results), 1)) * 100)}%" if s3_results else "N/A"
    iam_score = f"{round((iam_passed / max(len(iam_results), 1)) * 100)}%"
    total_score = f"{round((total_passed / max(total_checks, 1)) * 100)}%"
    
    summary_table.add_row("S3", str(s3_passed), str(s3_failed), str(len(s3_results)), s3_score)
    summary_table.add_row("IAM", str(iam_passed), str(iam_failed), str(len(iam_results)), iam_score)
    summary_table.add_row("[bold]TOTAL[/bold]", f"[bold]{total_passed}[/bold]", f"[bold]{total_failed}[/bold]", f"[bold]{total_checks}[/bold]", f"[bold]{total_score}[/bold]")
    
    print(summary_table)
    
    score_pct = round((total_passed / max(total_checks, 1)) * 100)
    if score_pct >= 80:
        score_color = "green"
        rating = "GOOD"
    elif score_pct >= 60:
        score_color = "yellow"
        rating = "NEEDS IMPROVEMENT"
    else:
        score_color = "red"
        rating = "AT RISK"
    
    print(f"\n[bold]Overall Compliance Score:[/bold] [{score_color}]{score_pct}% — {rating}[/{score_color}]")
    
    unified_report = {
        "report_type": "Unified AWS GRC Compliance Report",
        "timestamp": timestamp,
        "account": "868832438584",
        "generated_by": "OracleRecon GRC Compliance Checker",
        "s3_results": s3_results,
        "iam_results": iam_results,
        "summary": {
            "s3_passed": s3_passed,
            "s3_failed": s3_failed,
            "iam_passed": iam_passed,
            "iam_failed": iam_failed,
            "total_passed": total_passed,
            "total_failed": total_failed,
            "total_checks": total_checks,
            "compliance_score": f"{score_pct}%",
            "rating": rating
        }
    }
    
    report_filename = f"unified_report_{timestamp}.json"
    with open(report_filename, "w") as f:
        json.dump(unified_report, f, indent=2, default=str)
    
    print(f"\n[dim]Unified report saved to {report_filename}[/dim]")
    print(Panel(f"[bold green]Project 2 Complete — AWS GRC Compliance Checker[/bold green]\n[dim]OracleRecon | {timestamp}[/dim]"))

if __name__ == "__main__":
    run_full_compliance_check()