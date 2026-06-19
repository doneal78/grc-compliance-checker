import boto3
import json
from rich import print
from rich.panel import Panel

print(Panel("[bold cyan]AWS GRC Compliance Checker[/bold cyan]\n[dim]Phase 1 — Connection Test | OracleRecon[/dim]"))

session = boto3.Session()

sts = session.client('sts')
identity = sts.get_caller_identity()

account_id = identity['Account']
user_arn = identity['Arn']
user_id = identity['UserId']

print("\n[bold green]Connection Successful[/bold green]")
print(f"\n[cyan]Account ID:[/cyan]  {account_id}")
print(f"[cyan]User ARN:[/cyan]    {user_arn}")
print(f"[cyan]User ID:[/cyan]     {user_id}")

print(f"\n[dim]boto3 version: {boto3.__version__}[/dim]")
print(Panel("[bold green]Phase 1 Complete — Python is connected to AWS[/bold green]"))