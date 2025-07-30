import os
import json
import gzip
import pandas as pd
from rich.console import Console
from rich.table import Table
from rich.box import SIMPLE_HEAVY
from datetime import datetime, timedelta
import re
import pytz
import argparse
from rich.markup import escape
import textwrap

console = Console()

SENSITIVE_ACTIONS = {
# Critical
"AddUserToGroup": ("Critical"),
"AssumeRole": ("Critical"),
"AttachRolePolicy": ("Critical"),
"AttachUserPolicy": ("Critical"),
"AuthorizeSecurityGroupEgress": ("Critical"),
"AuthorizeSecurityGroupIngress": ("Critical"),
"CreateAccessKey": ("Critical"),
"CreateLoginProfile": ("Critical"),
"CreatePolicy": ("Critical"),
"CreateUser": ("Critical"),
"DeleteAccessKey": ("Critical"),
"DeleteLoginProfile": ("Critical"),
"DeletePolicy": ("Critical"),
"DeleteRole": ("Critical"),
"DeleteTrail": ("Critical"),
"DeleteUser": ("Critical"),
"DetachRolePolicy": ("Critical"),
"DetachUserPolicy": ("Critical"),
"ModifySnapshotAttribute": ("Critical"),
"PutBucketPolicy": ("Critical"),
"PutGroupPolicy": ("Critical"),
"PutRolePolicy": ("Critical"),
"PutUserPolicy": ("Critical"),
"RevokeSecurityGroupEgress": ("Critical"),
"RevokeSecurityGroupIngress": ("Critical"),
"StopLogging": ("Critical"),
"UpdateAccessKey": ("Critical"),
"UpdateAssumeRolePolicy": ("Critical"),
"UpdateLoginProfile": ("Critical"),
"PutAccountSettingDefault": ("Critical"),
# High
"CreatePolicy": ("High"),
"CreateRole": ("High"),
"CreateTrail": ("High"),
"DeletePolicy": ("High"),
"DeleteRole": ("High"),
"DeleteTrail": ("High"),
"PutBucketAcl": ("High"),
"PutObjectAcl": ("High"),
"RemoveUserFromGroup": ("High"),
"StartLogging": ("High"),
"StopLogging": ("High"),
"UpdateTrail": ("High"),
# Medium
"DescribeInstances": ("Medium"),
"DescribeSecurityGroups": ("Medium"),
"GenerateServiceLastAccessedDetails": ("Medium"),
"GetBucketAcl": ("Medium"),
"GetBucketPolicy": ("Medium"),
"GetObject": ("Medium"),
"ListAccessKeys": ("Medium"),
"ListBuckets": ("Medium"),
"ListGroups": ("Medium"),
"ListObjects": ("Medium"),
"ListRoles": ("Medium"),
"ListUsers": ("Medium"),
# Low
"GetAccountSummary": ("Low"),
"GetCallerIdentity": ("Low"),
"GetGroup": ("Low"),
"GetLoginProfile": ("Low"),
"GetPolicy": ("Low"),
"GetRole": ("Low"),
"GetUser": ("Low"),
"ListAccountAliases": ("Low"),
"ListAttachedRolePolicies": ("Low"),
"ListAttachedUserPolicies": ("Low"),
"ListPolicyVersions": ("Low"),
"ListRolePolicies": ("Low"),
"ListUserPolicies": ("Low"),
# Informational
"DescribeAvailabilityZones": ("Informational"),
"DescribeLogGroups": ("Informational"),
"DescribeRegions": ("Informational"),
"DescribeTrails": ("Informational"),
"GetEventSelectors": ("Informational"),
"GetMetricData": ("Informational"),
"GetMetricStatistics": ("Informational"),
"GetResourcePolicy": ("Informational"),
"ListMetrics": ("Informational"),
"ListTagsForResource": ("Informational"),
"LookupEvents": ("Informational"),
}

SEVERITY_COLORS = {
    "Medium": "yellow",
    "High": "orange3",
    "Critical": "red",
}

def read_json_file(filepath):
    try:
        if filepath.endswith(".gz"):
            with gzip.open(filepath, 'rt', encoding='utf-8') as f:
                return json.load(f)
        else:
            with open(filepath, 'r', encoding='utf-8') as f:
                return json.load(f)
    except Exception as e:
        console.print(f"[red]Failed to read {filepath}: {e}[/red]")
        return None

def extract_events(data):
    events = []
    records = data.get("Records", []) if isinstance(data, dict) else []

    for record in records:
        event_time = record.get("eventTime")
        user_identity = record.get("userIdentity", {})
        user_name = user_identity.get("userName") or user_identity.get("principalId", "Unknown")
        access_key = record.get("accessKeyId", "N/A")
        event_name = record.get("eventName")
        source_ip = record.get("sourceIPAddress", "N/A")
        dest_ip = record.get("destinationIPAddress", "N/A")

        resources = record.get("resources", [])
        resource_arns = ", ".join(r.get("ARN", "") for r in resources if "ARN" in r)

        if not resource_arns:
            request_params = record.get("requestParameters", {})
            fallback_parts = []
            if isinstance(request_params, dict):
                for k, v in request_params.items():
                    if isinstance(v, (str, int, float)):
                        fallback_parts.append(f"{k}={v}")
                    elif isinstance(v, dict) and "arn" in v:
                        fallback_parts.append(f"{k}={v['arn']}")
            if fallback_parts:
                resource_arns = f"{event_name}: " + ", ".join(fallback_parts)
            else:
                resource_arns = f"{event_name}: No resource details"

        errors_or_output = []
        if "errorMessage" in record:
            errors_or_output.append(f"ErrorMessage={record['errorMessage']}")
        if "errorCode" in record:
            errors_or_output.append(f"ErrorCode={record['errorCode']}")
        if "responseElements" in record:
            resp = record["responseElements"]
            if isinstance(resp, dict):
                try:
                    errors_or_output.append(f"ResponseElements={json.dumps(resp)}")
                except Exception:
                    pass

        if errors_or_output:
            resource_arns += "\n" + "\n".join(errors_or_output)

        # Determine severity
        severity = None
        for action, (sev) in SENSITIVE_ACTIONS.items():
            if action.lower() == event_name.lower():
                severity = sev
                break

        events.append({
            "Time": event_time,
            "User": user_name,
            "AccessKey": access_key,
            "Action": event_name,
            "SourceIP": source_ip,
            "DestinationIP": dest_ip,
            "Resource": resource_arns,
            "Severity": severity or "",
        })

    return events

def process_path(path):
    all_events = []

    if os.path.isfile(path):
        data = read_json_file(path)
        if data:
            all_events.extend(extract_events(data))
    elif os.path.isdir(path):
        for root, _, files in os.walk(path):
            for name in files:
                if name.endswith(".json") or name.endswith(".json.gz"):
                    file_path = os.path.join(root, name)
                    data = read_json_file(file_path)
                    if data:
                        all_events.extend(extract_events(data))
    else:
        console.print(f"[red]Path not found: {path}[/red]")

    return all_events

def highlight_text(text, highlight_string):
    if not highlight_string or not text:
        return text
    try:
        pattern = re.escape(highlight_string)
        return re.sub(
            pattern,
            f"[bold red]\\g<0>[/bold red]",
            text,
            flags=re.IGNORECASE
        )
    except Exception:
        return text

def parse_datetime_input(time_str):
    formats = ["%Y-%m-%d %H:%M", "%Y-%m-%d"]
    for fmt in formats:
        try:
            dt = datetime.strptime(time_str, fmt)
            return dt.replace(tzinfo=pytz.UTC)
        except ValueError:
            continue
    console.print(f"[red]Invalid time format: {time_str}. Use 'YYYY-MM-DD' or 'YYYY-MM-DD HH:MM'[/red]")
    return None

def parse_relative_last(last_str):
    now = datetime.now(pytz.UTC)
    match = re.match(r'^(\d+)([dhm])$', last_str)
    if not match:
        console.print(f"[red]Invalid --last format. Use like '7d', '24h', or '30m'.[/red]")
        return None, None

    value, unit = int(match.group(1)), match.group(2)
    if unit == "d":
        start = now - timedelta(days=value)
    elif unit == "h":
        start = now - timedelta(hours=value)
    elif unit == "m":
        start = now - timedelta(minutes=value)
    else:
        return None, None

    return start, now

def parse_relative_end(start_dt, end_str):
    if not end_str.startswith("+"):
        return None
    try:
        hours = int(end_str[1:])
        if not (1 <= hours <= 72):
            raise ValueError
        return start_dt + timedelta(hours=hours)
    except:
        console.print("[red]--end +N must be a number between 1 and 72[/red]")
        return None

def output_results(
    events,
    output_csv="slog.csv",
    highlight=None,
    user_filter=None,
    ip_filter=None,
    resource_filter=None,
    action_filter=None,
    access_key_filter=None,
    start_time=None,
    end_time=None,
    detect_mode=False,
    detect_level=None,
):
    if not events:
        console.print("[yellow]No events found.[/yellow]")
        return

    df = pd.DataFrame(events)
    df["Time"] = pd.to_datetime(df["Time"], utc=True, errors="coerce")

    if start_time:
        df = df[df["Time"] >= start_time]
    if end_time:
        df = df[df["Time"] <= end_time]

    if user_filter:
        df = df[df["User"].str.contains(user_filter, case=False, na=False)]

    if ip_filter:
        df = df[df["SourceIP"].str.contains(ip_filter, case=False, na=False)]

    if resource_filter:
        df = df[df["Resource"].str.contains(resource_filter, case=False, na=False)]

    if action_filter:
        df = df[df["Action"].str.contains(action_filter, case=False, na=False)]

    if access_key_filter:
        df = df[df["AccessKey"].str.contains(access_key_filter, case=False, na=False)]

    if detect_mode:
        # Filter only sensitive actions
        df = df[df["Severity"] != ""]

        if detect_level:
            detect_level = detect_level.capitalize()
            if detect_level in ["Medium", "High", "Critical", "Low", "Informational"]:
                df = df[df["Severity"] == detect_level]
        else:
            df = df[df["Severity"].isin(["Medium", "High", "Critical"])]

    if df.empty:
        console.print("[yellow]No events matched the filters.[/yellow]")
        return

    df.sort_values(by="Time", inplace=True)
    df.to_csv(output_csv, index=False)

    table = Table(title="CloudTrail Timeline", box=SIMPLE_HEAVY, show_lines=True)

    column_settings = {
        "Time": {"style": "green"},
        "User": {"style": "magenta"},
        "AccessKey": {"style": "cyan"},
        "Action": {"style": "yellow"},
        "SourceIP": {"style": "blue"},
        "DestinationIP": {"style": "blue"},
        "Resource": {"style": "white", "max_width": 60},
        "Severity": {},
    }

    for col, opts in column_settings.items():
        if "max_width" in opts:
            table.add_column(col, style=opts.get("style", None), max_width=opts["max_width"], overflow="fold")
        else:
            table.add_column(col, style=opts.get("style", None))

    for _, row in df.iterrows():
        severity = row["Severity"]
        sev_color = SEVERITY_COLORS.get(severity, None)
        sev_text = severity
        if sev_color:
            sev_text = f"[bold {sev_color}]{severity}[/bold {sev_color}]"

        resource_text = row["Resource"]
        if highlight:
            resource_text = highlight_text(resource_text, highlight)

        table.add_row(
            row["Time"].strftime("%Y-%m-%d %H:%M:%S"),
            row["User"],
            row["AccessKey"],
            row["Action"],
            row["SourceIP"],
            row["DestinationIP"],
            resource_text,
            sev_text
        )

    console.print(table)
    console.print(f"[green]CSV output saved to: {output_csv}[/green]")

def print_help():
    help_text = """
    AWS CloudTrail JSON Log Parser

    This script processes AWS CloudTrail JSON or gzipped JSON log files or directories
    and extracts event timelines. It highlights sensitive actions based on predefined
    severity levels, filters by user, IP, time, and more, and outputs the result as
    a colored terminal table and a CSV file.

    USAGE:
      python script.py PATH [options]

    REQUIRED ARGUMENTS:
      PATH                Path to CloudTrail JSON file or directory containing JSON(.gz) files

    OPTIONAL ARGUMENTS:
      --csv FILE          Output CSV filename (default: slog.csv)
      --highlight STR     String to highlight in the output table
      --user USER         Filter events by username or principal ID
      --source-ip IP      Filter by source IP address
      --resource-contains STR  Filter by substring in resource ARNs
      --action ACTION     Filter by event/action name
      --access-key KEY    Filter by AWS Access Key ID
      --start TIME        Start time filter, format 'YYYY-MM-DD' or 'YYYY-MM-DD HH:MM'
      --end TIME          End time filter, format 'YYYY-MM-DD', 'YYYY-MM-DD HH:MM', or relative '+N' hours
      --last DURATION     Relative time filter like '7d' (days), '24h' (hours), or '30m' (minutes)
      --detect [LEVEL]    Enable detection of sensitive actions.
                         LEVEL is optional and can be: all, medium, high, critical.
                         Default is 'all'.

    EXAMPLES:
      # Parse single file and output CSV
      python script.py ./logs/cloudtrail-2023-07-30.json --csv output.csv

      # Parse directory, highlight 'DeleteUser' in output
      python script.py ./cloudtrail_logs --highlight DeleteUser

      # Filter events for user 'alice' in the last 7 days
      python script.py ./logs --user alice --last 7d

      # Detect only critical sensitive actions
      python script.py ./logs --detect critical

      # Filter events between specific times
      python script.py ./logs --start "2023-07-01 00:00" --end "2023-07-15 23:59"

    NOTES:
      - Time inputs are in UTC.
      - Use --last for relative time ranges (e.g., 7d = last 7 days).
      - Sensitive actions are based on known AWS IAM and CloudTrail actions.
      - Outputs CSV by default to 'slog.csv' if --csv is not provided.

    For detailed filtering options, use --help.
    """
    console.print(textwrap.dedent(help_text))

def main():
    parser = argparse.ArgumentParser(
        description="It's time to slog through some logs!",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""
        EXAMPLES:
          python script.py ./logs/cloudtrail-2023-07-30.json --csv output.csv
          python script.py ./cloudtrail_logs --highlight DeleteUser
          python script.py ./logs --user alice --last 7d
          python script.py ./logs --detect critical
          python script.py ./logs --start "2023-07-01 00:00" --end "2023-07-15 23:59"
        """)
    )
    parser.add_argument("path", nargs='?', help="Path to CloudTrail JSON file or directory")
    parser.add_argument("--csv", help="Output CSV file name", default="slog.csv")
    parser.add_argument("--highlight", help="String to highlight in table output", default=None)
    parser.add_argument("--user", help="Filter by username or principal ID", default=None)
    parser.add_argument("--source-ip", help="Filter by source IP address", default=None)
    parser.add_argument("--resource-contains", help="Filter by substring in resource ARN(s)", default=None)
    parser.add_argument("--action", help="Filter by action/event name", default=None)
    parser.add_argument("--access-key", help="Filter by AccessKeyId", default=None)
    parser.add_argument("--start", help="Start time in 'YYYY-MM-DD' or 'YYYY-MM-DD HH:MM'", default=None)
    parser.add_argument("--end", help="End time in 'YYYY-MM-DD', 'YYYY-MM-DD HH:MM', or +N (hours)", default=None)
    parser.add_argument("--last", help="Use relative time like 7d, 24h, 30m", default=None)
    parser.add_argument("--detect", nargs='?', const='all', choices=['all', 'informational', 'low', 'medium', 'high', 'critical'], help="Detect sensitive actions; optionally filter by severity (informational, low, medium, high, critical)")

    args = parser.parse_args()

    if not args.path:
        print_help()
        exit(1)

    start_time = None
    end_time = None

    if args.last:
        start_time, end_time = parse_relative_last(args.last)
        if not start_time:
            exit(1)
    else:
        if args.start:
            start_time = parse_datetime_input(args.start)
            if not start_time:
                exit(1)
        if args.end:
            if args.end.startswith("+") and start_time:
                end_time = parse_relative_end(start_time, args.end)
                if not end_time:
                    exit(1)
            else:
                end_time = parse_datetime_input(args.end)
                if not end_time:
                    exit(1)

    events = process_path(args.path)

    output_results(
        events,
        output_csv=args.csv,
        highlight=args.highlight,
        user_filter=args.user,
        ip_filter=args.source_ip,
        resource_filter=args.resource_contains,
        action_filter=args.action,
        access_key_filter=args.access_key,
        start_time=start_time,
        end_time=end_time,
        detect_mode=bool(args.detect),
        detect_level=args.detect if args.detect != "all" else None,
    )

if __name__ == "__main__":
    main()
