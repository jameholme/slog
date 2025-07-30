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

console = Console()

SENSITIVE_ACTIONS = {
    "DeleteBucket": ("Critical"),
    "PutBucketAcl": ("High"),
    "CreateUser": ("Critical"),
    "DeleteUser": ("Critical"),
    "AttachUserPolicy": ("Critical"),
    "DetachUserPolicy": ("Critical"),
    "CreateAccessKey": ("Critical"),
    "DeleteAccessKey": ("Critical"),
    "UpdateAccessKey": ("Critical"),
    "UpdateAssumeRolePolicy": ("Critical"),
    "CreateRole": ("High"),
    "DeleteRole": ("Critical"),
    "PutRolePolicy": ("Critical"),
    "AddUserToGroup": ("Critical"),
    "RemoveUserFromGroup": ("Critical"),
    "CreateTrail": ("High"),
    "DeleteTrail": ("High"),
    "StopLogging": ("High"),
    "StartLogging": ("High"),
    "UpdateTrail": ("High"),
    "PutUserPolicy": ("Critical"),
    "PutGroupPolicy": ("Critical"),
    "CreatePolicy": ("Critical"),
    "DeletePolicy": ("Critical"),
    "AttachRolePolicy": ("Critical"),
    "DetachRolePolicy": ("Critical"),
    "CreateLoginProfile": ("Critical"),
    "UpdateLoginProfile": ("Critical"),
    "DeleteLoginProfile": ("Critical"),
    "AssumeRole": ("Critical"),
    "PutBucketPolicy": ("Critical"),
    "PutObjectAcl": ("High"),
    "ModifySnapshotAttribute": ("Critical"),
    "AuthorizeSecurityGroupIngress": ("Critical"),
    "AuthorizeSecurityGroupEgress": ("Critical"),
    "RevokeSecurityGroupIngress": ("Critical"),
    "RevokeSecurityGroupEgress": ("Critical"),
    "PutAccountSettingDefault": ("Critical"),
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
            if detect_level in SEVERITY_COLORS:
                df = df[df["Severity"] == detect_level]

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

    for col in column_settings.keys():
        table.add_column(col, **column_settings[col])

    for _, row in df.iterrows():
        row_data = []
        for col in column_settings.keys():
            val = str(row[col]) if pd.notna(row[col]) else ""

            # Escape markup before printing to avoid Rich markup errors
            val = escape(val)

            # Special formatting for Resource: wrap long lines
            if col == "Resource" and len(val) > 60:
                val = "\n".join([val[i:i+60] for i in range(0, len(val), 60)])

            # Highlight severity tags with colors
            if col == "Severity" and val in SEVERITY_COLORS:
                color = SEVERITY_COLORS[val]
                val = f"[{color}]{val}[/{color}]"

            # Highlight user-specified string
            if col != "Severity":  # Don't override severity color
                val = highlight_text(val, highlight)

            row_data.append(val)
        table.add_row(*row_data)

    console.print(table)
    console.print(f"[green]Saved CSV output to {output_csv}[/green]")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Parse AWS CloudTrail JSON logs into timeline format.")
    parser.add_argument("path", help="Path to CloudTrail JSON file or directory")
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
    parser.add_argument("--detect", nargs='?', const='all', choices=['all', 'medium', 'high', 'critical'], help="Detect sensitive actions; optionally filter by severity")

    args = parser.parse_args()

    start_dt, end_dt = None, None

    if args.last:
        start_dt, end_dt = parse_relative_last(args.last)
    elif args.start:
        start_dt = parse_datetime_input(args.start)
        if args.end:
            if args.end.startswith("+"):
                end_dt = parse_relative_end(start_dt, args.end)
            else:
                end_dt = parse_datetime_input(args.end)

    detect_mode = False
    detect_level = None
    if args.detect:
        detect_mode = True
        if args.detect.lower() != "all":
            detect_level = args.detect.capitalize()

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
        start_time=start_dt,
        end_time=end_dt,
        detect_mode=detect_mode,
        detect_level=detect_level,
    )
