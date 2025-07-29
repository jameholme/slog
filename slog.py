import os
import json
import gzip
import pandas as pd
from rich.console import Console
from rich.table import Table
from rich.box import SIMPLE_HEAVY
from datetime import datetime
import re

console = Console()


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

        # Try to extract standard resource ARNs
        resources = record.get("resources", [])
        resource_arns = ", ".join(r.get("ARN", "") for r in resources if "ARN" in r)

        # If no ARNs, try to build fallback info from requestParameters
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

        events.append({
            "Time": event_time,
            "User": user_name,
            "AccessKey": access_key,
            "Action": event_name,
            "SourceIP": source_ip,
            "DestinationIP": dest_ip,
            "Resource": resource_arns,
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


def output_results(
    events,
    output_csv="cloudtrail_timeline.csv",
    highlight=None,
    user_filter=None,
    ip_filter=None,
    resource_filter=None,
    action_filter=None,
):
    if not events:
        console.print("[yellow]No events found.[/yellow]")
        return

    df = pd.DataFrame(events)

    # Apply filters
    if user_filter:
        df = df[df["User"].str.contains(user_filter, case=False, na=False)]

    if ip_filter:
        df = df[df["SourceIP"].str.contains(ip_filter, case=False, na=False)]

    if resource_filter:
        df = df[df["Resource"].str.contains(resource_filter, case=False, na=False)]

    if action_filter:
        df = df[df["Action"].str.contains(action_filter, case=False, na=False)]

    if df.empty:
        console.print("[yellow]No events matched the filters.[/yellow]")
        return

    df["Time"] = pd.to_datetime(df["Time"], errors="coerce")
    df.sort_values(by="Time", inplace=True)
    df.to_csv(output_csv, index=False)

    # Display a rich-formatted table
    table = Table(title="CloudTrail Timeline", box=SIMPLE_HEAVY, show_lines=True)

    column_settings = {
        "Time": {"style": "green"},
        "User": {"style": "magenta"},
        "AccessKey": {"style": "cyan"},
        "Action": {"style": "yellow"},
        "SourceIP": {"style": "blue"},
        "DestinationIP": {"style": "blue"},
        "Resource": {"style": "white", "max_width": 60},
    }

    for col in df.columns:
        settings = column_settings.get(col, {})
        table.add_column(col, **settings)

    for _, row in df.iterrows():
        row_data = []
        for col in df.columns:
            val = str(row[col]) if pd.notna(row[col]) else ""
            if col == "Resource" and len(val) > 60:
                val = "\n".join([val[i:i+60] for i in range(0, len(val), 60)])
            val = highlight_text(val, highlight)
            row_data.append(val)
        table.add_row(*row_data)

    console.print(table)
    console.print(f"[green]Saved CSV output to {output_csv}[/green]")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Parse AWS CloudTrail JSON logs into timeline format.")
    parser.add_argument("path", help="Path to CloudTrail JSON file or directory")
    parser.add_argument("--csv", help="Output CSV file name", default="cloudtrail_timeline.csv")
    parser.add_argument("--highlight", help="String to highlight in table output", default=None)
    parser.add_argument("--user", help="Filter by username or principal ID", default=None)
    parser.add_argument("--source-ip", help="Filter by source IP address", default=None)
    parser.add_argument("--resource-contains", help="Filter by substring in resource ARN(s)", default=None)
    parser.add_argument("--action", help="Filter by action/event name", default=None)

    args = parser.parse_args()

    events = process_path(args.path)
    output_results(
        events,
        output_csv=args.csv,
        highlight=args.highlight,
        user_filter=args.user,
        ip_filter=args.source_ip,
        resource_filter=args.resource_contains,
        action_filter=args.action,
    )
