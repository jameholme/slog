import os
import gzip
import json
import argparse
from datetime import datetime
import pandas as pd
from rich.console import Console
from rich.table import Table
from rich import box
from rich.highlighter import Highlighter

class CustomHighlighter(Highlighter):
    def __init__(self, highlight_str):
        self.highlight_str = highlight_str.lower() if highlight_str else None

    def highlight(self, text):
        if self.highlight_str and self.highlight_str in text.plain.lower():
            text.stylize("bold red", 0, len(text))

def parse_event(event):
    user_identity = event.get("userIdentity", {})
    user = user_identity.get("userName") or user_identity.get("principalId", "N/A")
    access_key = user_identity.get("accessKeyId", "N/A")
    event_time = event.get("eventTime", "N/A")
    action = event.get("eventName", "N/A")
    src_ip = event.get("sourceIPAddress", "N/A")
    dst_ip = event.get("recipientAccountId", "N/A")

    resources = event.get("resources", [])
    if resources:
        resource_str = ", ".join([r.get("ARN", r.get("resourceName", "")) for r in resources])
    else:
        params = event.get("requestParameters", {})
        if isinstance(params, dict):
            resource_str = ", ".join(f"{k}={v}" for k, v in params.items() if isinstance(v, (str, int)))
        else:
            resource_str = "N/A"

    return {
        "Time": event_time,
        "User": user,
        "AccessKey": access_key,
        "Action": action,
        "SourceIP": src_ip,
        "DestinationIP": dst_ip,
        "Resource": resource_str or "N/A"
    }

def load_events_from_file(filepath):
    events = []
    open_func = gzip.open if filepath.endswith(".gz") else open
    with open_func(filepath, "rt", encoding="utf-8") as f:
        content = json.load(f)
        for record in content.get("Records", []):
            events.append(parse_event(record))
    return events

def collect_all_events(path):
    all_events = []
    for root, _, files in os.walk(path):
        for file in files:
            if file.endswith(".json") or file.endswith(".json.gz"):
                filepath = os.path.join(root, file)
                all_events.extend(load_events_from_file(filepath))
    return sorted(all_events, key=lambda x: x["Time"])

def filter_events(events, args):
    def parse_time(t):
        if not t:
            return None
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
            try:
                return datetime.strptime(t, fmt)
            except ValueError:
                continue
        raise ValueError(f"Invalid time format: {t}")

    start = parse_time(args.start_time)
    end = parse_time(args.end_time)

    filtered = []
    for event in events:
        try:
            event_dt = datetime.strptime(event["Time"], "%Y-%m-%dT%H:%M:%SZ")
            if start and event_dt < start:
                continue
            if end and event_dt > end:
                continue
        except Exception:
            pass

        if args.user and event["User"] != args.user:
            continue
        if args.source_ip and event["SourceIP"] != args.source_ip:
            continue
        if args.resource_contains and args.resource_contains.lower() not in event["Resource"].lower():
            continue
        if args.action and args.action.lower() != event["Action"].lower():
            continue

        filtered.append(event)

    return filtered

def display_events(events, highlight):
    table = Table(show_header=True, header_style="bold cyan", box=box.MINIMAL_DOUBLE_HEAD)
    for column in ["Time", "User", "AccessKey", "Action", "SourceIP", "DestinationIP", "Resource"]:
        table.add_column(column, overflow="fold")

    highlighter = CustomHighlighter(highlight)
    for event in events:
        row = [highlighter(str(event[col])) for col in table.columns.keys()]
        table.add_row(*row)

    console = Console()
    console.print(table)

def save_to_csv(events, filename):
    df = pd.DataFrame(events)
    df.to_csv(filename, index=False)

def main():
    parser = argparse.ArgumentParser(description="slog: CloudTrail log timeline viewer")
    parser.add_argument("path", help="Path to CloudTrail .json or .json.gz files or directory")
    parser.add_argument("--csv", default="cloudtrail_timeline.csv", help="CSV output filename")
    parser.add_argument("--user", help="Filter by username or principalId")
    parser.add_argument("--source-ip", help="Filter by source IP address")
    parser.add_argument("--resource-contains", help="Filter if resource contains this substring")
    parser.add_argument("--action", help="Filter by action/event name")
    parser.add_argument("--highlight", help="Highlight a specific string in output")
    parser.add_argument("--start-time", help="Start time in YYYY-MM-DD or YYYY-MM-DD HH:MM:SS")
    parser.add_argument("--end-time", help="End time in YYYY-MM-DD or YYYY-MM-DD HH:MM:SS")
    args = parser.parse_args()

    events = collect_all_events(args.path)
    filtered = filter_events(events, args)
    display_events(filtered, args.highlight)
    save_to_csv(filtered, args.csv)

if __name__ == "__main__":
    main()
