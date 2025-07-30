```
  ><< <<    ><<            ><<<<         ><<<<   
><<    ><<  ><<         ><<    ><<     ><    ><< 
 ><<        ><<       ><<        ><<  ><<        
   ><<      ><<       ><<        ><<  ><<        
      ><<   ><<       ><<        ><<  ><<   ><<<<
><<    ><<  ><<         ><<     ><<    ><<    >< 
  ><< <<    ><<<<<<<<      ><<<<         ><<<<< ⠀
```
**slog** is a simple Python utility that was born from doing a fun little Hack the Box Sherlocks challenge. The utility helps you slog through AWS CloudTrail logs (`.json` or `.json.gz`), extracts key event information, and displays it in a human-readable, filterable, and highlightable timeline. Output is shown in a terminal table and saved to CSV.

## Features

* Parses CloudTrail JSON and JSON.GZ files recursively  
* Sorts all events chronologically  
* Filters by:
  - Username (`--user`)
  - Source IP (`--source-ip`)
  - Resource ARN or name (`--resource-contains`)
  - Action/Event name (`--action`)
* Supports flexible date/time filtering:
  - Absolute start/end time (`--start`, `--end`)
  - Relative ranges (`--last 24h`, `--last 30m`, etc.)
  - Shortcut duration after start (`--end +2`)
* Accepts dates with or without time:  
  - `YYYY-MM-DD`  
  - `YYYY-MM-DD HH:MM`  
* Supports detection of sensitive medium, high, and critical actions using (`--detect`)
* Highlights any string of interest  
* Automatically extracts meaningful fallback resource info (useful for IAM and API events)  
* Outputs to terminal and CSV

---

## 📦 Requirements

```bash
pip install pandas rich
```

---

## 🚀 Usage

```bash
python slog.py <path-to-log-files> [options]
```

### Example:

```bash
python slog.py ./logs \
  --user alice \
  --source-ip 10.0.0.5 \
  --resource-contains customerb \
  --action DeleteUser \
  --highlight arn:aws
```

---

## 🔧 Options

| Option                | Description |
|------------------------|-------------|
| `path`                | Path to CloudTrail `.json` or `.json.gz` file or directory |
| `--csv`               | Output CSV file name (default: `slog.csv`) |
| `--user`              | Filter by user name or principal ID |
| `--source-ip`         | Filter by source IP address |
| `--resource-contains` | Filter by substring match in the resource ARN or ID |
| `--action`            | Filter by event/action name (e.g. `CreateUser`, `DeleteAccessKey`) |
| `--access-key`        | Filter by access key ID |
| `--highlight`         | Highlight a string (e.g. a user, IP, action, or ARN) in the output |
| `--start`             | Start time (`YYYY-MM-DD` or `YYYY-MM-DD HH:MM`) |
| `--end`               | End time (`YYYY-MM-DD`, `YYYY-MM-DD HH:MM`, or `+N` hours after `--start`) |
| `--last`              | Use a relative time range (e.g. `30m`, `1h`, `2h`, `12h`, `24h`, `7d`) |

---

## 📄 Output

- **Terminal Table**: Formatted table of filtered and sorted events with optional highlighting
- **CSV File**: All displayed data saved to a CSV (default: `slog.csv`)

### Output Columns

- `Time`
- `User`
- `AccessKey`
- `Action`
- `SourceIP`
- `DestinationIP`
- `Resource` (auto-fallback to parameters if ARN missing)

---

## 🔍 Examples

Show all IAM-related changes:

```bash
python slog.py ./logs --resource-contains IAM
```

Highlight risky actions:

```bash
python slog.py ./logs --highlight TerminateInstances
```

Search for user activity from a specific IP:

```bash
python slog.py ./logs --user bob --source-ip 192.168.1.12
```

Last 2 hours of activity:

```bash
python slog.py ./logs --last 2h
```

All activity starting at 2024-12-01 08:00 and continuing for 2 hours:

```bash
python slog.py ./logs --start "2024-12-01 08:00" --end +2
```

---

## 📂 Output Example

```
┏━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Time                 ┃ User     ┃ AccessKey  ┃ Action            ┃ SourceIP     ┃ DestinationIP     ┃ Resource                             ┃
┡━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
┃ 2025-07-27T13:45:22Z ┃ alice    ┃ AKIA...    ┃ DeleteAccessKey   ┃ 10.0.0.1     ┃ N/A               ┃ keyId=AKIA..., userName=alice        ┃
┃ 2025-07-27T13:50:00Z ┃ admin    ┃ AKIA...    ┃ CreateUser        ┃ 10.0.0.5     ┃ N/A               ┃ CreateUser: userName=bob             ┃
└──────────────────────┴──────────┴────────────┴───────────────────┴──────────────┴───────────────────┴──────────────────────────────────────┘
```

---

## 📬 Suggestions?

Open a PR or file an issue with improvements, bug fixes, or feature requests!

---

## 🔒 Disclaimer

This script is for analysis and monitoring of AWS CloudTrail logs. Use responsibly and ensure you have the necessary permissions to access the logs you're analyzing.
