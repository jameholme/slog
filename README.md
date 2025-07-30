```
  ><< <<    ><<            ><<<<         ><<<<   
><<    ><<  ><<         ><<    ><<     ><    ><< 
 ><<        ><<       ><<        ><<  ><<        
   ><<      ><<       ><<        ><<  ><<        
      ><<   ><<       ><<        ><<  ><<   ><<<<
><<    ><<  ><<         ><<     ><<    ><<    >< 
  ><< <<    ><<<<<<<<      ><<<<         ><<<<< ⠀
```

**slog** is a lightweight Python utility born from doing a fun little Hack the Box Sherlocks challenge designed for /slogging/ through AWS CloudTrail logs (`.json` or `.json.gz`) and identifying meaningful patterns, user activity, and potentially sensitive actions. It’s perfect for threat hunting, incident response, or general visibility across your AWS environment. Output is shown in a terminal table and saved to CSV.

---

## 🛠️ Features

- ✅ **Recursive parsing** of CloudTrail `.json` and `.json.gz` files
- 📅 **Chronologically sorted** event timeline
- 🔍 Flexible filtering:
  - Username (`--user`)
  - Source IP (`--source-ip`)
  - Action name (`--action`)
  - Resource string match (`--resource-contains`)
  - AWS Access Key (`--access-key`)
- ⏳ Smart time filtering:
  - Absolute ranges (`--start`, `--end`)
  - Relative (`--last 24h`, `--last 30m`, etc.)
  - Offset duration (`--end +2`)
- 🚨 **Action severity detection** with `--detect`
  - Default: Medium, High, Critical
  - Customizable: use `--detect low` or `--detect informational` to include lower severities
- ✨ Highlight arbitrary strings (`--highlight`) in color
- 📋 Exports results to CSV (default: `slog.csv`)
- 🧠 Fallback logic extracts resource identifiers even from obscure logs

---

## 📦 Requirements
This script relies on the following Python packages and standard libraries:
- Standard libraries (no installation needed):
  - os
  - json
  - gzip
  - datetime
  - re
  - argparse
  - textwrap
- Third-party libraries (install with pip):
  - pandas
  - rich
  - pytz
  
```bash
pip install pandas rich pytz
```

---

## 🚀 Usage

```bash

It's time to slog through some logs!

positional arguments:
  path                  Path to CloudTrail JSON file or directory

options:
  -h, --help            show this help message and exit
  --csv CSV             Output CSV file name
  --highlight HIGHLIGHT
                        String to highlight in table output
  --user USER           Filter by username or principal ID
  --source-ip SOURCE_IP
                        Filter by source IP address
  --resource-contains RESOURCE_CONTAINS
                        Filter by substring in resource ARN(s)
  --action ACTION       Filter by action/event name
  --access-key ACCESS_KEY
                        Filter by AccessKeyId
  --start START         Start time in 'YYYY-MM-DD' or 'YYYY-MM-DD HH:MM'
  --end END             End time in 'YYYY-MM-DD', 'YYYY-MM-DD HH:MM', or +N (hours)
  --last LAST           Use relative time like 7d, 24h, 30m
  --detect [{all,informational,low,medium,high,critical}]
                        Detect sensitive actions; optionally filter by severity (informational, low, medium, high, critical)

EXAMPLES:
  python script.py ./logs/cloudtrail-2023-07-30.json --csv output.csv
  python script.py ./cloudtrail_logs --highlight DeleteUser
  python script.py ./logs --user alice --last 7d
  python script.py ./logs --detect critical
  python script.py ./logs --start "2023-07-01 00:00" --end "2023-07-15 23:59"
```

---

## 🔍 Examples

Get all IAM-related activity in last 12 hours:

```bash
python slog.py ./logs --resource-contains iam --last 12h
```

See what a specific user did today:

```bash
python slog.py ./logs --user bob --start 2025-07-30
```

Highlight a suspicious IP:

```bash
python slog.py ./logs --highlight 192.168.1.5
```

Show only critical actions:

```bash
python slog.py ./logs --detect critical
```

---

## 🧪 Sample Output

```
┏━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━┓
┃ Time                 ┃ User     ┃ AccessKey  ┃ Action            ┃ SourceIP     ┃ DestinationIP     ┃ Resource                             ┃ Severity  ┃
┡━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━┩
┃ 2025-07-27T13:45:22Z ┃ alice    ┃ AKIA...    ┃ DeleteAccessKey   ┃ 10.0.0.1     ┃ N/A               ┃ keyId=AKIA..., userName=alice        ┃ Critical  ┃
┃ 2025-07-27T13:50:00Z ┃ admin    ┃ AKIA...    ┃ CreateUser        ┃ 10.0.0.5     ┃ N/A               ┃ CreateUser: userName=bob             ┃ Critical  ┃
└──────────────────────┴──────────┴────────────┴───────────────────┴──────────────┴───────────────────┴──────────────────────────────────────┴───────────┘
```

---

## 📬 Contribute

Open a PR or file an issue with improvements, bug fixes, or feature requests!

---

## ⚠️ Disclaimer

This script is for analysis and monitoring of AWS CloudTrail logs. Use responsibly and ensure you have the necessary permissions to access the logs you're analyzing.
