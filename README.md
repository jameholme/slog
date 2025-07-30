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
python slog.py ./cloudtrail-logs \
  --user alice \
  --source-ip 10.0.0.5 \
  --action DeleteUser \
  --resource-contains iam \
  --highlight AKIA \
  --detect
```

---

## 🔧 Options

| Option                | Description |
|------------------------|-------------|
| `path`                | Path to CloudTrail file or directory |
| `--csv`               | Output CSV filename (default: `slog.csv`) |
| `--user`              | Filter by username or principal ID |
| `--source-ip`         | Filter by source IP |
| `--action`            | Filter by specific action name |
| `--resource-contains` | Filter by partial match in resource name or ARN |
| `--access-key`        | Filter by AWS Access Key ID |
| `--highlight`         | Highlight a term (user, action, IP, etc.) |
| `--start`             | Start date/time (`YYYY-MM-DD` or `YYYY-MM-DD HH:MM`) |
| `--end`               | End time or offset (e.g. `+2` for 2 hours after `--start`) |
| `--last`              | Show logs from the past `N` (`30m`, `2h`, `7d`, etc.) |
| `--detect [level]`    | Show only sensitive actions. Optional level: `medium`, `high`, `critical`, `low`, `informational`. Default: Medium+ |

---

## 🔒 Detection Severity Defaults

When using `--detect` **without a level**, only these are shown:
- `Medium`
- `High`
- `Critical`

To show additional levels:

```bash
--detect low
--detect informational
```

To show just one level:

```bash
--detect high
```

---

## 🧾 Output

- 📊 **Terminal Table**: Filtered and color-highlighted table
- 📄 **CSV Export**: Same data, saved as `slog.csv` (unless overridden)

### Columns

- `Time`
- `User`
- `AccessKey`
- `Action`
- `SourceIP`
- `DestinationIP`
- `Resource`

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
