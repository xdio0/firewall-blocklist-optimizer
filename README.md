# Firewall Blocklist Aggregator & Optimizer

A Node.js script designed to automate the process of downloading, parsing, validating, optimizing, and consolidates IP and domain blocklists from multiple remote sources. The output files are formatted and optimized for ingestion by firewalls (such as FortiGate) and other network security appliances.

## Features

- **Multi-Source Fetching**: Parallel downloading of blocklists from multiple remote servers specified in a CSV format.
- **Failover & Caching**: Local caching of downloaded files. If a download fails, the script falls back to the last successfully cached version and tracks consecutive failures.
- **Robust Parsing & Categorization**:
  - Classifies entries into IPv4, IPv6, Subnets (CIDR), Domains, Cisco Access Control Lists (ACL), and comments.
  - Automatically translates Cisco-style denial access lists (`access-list deny ip ...`) into CIDR notation.
- **High-Performance Optimization**:
  - Automatically merges contiguous IP addresses into minimal CIDR networks.
  - Removes redundant networks (overlapping subnets).
  - Uses binary search to filter out individual IPs that are already covered by optimized CIDR subnets.
- **Allowlisting**: Supports custom exclusion lists (`allowlist.txt`) to ensure critical domains or internal IPs are never blocked.
- **Output Pagination**: Splits output lists (`ipsXX.txt`, `netsXX.txt`, `domainsXX.txt`) into multiple parts when they exceed a configurable line limit.
- **Atomic File Writing**: Uses temporary directories and atomic operations to prevent output corruption during processing.
- **Detailed Reporting**: Generates a processing summary (`resume.txt`) with statistical breakdowns per source URL.

---

## File Structure

```text
├── downloads/             # Temporary folder for current downloads
├── downloads_cache/       # Cache containing last successful downloads
├── allowlist.txt          # IPs and domains to exclude from blocking
├── config.txt             # Configuration file (output path, line limit)
├── urls.csv               # Semicolon-separated file containing target URLs and download status
├── firewall.js            # Main script execution entry point
├── package.json           # Node dependencies and scripts
└── README.md              # This file
```

---

## Setup & Configuration

### Prerequisites
- [Node.js](https://nodejs.org/) (v16.0.0 or higher recommended)

### Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/xdio0/firewall-blocklist-optimizer.git
   cd firewall-blocklist-optimizer
   ```
2. Install dependencies:
   ```bash
   npm install
   ```

### Configuration Files

#### 1. `config.txt`
Define the main configurations of the optimizer:
```ini
# Output folder for the processed list files
outputWebDir=C:\\SYS\\www\\firewall_rules

# Maximum lines per output file (useful for firewall import limits). If 0, limits are disabled.
maxLinesPerFile=130000
```

#### 2. `allowlist.txt`
Specify domains or IPs that should be exempt from the blocklists. Comments starting with `#` are supported:
```text
# Exclude my business website
example-safe-domain.com

# Exclude trusted remote branch IP
203.0.113.10
```

#### 3. `urls.csv`
Add the raw blocklist URLs you want to fetch and parse:
```csv
https://rules.emergingthreats.net/blockrules/compromised-ips.txt
https://v.firebog.net/hosts/static/w3kbl.txt
```
*Note: The script automatically appends download status and last modified timestamps to this CSV file after running.*

> [!IMPORTANT]
> **Blocklist URLs Notice:** The default sources included in `urls.csv` are provided for demonstration purposes only. They may not be fully optimized, up-to-date, or suitable for your specific security and production needs. Please review and update this file with blocklist providers that align with your organization's policies, licenses, and security standards.

---

## Usage

Run the main processor script:
```bash
node firewall.js
```

### Outputs

All results are saved in the directory specified by `outputWebDir` in `config.txt`:
- `ips01.txt`, `ips02.txt` ...: Optimized IPv4 addresses.
- `nets01.txt`, `nets02.txt` ...: Optimized subnets (CIDR format).
- `domains01.txt`, `domains02.txt` ...: Aggregated domain names.
- `invalid.txt`: Listing of lines that could not be parsed.
- `resume.txt`: A detailed run report showing processed metrics and statistics per list provider.

### Automation & Scheduling

To automate blocklist updates, you can run this script as a scheduled task (e.g., via `cron` in Linux/Unix or **Task Scheduler** in Windows). 

Please observe the following guidelines to respect blocklist providers and avoid IP bans:
* **Run frequency:** Schedule updates **once every 12 or 24 hours** (e.g., once daily). Public blocklists do not change in real-time.
* **Avoid aggressive polling:** Running this script too frequently consumes excessive bandwidth and may cause providers to automatically block your server's IP address.

---

## Optimization Details

1. **IP Range to CIDR Conversion**: Ranges of sequential IPs are parsed and dynamically merged into the largest possible subnets to reduce firewall rule count.
2. **Subnet Deduping**: If a subnet overlaps with another (e.g., `192.168.1.0/24` and `192.168.0.0/16`), the script retains only the wider parent subnet.
3. **Binary Search Filter**: Individual IP addresses are checked against the final list of networks using binary search. If an IP falls inside any of the CIDR subnets, it is pruned from the single IP list.

---

## License

This project is licensed under the MIT License. See the `package.json` file for details.
