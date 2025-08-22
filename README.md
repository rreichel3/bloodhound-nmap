# >x=ú Bloodhound Nmap Scanner

> **Transform your network reconnaissance into beautiful BloodHound graphs! <¯**

A powerful Python tool that combines the network discovery capabilities of **Nmap** with the graph visualization power of **BloodHound's OpenGraph format**. Turn your port scans into actionable intelligence! 

## ( Features

- = **Smart Network Scanning**: Leverage Nmap's powerful scanning engine
- < **Subnet Expansion**: Automatically expand CIDR notation (`192.168.1.0/24`) into individual hosts
- =Ê **BloodHound Integration**: Export results directly to OpenGraph JSON format
- ™ **Flexible Configuration**: JSON-based configuration for easy customization
- =á **Security Focused**: Built for defensive security and network analysis
- =€ **Easy to Use**: Simple command-line interface

## =€ Quick Start

### Prerequisites

- Python 3.13+
- Nmap installed on your system
- Root/Administrator privileges (for some scan types)

### Installation

1. **Clone the repository:**
   ```bash
   git clone <your-repo-url>
   cd bloodhound-nmap
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

### Usage

1. **Create your scan configuration:**
   ```bash
   cp scan_config.json my_scan.json
   # Edit my_scan.json with your targets
   ```

2. **Run the scan:**
   ```bash
   python main.py my_scan.json
   ```

3. **Import results into BloodHound! =È**

## =Ý Configuration Format

Create a JSON configuration file with your scan parameters:

```json
{
  "hosts": [
    "127.0.0.1",
    "192.168.1.0/24",
    "scanme.nmap.org"
  ],
  "ports": [22, 80, 443, 3389, 8080],
  "output_file": "my_scan_results.json"
}
```

### Configuration Options

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `hosts` | Array | List of IPs, hostnames, or CIDR subnets | `["10.0.0.1", "192.168.1.0/24"]` |
| `ports` | Array/String | Ports to scan | `[80, 443]` or `"1-1000"` |
| `output_file` | String | Output filename (optional) | `"results.json"` |

## <¯ What Gets Scanned?

For each discovered host, the tool captures:

- <à **Host Information**: IP address, hostname, state
- =¥ **Operating System**: Detected OS and accuracy
- =ª **Open Ports**: All discovered open ports
- =' **Services**: Service names, products, versions
- =Ê **BloodHound Properties**: Everything formatted for graph analysis

## < Example Output

```json
{
  "nodes": [
    {
      "id": "web-server-01",
      "kinds": ["Computer", "Server"],
      "properties": {
        "ip_address": "192.168.1.100",
        "hostname": "web-server-01",
        "state": "up",
        "os_name": "Linux 3.2 - 4.9",
        "open_ports": ["22/tcp", "80/tcp", "443/tcp"],
        "port_count": 3,
        "service_80_tcp_name": "http",
        "service_443_tcp_name": "https"
      }
    }
  ]
}
```

## =' Advanced Usage

### Large Network Scanning
```json
{
  "hosts": ["10.0.0.0/16"],
  "ports": "1-65535",
  "output_file": "enterprise_scan.json"
}
```

### Quick Service Discovery
```json
{
  "hosts": ["target.company.com"],
  "ports": [21, 22, 23, 25, 53, 80, 110, 443, 993, 995, 3389],
  "output_file": "service_discovery.json"
}
```

##   Safety Features

- =á **Subnet Limits**: Automatically limits subnet expansion to 1024 hosts
- = **Defensive Only**: Built for security analysis and network documentation
- =Ë **Error Handling**: Graceful handling of network issues and invalid targets

## > Contributing

Contributions welcome! This tool is designed for **defensive security purposes only**. Please ensure all contributions align with this mission.

## =Ü License

[Add your license here]

## =O Acknowledgments

- **Nmap Team**: For the incredible network scanning capabilities
- **BloodHound Team**: For revolutionizing attack path analysis
- **Python-Nmap**: For the excellent Python bindings

---

**Happy Scanning! <‰** Remember to always scan responsibly and only on networks you own or have explicit permission to test! =á