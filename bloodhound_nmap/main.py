
import nmap
import json
import sys
import ipaddress
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
from opengraph import OpenGraphBuilder


def load_config(config_file):
    """
    Load configuration from JSON file
    
    Args:
        config_file: Path to JSON configuration file
    
    Returns:
        dict: Configuration dictionary
    """
    try:
        with open(config_file, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"Error: Configuration file '{config_file}' not found")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in configuration file: {e}")
        sys.exit(1)


def expand_subnets(hosts):
    """
    Expand subnet notation (CIDR) to individual IP addresses
    
    Args:
        hosts: List of hostnames/IPs/subnets
    
    Returns:
        list: Expanded list of individual hosts
    """
    expanded_hosts = []
    
    for host in hosts:
        try:
            # Check if it's a subnet (contains '/')
            if '/' in host:
                network = ipaddress.ip_network(host, strict=False)
                # Warn about large subnets but don't limit
                if network.num_addresses > 10000:
                    print(f"Warning: Subnet {host} has {network.num_addresses} addresses. This may take a very long time to scan.")
                
                hosts_to_add = list(network.hosts())
                expanded_hosts.extend([str(ip) for ip in hosts_to_add])
            else:
                # Regular hostname or IP
                expanded_hosts.append(host)
        except ipaddress.AddressValueError:
            # Not a valid IP/subnet, treat as hostname
            expanded_hosts.append(host)
    
    return expanded_hosts


def ping_sweep(hosts):
    """
    Perform ping sweep to identify live hosts
    
    Args:
        hosts: List of IP addresses or hostnames to check
    
    Returns:
        list: List of live hosts
    """
    nm = nmap.PortScanner()
    live_hosts = []
    
    # Convert list to space-separated string if needed
    if isinstance(hosts, list):
        hosts_str = " ".join(hosts)
    else:
        hosts_str = hosts
    
    print(f"Performing ping sweep on {len(hosts) if isinstance(hosts, list) else 1} hosts...")
    
    try:
        # Fast ping scan with aggressive timing
        nm.scan(hosts=hosts_str, arguments='-sn -T4 --min-rate=5000')
        
        for host in nm.all_hosts():
            if nm[host].state() == 'up':
                live_hosts.append(host)
        
        print(f"Found {len(live_hosts)} live hosts out of {len(hosts) if isinstance(hosts, list) else 1}")
        
    except Exception as e:
        print(f"Ping sweep failed: {e}")
        # Fall back to original host list
        return hosts if isinstance(hosts, list) else [hosts]
    
    return live_hosts


def scan_single_host(host, ports, scan_options):
    """
    Scan a single host
    
    Args:
        host: Single IP address or hostname
        ports: Port range to scan
        scan_options: Nmap scan arguments
    
    Returns:
        tuple: (host, nmap.PortScanner results or None)
    """
    try:
        nm = nmap.PortScanner()
        nm.scan(hosts=host, ports=ports, arguments=scan_options)
        return (host, nm)
    except Exception as e:
        print(f"Error scanning {host}: {e}")
        return (host, None)


def scan_hosts_parallel(hosts, ports="1-1000", threads=10, fast_mode=False, ping_first=True):
    """
    Perform parallel nmap scan on specified hosts and ports
    
    Args:
        hosts: List of IP addresses or hostnames to scan
        ports: Port range to scan (default: 1-1000)
        threads: Number of parallel threads (default: 10)
        fast_mode: Use faster scan options (default: False)
        ping_first: Perform ping sweep first (default: True)
    
    Returns:
        nmap.PortScanner with combined results
    """
    # Ensure hosts is a list
    if not isinstance(hosts, list):
        hosts = [hosts]
    
    # Optional ping sweep to filter live hosts
    if ping_first and len(hosts) > 1:
        hosts = ping_sweep(hosts)
        if not hosts:
            print("No live hosts found during ping sweep")
            return nmap.PortScanner()
    
    # Choose scan arguments based on mode
    if fast_mode:
        scan_args = '-sS -T4 --min-rate=1000'
    else:
        scan_args = '-sS -sV -T3'
    
    print(f"Scanning {len(hosts)} hosts on ports {ports} using {threads} threads ({'fast mode' if fast_mode else 'standard scan'})")
    
    # Combine all results into a single PortScanner object
    combined_nm = nmap.PortScanner()
    results_lock = Lock()
    
    def process_result(future):
        host, nm_result = future.result()
        if nm_result is not None:
            with results_lock:
                # Merge results
                for scanned_host in nm_result.all_hosts():
                    combined_nm._scan_result['scan'][scanned_host] = nm_result._scan_result['scan'][scanned_host]
    
    # Scan hosts in parallel
    with ThreadPoolExecutor(max_workers=threads) as executor:
        # Submit all scan jobs
        futures = [executor.submit(scan_single_host, host, ports, scan_args) for host in hosts]
        
        # Process completed scans
        completed = 0
        for future in as_completed(futures):
            process_result(future)
            completed += 1
            if completed % max(1, len(hosts) // 10) == 0:  # Progress updates
                print(f"Completed {completed}/{len(hosts)} scans...")
    
    return combined_nm


# Backward compatibility wrapper
def scan_hosts(hosts, ports="1-1000"):
    """
    Backward compatibility wrapper for scan_hosts
    """
    return scan_hosts_parallel(hosts, ports, threads=1, fast_mode=False, ping_first=False)


def convert_nmap_to_servers(nm_results):
    """
    Convert nmap scan results to OpenGraph server objects
    
    Args:
        nm_results: nmap.PortScanner results
    
    Returns:
        OpenGraphBuilder with server nodes
    """
    builder = OpenGraphBuilder(source_kind="NmapScanner")
    
    for host in nm_results.all_hosts():
        host_info = nm_results[host]
        
        # Extract host properties
        properties = {
            "ip_address": host,
            "state": host_info.state(),
        }
        
        # Add hostname if available
        if 'hostnames' in host_info and host_info['hostnames']:
            hostname = host_info['hostnames'][0]['name']
            if hostname:
                properties["hostname"] = hostname
        
        # Add OS information if available
        if 'osmatch' in host_info and host_info['osmatch']:
            os_match = host_info['osmatch'][0]
            properties["os_name"] = os_match['name']
            properties["os_accuracy"] = os_match['accuracy']
        
        # Add port information
        open_ports = []
        services = {}
        
        for protocol in host_info.all_protocols():
            ports = host_info[protocol].keys()
            for port in ports:
                port_info = host_info[protocol][port]
                if port_info['state'] == 'open':
                    open_ports.append(f"{port}/{protocol}")
                    
                    # Add service information as separate primitive properties
                    if port_info['name']:
                        service_prefix = f"service_{port}_{protocol}"
                        services[f"{service_prefix}_name"] = port_info['name']
                        if port_info.get('product'):
                            services[f"{service_prefix}_product"] = port_info['product']
                        if port_info.get('version'):
                            services[f"{service_prefix}_version"] = port_info['version']
                        if port_info.get('extrainfo'):
                            services[f"{service_prefix}_extrainfo"] = port_info['extrainfo']
        
        properties["open_ports"] = open_ports
        properties["port_count"] = len(open_ports)
        
        # Add service details as separate properties
        properties.update(services)
        
        # Create server node
        node_id = properties.get("hostname", host)
        server = builder.create_node(
            id=node_id,
            kinds=["Computer", "Server"],
            properties=properties
        )
    
    return builder


def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(
        description="Transform Nmap scan results into BloodHound-compatible OpenGraph format",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Example usage:
  bloodhound-nmap scan_config.json
  bloodhound-nmap --fast --threads 20 my_targets.json
  bloodhound-nmap --no-ping --threads 5 scan_config.json
        
The configuration file should be a JSON file with the following format:
{
  "hosts": ["127.0.0.1", "192.168.1.0/24", "scanme.nmap.org"],
  "ports": [22, 80, 443, 3389, 8080],
  "output_file": "results.json"
}
        """
    )
    parser.add_argument(
        "config_file", 
        help="JSON configuration file specifying hosts and ports to scan"
    )
    parser.add_argument(
        "--threads", "-t",
        type=int,
        default=10,
        help="Number of parallel scanning threads (default: 10)"
    )
    parser.add_argument(
        "--fast", "-f",
        action="store_true",
        help="Use fast scan mode (less accurate but much faster)"
    )
    parser.add_argument(
        "--no-ping",
        action="store_true",
        help="Skip ping sweep (scan all hosts directly)"
    )
    parser.add_argument(
        "--version", 
        action="version", 
        version="%(prog)s 0.2.0"
    )
    
    args = parser.parse_args()
    config_file = args.config_file
    
    # Load configuration
    config = load_config(config_file)
    
    # Extract hosts and ports from config
    hosts_config = config.get("hosts", [])
    if not hosts_config:
        print("Error: No hosts specified in configuration file")
        sys.exit(1)
    
    # Expand subnets to individual hosts
    hosts_to_scan = expand_subnets(hosts_config)
    print(f"Expanded {len(hosts_config)} host entries to {len(hosts_to_scan)} individual hosts")
    
    # Get ports from config (can be list or string)
    ports_config = config.get("ports", "1-1000")
    if isinstance(ports_config, list):
        ports_to_scan = ",".join(map(str, ports_config))
    else:
        ports_to_scan = str(ports_config)
    
    # Get output filename (optional)
    output_file = config.get("output_file", "nmap_scan_results.json")
    
    try:
        # Perform nmap scan using parallel scanning
        scan_results = scan_hosts_parallel(
            hosts_to_scan, 
            ports_to_scan,
            threads=args.threads,
            fast_mode=args.fast,
            ping_first=not args.no_ping
        )
        
        # Convert to OpenGraph server objects
        builder = convert_nmap_to_servers(scan_results)
        
        # Export results
        json_output = builder.to_json()
        print("\nScan Results as OpenGraph JSON:")
        print(json_output)
        
        # Save to file
        builder.save_to_file(output_file)
        print(f"\nResults saved to {output_file}")
        
    except Exception as e:
        print(f"Error during scan: {e}")


if __name__ == "__main__":
    main()
