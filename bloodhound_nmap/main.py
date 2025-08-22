
import nmap
import json
import sys
import ipaddress
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
                # Limit subnet expansion to avoid scanning too many hosts
                if network.num_addresses > 1024:
                    print(f"Warning: Subnet {host} has {network.num_addresses} addresses. Limiting to first 1024.")
                    hosts_to_add = list(network.hosts())[:1024]
                else:
                    hosts_to_add = list(network.hosts())
                
                expanded_hosts.extend([str(ip) for ip in hosts_to_add])
            else:
                # Regular hostname or IP
                expanded_hosts.append(host)
        except ipaddress.AddressValueError:
            # Not a valid IP/subnet, treat as hostname
            expanded_hosts.append(host)
    
    return expanded_hosts


def scan_hosts(hosts, ports="1-1000"):
    """
    Perform nmap scan on specified hosts and ports
    
    Args:
        hosts: List of IP addresses or hostnames to scan
        ports: Port range to scan (default: 1-1000)
    
    Returns:
        nmap.PortScanner results
    """
    nm = nmap.PortScanner()
    
    # Convert list to space-separated string if needed
    if isinstance(hosts, list):
        hosts_str = " ".join(hosts)
    else:
        hosts_str = hosts
    
    print(f"Scanning hosts: {hosts_str} on ports {ports}")
    nm.scan(hosts=hosts_str, ports=ports, arguments='-sS -O -A')
    
    return nm


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
    # Check for configuration file argument
    if len(sys.argv) < 2:
        print("Usage: python main.py <config_file.json>")
        print("Example: python main.py scan_config.json")
        sys.exit(1)
    
    config_file = sys.argv[1]
    
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
        # Perform nmap scan
        scan_results = scan_hosts(hosts_to_scan, ports_to_scan)
        
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
