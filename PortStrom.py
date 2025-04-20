import argparse
import json
import csv
import os
import subprocess

# This function runs Masscan to detect open ports on the target
def run_masscan(target, rate):
    print(f"[+] Running Masscan on {target} with rate {rate}")
    masscan_command = f"masscan {target} -p1-65535 --rate {rate} --open-only"
    result = subprocess.run(masscan_command, shell=True, capture_output=True, text=True)
    
    if result.returncode != 0:
        print("[!] Masscan failed:", result.stderr)
        return []
    
    open_ports = []
    for line in result.stdout.splitlines():
        if 'open' in line:
            port = int(line.split()[3].split('/')[0])  # Extract port number (without '/tcp')
            open_ports.append(port)
    
    print(f"[+] Found open ports: {open_ports}")
    return open_ports

# This function runs Nmap to identify services and versions for open ports
def run_nmap(target, ports):
    print(f"[+] Running Nmap on {target} for ports {ports}")
    nmap_command = f"nmap -sS -sV -O -p{','.join(map(str, ports))} --script=default -T4 {target}"
    result = subprocess.run(nmap_command, shell=True, capture_output=True, text=True)
    
    if result.returncode != 0:
        print("[!] Nmap failed:", result.stderr)
        return {}

    nmap_result = {}
    lines = result.stdout.splitlines()
    current_port = None
    for line in lines:
        if line.startswith('Nmap scan report'):
            current_port = None
        elif 'open' in line and current_port is None:
            parts = line.split()
            # Handle the 'port/tcp' format by stripping '/tcp'
            current_port = int(parts[0].split('/')[0])  # Extract the port number only
        elif 'Service Info' in line:
            nmap_result[current_port] = {'service': 'Unknown', 'version': 'Unknown', 'os': line.split('=')[1].strip()}
        elif current_port is not None and 'Service' in line:
            service, version = line.split(' ', 1)
            nmap_result[current_port] = {'service': service.strip(), 'version': version.strip(), 'os': 'Unknown'}
    
    return nmap_result

# This function runs Naabu to gather web-related information (subdomains and directories)
def run_naabu(target, ports):
    web_ports = [port for port in ports if port in [80, 443]]
    if not web_ports:
        return {}
    
    print(f"[+] Running Naabu on web ports: {web_ports}")
    naabu_result = {}
    for port in web_ports:
        naabu_command = f"naabu -host {target}:{port}"
        result = subprocess.run(naabu_command, shell=True, capture_output=True, text=True)
        
        if result.returncode != 0:
            print("[!] Naabu failed:", result.stderr)
            naabu_result[port] = {}
            continue
        
        # For example, collecting subdomains and directories
        subdomains = [line for line in result.stdout.splitlines() if 'subdomain' in line]
        directories = [line for line in result.stdout.splitlines() if 'directory' in line]
        
        naabu_result[port] = {
            'subdomains': subdomains,
            'directories': directories
        }
    
    return naabu_result

# This function saves the report in JSON format
def save_as_json(data, output_path):
    with open(output_path, 'w') as f:
        json.dump(data, f, indent=4)
    print(f"[+] Output saved as JSON at {output_path}")

# This function saves the report in CSV format
def save_as_csv(data, output_path):
    with open(output_path, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["Target", "Port", "Service", "Version", "OS"])
        for port, info in data['nmap'].items():
            writer.writerow([data['target'], port, info['service'], info['version'], info['os']])
    print(f"[+] Output saved as CSV at {output_path}")

# This function saves the report in HTML format
def save_as_html(data, output_path):
    html_content = f"<html><head><title>Scan Report for {data['target']}</title></head><body>"
    html_content += f"<h1>Scan Report for {data['target']}</h1>"
    
    # Adding open ports
    html_content += "<h2>Open Ports:</h2><ul>"
    for port in data['open_ports']:
        service = data['nmap'].get(str(port), {}).get('service', 'Unknown')
        version = data['nmap'].get(str(port), {}).get('version', 'Unknown')
        html_content += f"<li>Port {port}: {service} {version}</li>"
    html_content += "</ul>"
    
    # Adding web-related findings
    html_content += "<h2>Web Port Findings:</h2>"
    for port, web_info in data.get('web_ports', {}).items():
        html_content += f"<h3>Port {port}:</h3><ul>"
        for subdomain in web_info.get('subdomains', []):
            html_content += f"<li>Subdomain: {subdomain}</li>"
        for directory in web_info.get('directories', []):
            html_content += f"<li>Directory: {directory}</li>"
        html_content += "</ul>"
    
    # Adding status
    html_content += "<h2>Status:</h2><ul>"
    html_content += f"<li>Masscan: {data['status']['masscan']}</li>"
    html_content += f"<li>Nmap: {data['status']['nmap']}</li>"
    html_content += f"<li>Naabu: {data['status']['naabu']}</li>"
    html_content += "</ul></body></html>"
    
    with open(output_path, 'w') as f:
        f.write(html_content)
    print(f"[+] Output saved as HTML at {output_path}")

# This function saves the report in the chosen format (JSON, CSV, HTML)
def save_report(data, output_path):
    ext = os.path.splitext(output_path)[1].lower()
    if ext == '.json':
        save_as_json(data, output_path)
    elif ext == '.csv':
        save_as_csv(data, output_path)
    elif ext == '.html':
        save_as_html(data, output_path)
    else:
        print("[!] Unsupported output format. Please choose .json, .csv, or .html.")

def main():
    # Command-line argument parsing
    parser = argparse.ArgumentParser(description="SmartScanner - Recon Tool")
    parser.add_argument('target', help="Target IP, IP Range, or Domain")
    parser.add_argument('--rate', type=int, default=1000, help="Masscan rate (default: 1000)")
    parser.add_argument('--output', type=str, help="Path to save the output (e.g., results.json, results.csv, results.html)")
    
    args = parser.parse_args()
    
    # Running Masscan to detect open ports
    open_ports = run_masscan(args.target, args.rate)
    
    # Running Nmap to identify services and versions for the open ports
    nmap_result = run_nmap(args.target, open_ports)
    
    # Running Naabu to gather web-related information for web ports
    naabu_result = run_naabu(args.target, open_ports)
    
    # Constructing the final report data
    scan_data = {
        'target': args.target,
        'open_ports': open_ports,
        'nmap': nmap_result,
        'web_ports': naabu_result,
        'status': {
            'masscan': 'success',
            'nmap': 'success',
            'naabu': 'success'
        }
    }
    
    # Saving the report in the selected format
    if args.output:
        save_report(scan_data, args.output)
    else:
        print("[!] No output file specified. Use --output to specify a file.")

if __name__ == '__main__':
    main()
