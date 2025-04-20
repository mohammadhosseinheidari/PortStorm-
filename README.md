# PortStorm - Recon Tool

PortStorm is a comprehensive and automated reconnaissance tool designed for security professionals and ethical hackers. It integrates multiple tools like Masscan, Nmap, and Naabu to perform network scanning and gather detailed information about a target. The tool supports various output formats, including JSON, CSV, and HTML, making it easy to save and analyze the results.

## Features

- **Masscan Integration**: Detects open ports on the target with high-speed scanning.
- **Nmap Integration**: Identifies services, versions, and operating systems of the target.
- **Naabu Integration**: Gathers web-related information, including subdomains and directories, for web ports.
- **Flexible Output Formats**: Supports saving results as JSON, CSV, or HTML.
- **Command-Line Interface**: Easy-to-use CLI for specifying the target, scan rate, and output format.

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/portstorm.git
   cd portstorm
   ```

2. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Make sure you have the following tools installed on your system:
   - [Masscan](https://github.com/robertdavidgraham/masscan)
   - [Nmap](https://nmap.org/)
   - [Naabu](https://github.com/projectdiscovery/naabu)

## Usage

Run the script using the following command:
```bash
python portstorm.py <target> [--rate <rate>] [--output <output_path>]
```

### Options:
- `target`: The target IP, IP range, or domain to scan.
- `--rate`: (Optional) The rate of packets sent by Masscan (default: 1000).
- `--output`: (Optional) Path to save the output file (supports `.json`, `.csv`, `.html`).

### Example:
```bash
python portstorm.py example.com --rate 500 --output results.html
```

## Output

The tool provides the following information:
- **Open Ports**: Detected open ports on the target.
- **Service and Version Info**: Identified services and versions for the open ports.
- **Web Port Findings**: Subdomains and directories discovered on web ports.
- **Status**: Status of each scanning step (Masscan, Nmap, Naabu).

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Disclaimer

This tool is intended for ethical use only. Unauthorized scanning of networks or systems is illegal and strictly prohibited. Use this tool responsibly.

## Contribution

Contributions are welcome! Feel free to open an issue or submit a pull request.
