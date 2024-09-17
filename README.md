# Packet Sniffer

A simple Python-based packet sniffer built using Scapy. This tool captures and analyzes HTTP network traffic on a specified network interface. It can also identify potential login credentials (username/password) sent over HTTP, making it useful for testing the security of HTTP traffic in a controlled environment.

> **Warning**: This tool should only be used in environments where you have explicit permission to perform network analysis. Unauthorized use of this tool on networks you do not own or have authorization to test is illegal.

## Features

- Captures and displays HTTP requests made over the network.
- Filters out HTTPS and other encrypted traffic.
- Detects potential login credentials (username/password) sent over HTTP.
- Can be run on any network interface (e.g., `eth0`, `wlan0`).

## Prerequisites

Before running the packet sniffer, ensure you have the following:

- **Python 3.x**
- **Scapy** (Python library for packet manipulation and sniffing)

You can install Scapy using `pip`:

```bash
pip install scapy
```

## How It Works

This tool captures all HTTP traffic passing through the specified network interface. For each captured HTTP request, it displays:

- The requested URL.
- Any potential login information (username/password) found in the HTTP payload.

### Limitations
- **HTTPS Traffic**: The sniffer will not capture or decode HTTPS traffic as it is encrypted. You will only see HTTP requests.

## Installation

1. Clone the repository:

   ```bash
   git clone git@github.com:MickLondonjr/packet-sniffer.git
   cd packet-sniffer
   ```

2. Create and activate a virtual environment:

   ```bash
   python3 -m venv env
   source env/bin/activate
   ```

3. Install the required dependencies:

   ```bash
   pip install -r requirements.txt
   ```

## Usage

To run the packet sniffer, use the following syntax:

```bash
sudo python3 packet-sniffer.py -i <interface>
```

Replace `<interface>` with the name of the network interface you want to monitor. For example, `eth0`, `wlan0`, etc.

### Example

```bash
sudo python3 packet-sniffer.py -i eth0
```

This will start capturing HTTP traffic on the `eth0` interface and output the requests and potential login information to the terminal.

## Example Output

```bash
[+] HTTP Request >> http://example.com/login
[+] Possible username/password >> username=admin&password=12345
```

## Testing

To test the packet sniffer, generate HTTP traffic by visiting websites using HTTP (not HTTPS) or by using tools like `curl`:

```bash
curl http://example.com
```

## Legal Disclaimer

This tool is intended for educational purposes only. Use it responsibly and only in environments where you have explicit permission to test network security. Unauthorized use of this tool on networks you do not own or have permission to test may violate laws and could result in criminal charges.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
```

### Key Sections:
- **Introduction**: Describes what the tool does and warns about legal usage.
- **Features**: Highlights the main features of the tool.
- **Prerequisites**: Lists Python and Scapy as requirements.
- **Installation**: Walks through how to clone the repository and set up a virtual environment.
- **Usage**: Explains how to run the packet sniffer and customize it with network interfaces.
- **Example**: Provides an example of the tool in action.
- **Legal Disclaimer**: Ensures users are aware of the legal responsibilities.
