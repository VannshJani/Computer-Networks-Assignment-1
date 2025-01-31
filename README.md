# Computer-Networks-Assignment-1
This repository is the computer networks assignment-1 done by Vannsh Jani and John Debarma

# Network Packet Sniffer

This is a **Network Packet Sniffer** implemented in C using the `pcap` library. It captures network packets, analyzes them, and provides statistics such as packet size distribution, flow statistics, and protocol filtering.

## Features
- Captures packets from a specified network interface.
- Filters packets based on source IP, destination IP, or protocol (TCP/UDP).
- Displays packet details including source/destination IPs and payload information.
- Maintains and prints statistics such as total packets, data transferred, and flow statistics.
- Can decode and print HTTP payloads.

## Compilation

To compile the program, use the following command:

```sh
gcc -o packet_sniffer final.c -lpcap
```

### Dependencies
Ensure that `libpcap` is installed on your system. Install it using:

- **Ubuntu/Debian:**
  ```sh
  sudo apt-get install libpcap-dev
  ```

- **MacOS:**
  ```sh
  brew install libpcap
  ```

## Usage

Run the program with a network interface name:

```sh
sudo ./packet_sniffer <network_interface> [options]
```

### Arguments
- `<network_interface>`: The network interface to sniff packets from (e.g., `eth0`, `wlan0`).
- `--src-ip <IP>`: Filter packets from a specific source IP.
- `--dest-ip <IP>`: Filter packets to a specific destination IP.
- `--protocol <TCP|UDP>`: Filter packets by protocol.
- `--v`: Display flow statistics.
- `--d`: Decode and print HTTP payloads.

### Example Commands

#### Capture all packets on `eth0`:
```sh
sudo ./packet_sniffer eth0
```

#### Capture only TCP packets:
```sh
sudo ./packet_sniffer eth0 --protocol TCP
```

#### Capture packets from a specific source IP:
```sh
sudo ./packet_sniffer eth0 --src-ip 192.168.1.10
```

#### Capture and decode HTTP payloads:
```sh
sudo ./packet_sniffer eth0 --d
```

## Output
- **Console Output:** Displays packet details, statistics, and optionally, HTTP payloads.
- **Flow Statistics:** Written to `flow_statistics.txt` if `--v` is used.
- **IP Count Flow:** Written to `ip_count_flow.txt` for source/destination IP statistics.

## Stopping the Sniffer
Press `Ctrl + C` to stop the packet capture and display the summary.

## Testing
A test script (`test_script.sh`) is provided to verify the functionality of the sniffer.

## License
This project is open-source and available for modification and distribution.

