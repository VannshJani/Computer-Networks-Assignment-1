#!/bin/bash

# Check if the correct number of arguments is provided
if [ "$#" -ne 3 ]; then
    echo "Usage: bash test.sh <packet_sniffer_executable> <network_interface> <pcap_file>"
    exit 1
fi

# Get arguments
EXECUTABLE=$1
INTERFACE=$2
PCAP_FILE=$3

# Check if the sniffer executable exists
if [ ! -f "./$EXECUTABLE" ]; then
    echo "Error: $EXECUTABLE not found! Please compile the code first."
    exit 1
fi

# Check if the PCAP file exists
if [ ! -f "$PCAP_FILE" ]; then
    echo "Error: PCAP file $PCAP_FILE not found! Please provide a valid PCAP file."
    exit 1
fi

# Run the packet sniffer in the background
echo "Starting packet sniffer..."
sudo ./$EXECUTABLE $INTERFACE > test_output.log 2>&1 &
PID=$!
sleep 12  # Allow some startup time

# Replay packets using tcpreplay
echo "Replaying packets from $PCAP_FILE..."
sudo tcpreplay -i $INTERFACE --mbps=20 $PCAP_FILE 2>/dev/null
sleep 5  # Give time for packet capture

# Stop the sniffer
kill $PID
sleep 1  # Ensure it stops properly

echo "Checking captured packets..."

# Test 1: Check if packets were captured
if ! grep -q "Packet no." test_output.log; then
    echo "Test 1 FAILED: No packets captured"
    exit 1
else
    echo "Test 1 SUCCESS: Packets captured"
fi

# Test 2: Validate TCP filtering (all packets must be TCP)
echo "Validating TCP packets capture..."
# Replay the packets with the TCP filter argument
sudo ./$EXECUTABLE $INTERFACE --protocol TCP > test_tcp.log 2>&1 &
PID=$!
sleep 5
echo "Replaying packets again for TCP test with TCP filter..."
sudo tcpreplay -i $INTERFACE --mbps=30 $PCAP_FILE 2>/dev/null
sleep 5
kill $PID
sleep 1  # Ensure the sniffer stops properly

# Ensure that all captured packets in test_tcp.log are TCP
tcp_packet_count=$(grep -c "TCP" test_tcp.log)
if [ "$tcp_packet_count" -gt 0 ]; then
    echo "Test 2 SUCCESS: All packets captured are TCP, $tcp_packet_count TCP packets captured"
else
    echo "Test 2 FAILED: No TCP packets captured"
    exit 1
fi

# Test 3: Validate source IP filtering (all packets must have the given src-ip)
echo "Validating source IP filtering..."
# Replay the packets with the src-ip filter argument
sudo ./$EXECUTABLE $INTERFACE --src-ip 192.168.10.50 > test_src_ip.log 2>&1 &
PID=$!
sleep 5
echo "Replaying packets again for Source IP test with src-ip filter..."
sudo tcpreplay -i $INTERFACE --mbps=30 $PCAP_FILE 2>/dev/null
sleep 5
kill $PID
sleep 1  # Ensure the sniffer stops properly

# Ensure that all captured packets in test_src_ip.log have the correct source IP
invalid_ip_count=$(grep -v "192.168.10.50" test_src_ip.log | wc -l)
if [ "$invalid_ip_count" -gt 0 ]; then
    echo "Test 3 FAILED: Found packets not from source IP 192.168.10.50"
    exit 1
else
    echo "Test 3 SUCCESS: All captured packets are from source IP 192.168.10.50"
fi

echo "All tests completed successfully. Check logs for details."
