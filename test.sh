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
grep -q "Packet no." test_output.log && echo "Test 1 SUCCESS: Packets captured" || echo "Test 1 FAILED: No packets captured"

# Test 2: Validate TCP filtering
sudo ./$EXECUTABLE $INTERFACE --protocol TCP > test_tcp.log 2>&1 &
PID=$!
sleep 5
echo "Replaying packets again for TCP test..."
sudo tcpreplay -i $INTERFACE --mbps=30 $PCAP_FILE 2>/dev/null
sleep 5
kill $PID
grep -q "Filtering packets with TCP protocol" test_tcp.log && echo "Test 2 SUCCESS: TCP filter working" || echo "Test 2 FAILED: TCP filter not working"

# Test 3: Validate source IP filtering
sudo ./$EXECUTABLE $INTERFACE --src-ip 192.168.10.50 > test_src_ip.log 2>&1 &
PID=$!
sleep 5
echo "Replaying packets again for Source IP test..."
sudo tcpreplay -i $INTERFACE --mbps=30 $PCAP_FILE 2>/dev/null
sleep 5
kill $PID
grep -q "Filtering packets from source IP: 192.168.10.50" test_src_ip.log && echo "Test 3 SUCCESS: Source IP filter working" || echo "Test 3 FAILED: Source IP filter not working"

echo "All tests completed. Check logs for details."
