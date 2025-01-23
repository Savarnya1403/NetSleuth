#!/usr/bin/env python3
from scapy.all import ARP, Ether, srp, conf
import pyshark
import socket
from mac_vendor_lookup import MacLookup

def get_vendor(mac):
    """Get vendor name from MAC address."""
    try:
        vendor = MacLookup().lookup(mac)
        return vendor
    except:
        return "Unknown"

def get_hostname(ip):
    """Get the hostname of a device using reverse DNS."""
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except socket.herror:
        return "Unknown"

def sniff_packets(interface):
    """Use Pyshark to sniff packets and gather device details."""
    import time

    devices = {}
    print(f"\nSniffing packets on {interface} for 10 seconds...")
    try:
        # Initialize packet capture
        capture = pyshark.LiveCapture(interface=interface)
        start_time = time.time()

        # Sniff packets for 10 seconds
        for packet in capture:
            if time.time() - start_time > 10:  # Stop after 10 seconds
                break

            # Extract IP and MAC information
            if hasattr(packet, "ip") and hasattr(packet, "eth"):
                ip = packet.ip.src
                mac = packet.eth.src
                if ip not in devices:
                    devices[ip] = {"MAC": mac, "Vendor": get_vendor(mac), "Hostname": get_hostname(ip)}
    except KeyboardInterrupt:
        print("\nStopped sniffing.")
    return devices

def arp_scan(network_prefix, interface):
    """Scan the network using ARP requests."""
    print(f"\nScanning {network_prefix}0/24 for active devices...\n")
    # Create ARP request
    arp = ARP(pdst=f"{network_prefix}1-254")  # IP range
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")    # Broadcast MAC
    packet = ether / arp

    # Send ARP request and capture responses
    result = srp(packet, iface=interface, timeout=2, verbose=0)[0]

    devices = {}
    for sent, received in result:
        ip = received.psrc
        mac = received.hwsrc
        devices[ip] = {"MAC": mac, "Vendor": get_vendor(mac), "Hostname": get_hostname(ip)}

    return devices

def display_results(devices):
    """Display the discovered devices in a user-friendly format."""
    if not devices:
        print("No devices found on the network.")
        return

    print("\nDiscovered Devices:")
    print(f"{'IP':<15} {'MAC':<17} {'Hostname':<25} {'Vendor':<20}")
    print("-" * 80)
    for ip, details in devices.items():
        print(f"{ip:<15} {details['MAC']:<17} {details['Hostname']:<25} {details['Vendor']:<20}")
    print("\nScan complete.")

def main():
    conf.verb = 0  # Suppress Scapy warnings
    interface = input("Enter the network interface name (e.g., eth0, Wi-Fi): ").strip()
    network_prefix = input("Enter the network prefix (e.g., 192.168.1.): ").strip()
    if not network_prefix.endswith('.'):
        print("Invalid network prefix. It must end with a dot (e.g., 192.168.1.).")
        return

    # Sniff packets to capture initial details
    sniffed_devices = sniff_packets(interface)
    print("\nSniffed Devices:")
    display_results(sniffed_devices)

    # Perform ARP scan for confirmation
    arp_devices = arp_scan(network_prefix, interface)
    print("\nARP Scan Results:")
    display_results(arp_devices)

    # Merge results
    all_devices = {**sniffed_devices, **arp_devices}
    print("\nCombined Device List:")
    display_results(all_devices)

if __name__ == "__main__":
    main()
