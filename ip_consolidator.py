#!/usr/bin/env python3
"""
IP Address Consolidation Utility
Analyzes your IP list and shows consolidation opportunities
"""

import ipaddress
import sys

def consolidate_ip_ranges(ip_list):
    """Consolidate IP addresses into the smallest set of CIDR blocks"""
    if not ip_list:
        return []
    
    networks = []
    invalid = []
    
    for ip_str in ip_list:
        try:
            networks.append(ipaddress.ip_network(ip_str.strip(), strict=False))
        except ValueError as e:
            invalid.append((ip_str, str(e)))
            continue
    
    if invalid:
        print("⚠️  Invalid IP addresses found:")
        for ip, error in invalid:
            print(f"  - {ip}: {error}")
        print()
    
    if not networks:
        return []
    
    # Sort and collapse
    networks.sort()
    consolidated = list(ipaddress.collapse_addresses(networks))
    
    return [str(net) for net in consolidated]


def analyze_consolidation(original, consolidated):
    """Show detailed consolidation analysis"""
    print("=" * 70)
    print("IP ADDRESS CONSOLIDATION ANALYSIS")
    print("=" * 70)
    
    print(f"\nOriginal entries: {len(original)}")
    print(f"Consolidated entries: {len(consolidated)}")
    print(f"Rules saved: {len(original) - len(consolidated)}")
    print(f"Reduction: {((len(original) - len(consolidated)) / len(original) * 100):.1f}%")
    
    print("\n" + "=" * 70)
    print("CONSOLIDATED IP RANGES")
    print("=" * 70)
    for i, ip in enumerate(consolidated, 1):
        print(f"{i:3d}. {ip}")
    
    print("\n" + "=" * 70)
    print("COVERAGE CHECK")
    print("=" * 70)
    
    # Verify all original IPs are covered
    original_networks = []
    for ip_str in original:
        try:
            original_networks.append(ipaddress.ip_network(ip_str.strip(), strict=False))
        except ValueError:
            continue
    
    consolidated_networks = [ipaddress.ip_network(ip) for ip in consolidated]
    
    uncovered = []
    for orig_net in original_networks:
        covered = False
        for cons_net in consolidated_networks:
            if orig_net.subnet_of(cons_net) or orig_net == cons_net:
                covered = True
                break
        if not covered:
            uncovered.append(str(orig_net))
    
    if uncovered:
        print("⚠️  WARNING: Some original IPs not covered by consolidation!")
        for ip in uncovered:
            print(f"  - {ip}")
    else:
        print("✓ All original IP addresses are covered by consolidated ranges")


def read_ips_from_file(filename):
    """Read IP addresses from a file (one per line)"""
    try:
        with open(filename, 'r') as f:
            return [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except FileNotFoundError:
        print(f"Error: File '{filename}' not found")
        sys.exit(1)


def main():
    """Main function"""
    print("=" * 70)
    print("IP ADDRESS CONSOLIDATION UTILITY")
    print("=" * 70)
    
    # Get IP list
    print("\nHow do you want to provide IP addresses?")
    print("1. Enter manually (one per line, empty line to finish)")
    print("2. Read from file")
    
    choice = input("\nChoice (1 or 2): ").strip()
    
    if choice == '1':
        print("\nEnter IP addresses (one per line, empty line to finish):")
        ip_list = []
        while True:
            line = input().strip()
            if not line:
                break
            ip_list.append(line)
    elif choice == '2':
        filename = input("\nEnter filename: ").strip()
        ip_list = read_ips_from_file(filename)
    else:
        print("Invalid choice")
        sys.exit(1)
    
    if not ip_list:
        print("No IP addresses provided")
        sys.exit(1)
    
    print(f"\nProcessing {len(ip_list)} IP addresses...")
    
    # Consolidate
    consolidated = consolidate_ip_ranges(ip_list)
    
    if not consolidated:
        print("No valid IP addresses to consolidate")
        sys.exit(1)
    
    # Show analysis
    analyze_consolidation(ip_list, consolidated)
    
    # Offer to save
    print("\n" + "=" * 70)
    save = input("\nSave consolidated list to file? (yes/no): ").strip().lower()
    
    if save == 'yes':
        output_file = input("Enter output filename [consolidated_ips.txt]: ").strip()
        if not output_file:
            output_file = "consolidated_ips.txt"
        
        with open(output_file, 'w') as f:
            f.write("# Consolidated IP ranges\n")
            f.write(f"# Original: {len(ip_list)} entries\n")
            f.write(f"# Consolidated: {len(consolidated)} entries\n")
            f.write(f"# Reduction: {len(ip_list) - len(consolidated)} rules saved\n\n")
            for ip in consolidated:
                f.write(f"{ip}\n")
        
        print(f"✓ Saved to {output_file}")
    
    # Show Python list format for easy copying
    print("\n" + "=" * 70)
    print("COPY THIS TO YOUR update_nacl_enhanced.py SCRIPT:")
    print("=" * 70)
    print("\nALLOWED_IPS = [")
    for ip in consolidated:
        print(f"    '{ip}',")
    print("]")
    
    print("\n" + "=" * 70)
    print("NEXT STEPS:")
    print("=" * 70)
    print("1. Copy the ALLOWED_IPS list above")
    print("2. Paste it into update_nacl_enhanced.py (replacing existing ALLOWED_IPS)")
    print("3. Run: python3 update_nacl_enhanced.py")
    print("\n✓ The update script will use YOUR CONFIRMED consolidated list")
    print("✓ No automatic consolidation will happen")


if __name__ == "__main__":
    main()
