#!/usr/bin/env python3
"""
AWS Network ACL Updater - Enhanced Version

IMPORTANT: This script does NOT automatically consolidate IPs!
You MUST run ip_consolidator.py first to:
  1. Review consolidation opportunities
  2. Confirm the consolidated ranges
  3. Get the optimized IP list to paste here

This script will:
  - Check if you've consolidated (warns if too many /32 entries)
  - Verify AWS limits before deploying
  - Create backups before changes
  - Use YOUR confirmed IP list (no auto-consolidation)
"""

import boto3
import sys
import json
from datetime import datetime
import ipaddress

# Configuration - UPDATE THESE VALUES
NACL_IDS = [
    # 'acl-xxxxx',  # Add your Network ACL IDs here
    # 'acl-yyyyy',
]

ALLOWED_IPS = [
    # '1.2.3.4/32',      # Example: Specific IP
    # '10.0.0.0/16',     # Example: IP range
]

# Rule number configuration
ALLOW_RULE_START = 100  # Starting rule number for allow rules
DENY_ALL_RULE = 32766   # Rule number for deny all (just before default)

# Backup configuration
BACKUP_DIR = './nacl_backups'

# AWS limits (can be increased via service quota request)
DEFAULT_RULE_LIMIT = 20  # Per NACL (inbound + outbound combined)
MAX_RULE_LIMIT = 40      # Maximum with quota increase


def get_nacl_client():
    """Initialize EC2 client with credentials from environment"""
    return boto3.client('ec2')


def consolidate_ip_ranges(ip_list):
    """
    Consolidate IP addresses into the smallest set of CIDR blocks.
    This reduces the number of rules needed.
    """
    if not ip_list:
        return []
    
    # Parse all IPs into network objects
    networks = []
    for ip_str in ip_list:
        try:
            networks.append(ipaddress.ip_network(ip_str, strict=False))
        except ValueError as e:
            print(f"Warning: Invalid IP address '{ip_str}': {e}")
            continue
    
    if not networks:
        return []
    
    # Sort networks
    networks.sort()
    
    # Collapse adjacent/overlapping networks
    consolidated = list(ipaddress.collapse_addresses(networks))
    
    return [str(net) for net in consolidated]


def get_existing_rules(client, nacl_id):
    """Get all existing rules (inbound and outbound) for a NACL"""
    response = client.describe_network_acls(NetworkAclIds=[nacl_id])
    
    if not response['NetworkAcls']:
        raise Exception(f"Network ACL {nacl_id} not found")
    
    nacl = response['NetworkAcls'][0]
    
    # Get both inbound and outbound rules (excluding default rule 32767)
    all_rules = [entry for entry in nacl['Entries'] if entry['RuleNumber'] != 32767]
    inbound_rules = [entry for entry in all_rules if not entry['Egress']]
    egress_rules = [entry for entry in all_rules if entry['Egress']]
    
    return {
        'inbound': inbound_rules,
        'egress': egress_rules,
        'total': len(all_rules)
    }


def check_rule_limits(client, nacl_id, new_egress_count, rule_limit):
    """Check if adding new rules would exceed limits"""
    existing = get_existing_rules(client, nacl_id)
    
    # Calculate new totals
    # We'll delete existing egress rules and add new ones
    # So total = existing inbound + new egress rules + 1 (deny all rule)
    new_total = len(existing['inbound']) + new_egress_count + 1
    
    return {
        'current_inbound': len(existing['inbound']),
        'current_egress': len(existing['egress']),
        'current_total': existing['total'],
        'new_egress': new_egress_count,
        'new_total': new_total,
        'limit': rule_limit,
        'within_limit': new_total <= rule_limit,
        'rules_available': rule_limit - len(existing['inbound']) - 1  # -1 for deny all
    }


def save_backup(backup_data, backup_file):
    """Save backup data to JSON file"""
    import os
    
    # Create backup directory if it doesn't exist
    os.makedirs(BACKUP_DIR, exist_ok=True)
    
    backup_path = os.path.join(BACKUP_DIR, backup_file)
    
    with open(backup_path, 'w') as f:
        json.dump(backup_data, f, indent=2, default=str)
    
    return backup_path


def delete_egress_rule(client, nacl_id, rule_number):
    """Delete a specific egress rule"""
    print(f"  Deleting egress rule {rule_number}")
    client.delete_network_acl_entry(
        NetworkAclId=nacl_id,
        Egress=True,
        RuleNumber=rule_number
    )


def create_allow_rule(client, nacl_id, rule_number, cidr):
    """Create an allow rule for specific CIDR"""
    print(f"  Creating ALLOW rule {rule_number} for {cidr}")
    client.create_network_acl_entry(
        NetworkAclId=nacl_id,
        RuleNumber=rule_number,
        Protocol='-1',  # All protocols
        RuleAction='allow',
        Egress=True,
        CidrBlock=cidr
    )


def create_deny_all_rule(client, nacl_id, rule_number):
    """Create a deny all rule"""
    print(f"  Creating DENY ALL rule {rule_number}")
    client.create_network_acl_entry(
        NetworkAclId=nacl_id,
        RuleNumber=rule_number,
        Protocol='-1',  # All protocols
        RuleAction='deny',
        Egress=True,
        CidrBlock='0.0.0.0/0'
    )


def update_nacl(client, nacl_id, allowed_ips, backup_data):
    """Update a single NACL with new outbound rules"""
    print(f"\nProcessing NACL: {nacl_id}")
    
    # Get existing rules for backup
    existing = get_existing_rules(client, nacl_id)
    
    # Save backup data for this NACL
    backup_data['nacls'][nacl_id] = {
        'egress_rules': existing['egress']
    }
    
    # Delete all existing egress rules except the default (32767)
    for rule in existing['egress']:
        delete_egress_rule(client, nacl_id, rule['RuleNumber'])
    
    # Create allow rules for each IP
    rule_number = ALLOW_RULE_START
    for ip in allowed_ips:
        create_allow_rule(client, nacl_id, rule_number, ip)
        rule_number += 1
    
    # Create deny all rule
    create_deny_all_rule(client, nacl_id, DENY_ALL_RULE)
    
    print(f"✓ Successfully updated {nacl_id}")


def main():
    """Main function"""
    if not NACL_IDS:
        print("ERROR: No Network ACL IDs specified in NACL_IDS list")
        print("Please edit the script and add your NACL IDs")
        sys.exit(1)
    
    if not ALLOWED_IPS:
        print("ERROR: No IP addresses specified in ALLOWED_IPS list")
        print("Please edit the script and add the IP addresses to allow")
        sys.exit(1)
    
    print("=" * 70)
    print("AWS Network ACL Outbound Rules Updater (Enhanced)")
    print("=" * 70)
    
    # Check if IPs look consolidated
    print(f"\nIP list entries: {len(ALLOWED_IPS)}")
    
    # Warn if there are many /32 entries (likely not consolidated)
    slash_32_count = sum(1 for ip in ALLOWED_IPS if ip.endswith('/32'))
    if slash_32_count > 10:
        print("\n" + "⚠️ " * 35)
        print("⚠️  WARNING: You have many individual /32 IP addresses!")
        print(f"⚠️  Found {slash_32_count} individual IPs out of {len(ALLOWED_IPS)} total entries")
        print("⚠️ ")
        print("⚠️  REQUIRED: Run ip_consolidator.py FIRST to:")
        print("⚠️    1. See how many rules you can save")
        print("⚠️    2. Review the consolidated ranges")
        print("⚠️    3. Confirm the consolidation is acceptable")
        print("⚠️    4. Get the optimized IP list to use here")
        print("⚠️ ")
        print("⚠️  Then copy the consolidated list back to this script")
        print("⚠️ " * 35)
        
        response = input("\nHave you run ip_consolidator.py and confirmed these IPs? (yes/no): ")
        if response.lower() != 'yes':
            print("\n❌ Please run ip_consolidator.py first:")
            print("   python3 ip_consolidator.py")
            print("\nThen update ALLOWED_IPS in this script with the consolidated list.")
            sys.exit(1)
    
    print("\nIP addresses to allow:")
    for ip in ALLOWED_IPS:
        print(f"  - {ip}")
    
    # Determine rule limit
    print("\n" + "=" * 70)
    rule_limit_str = input(f"What is your NACL rule limit? (default: {DEFAULT_RULE_LIMIT}, max: {MAX_RULE_LIMIT}): ").strip()
    if rule_limit_str:
        try:
            rule_limit = int(rule_limit_str)
        except ValueError:
            print("Invalid input, using default limit")
            rule_limit = DEFAULT_RULE_LIMIT
    else:
        rule_limit = DEFAULT_RULE_LIMIT
    
    print(f"\nUsing rule limit: {rule_limit}")
    
    # Check limits for each NACL
    try:
        client = get_nacl_client()
        
        print("\n" + "=" * 70)
        print("Checking rule limits...")
        
        all_within_limits = True
        limit_checks = {}
        
        for nacl_id in NACL_IDS:
            check = check_rule_limits(client, nacl_id, len(ALLOWED_IPS), rule_limit)
            limit_checks[nacl_id] = check
            
            print(f"\nNACL: {nacl_id}")
            print(f"  Current rules: {check['current_total']} (Inbound: {check['current_inbound']}, Egress: {check['current_egress']})")
            print(f"  New egress rules: {check['new_egress']}")
            print(f"  Total after update: {check['new_total']} / {check['limit']}")
            
            if check['within_limit']:
                print(f"  ✓ Within limit ({check['limit'] - check['new_total']} rules remaining)")
            else:
                print(f"  ✗ EXCEEDS LIMIT by {check['new_total'] - check['limit']} rules!")
                print(f"  → You can only add {check['rules_available']} more egress rules")
                all_within_limits = False
        
        if not all_within_limits:
            print("\n" + "=" * 70)
            print("❌ ERROR: Some NACLs would exceed rule limits!")
            print("\nRequired steps:")
            print("1. Run ip_consolidator.py to reduce your IP list:")
            print("   python3 ip_consolidator.py")
            print("2. Copy the consolidated IPs to ALLOWED_IPS in this script")
            print("3. Run this script again")
            print("\nOther options:")
            print("• Request AWS quota increase (up to 40 rules per NACL)")
            print("• Split resources across multiple subnets/NACLs")
            print("• Remove unnecessary inbound rules")
            sys.exit(1)
        
        # Show what will be updated
        print("\n" + "=" * 70)
        print(f"Ready to update {len(NACL_IDS)} NACL(s)")
        print(f"Total rules to create: {len(ALLOWED_IPS) + 1} (allow rules + deny all)")
        
        response = input("\nProceed with updates? (yes/no): ")
        if response.lower() != 'yes':
            print("Aborted.")
            sys.exit(0)
        
        # Prepare backup data
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_file = f"nacl_backup_{timestamp}.json"
        backup_data = {
            'timestamp': timestamp,
            'datetime': datetime.now().isoformat(),
            'ip_count': len(ALLOWED_IPS),
            'allowed_ips': ALLOWED_IPS,
            'nacls': {}
        }
        
        print("\n" + "=" * 70)
        print("Creating backup...")
        
        for nacl_id in NACL_IDS:
            update_nacl(client, nacl_id, ALLOWED_IPS, backup_data)
        
        # Save backup after all updates
        backup_path = save_backup(backup_data, backup_file)
        
        print("\n" + "=" * 70)
        print("✓ All Network ACLs updated successfully!")
        print(f"✓ Backup saved to: {backup_path}")
        print(f"✓ Created {len(ALLOWED_IPS)} allow rules + 1 deny all rule")
        print("\nTo restore from backup, run:")
        print(f"  python3 restore_nacl.py {backup_path}")
        print("=" * 70)
        
    except Exception as e:
        print(f"\n✗ ERROR: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
