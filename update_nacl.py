#!/usr/bin/env python3
"""
AWS Network ACL Updater
Updates outbound rules to allow only specific IP addresses and deny all other traffic
Creates a backup before making changes for easy restoration
"""

import boto3
import sys
import json
from datetime import datetime

# AWS_DEFAULT_REGION (e.g., eu-west-2) - MUST match the region where your NACLs are located
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


def get_nacl_client():
    """Initialize EC2 client with credentials from environment"""
    return boto3.client('ec2')


def get_existing_egress_rules(client, nacl_id):
    """Get all existing egress rules for a NACL"""
    response = client.describe_network_acls(NetworkAclIds=[nacl_id])
    
    if not response['NetworkAcls']:
        raise Exception(f"Network ACL {nacl_id} not found")
    
    nacl = response['NetworkAcls'][0]
    egress_rules = [entry for entry in nacl['Entries'] if entry['Egress']]
    
    return egress_rules


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
    print(f"  Deleting rule {rule_number}")
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
    
    # Get existing egress rules
    existing_rules = get_existing_egress_rules(client, nacl_id)
    print(f"Found {len(existing_rules)} existing egress rules")
    
    # Save backup data for this NACL
    backup_data['nacls'][nacl_id] = {
        'egress_rules': existing_rules
    }
    
    # Delete all existing egress rules except the default (32767)
    for rule in existing_rules:
        rule_number = rule['RuleNumber']
        if rule_number != 32767:  # Don't delete the default rule
            delete_egress_rule(client, nacl_id, rule_number)
    
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
    
    print("=" * 60)
    print("AWS Network ACL Outbound Rules Updater")
    print("=" * 60)
    print(f"\nNACLs to update: {len(NACL_IDS)}")
    print(f"Allowed IPs: {len(ALLOWED_IPS)}")
    print("\nAllowed IP addresses:")
    for ip in ALLOWED_IPS:
        print(f"  - {ip}")
    
    print("\n" + "=" * 60)
    response = input("Proceed with updates? (yes/no): ")
    if response.lower() != 'yes':
        print("Aborted.")
        sys.exit(0)
    
    try:
        client = get_nacl_client()
        
        # Prepare backup data
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_file = f"nacl_backup_{timestamp}.json"
        backup_data = {
            'timestamp': timestamp,
            'datetime': datetime.now().isoformat(),
            'nacls': {}
        }
        
        print("\n" + "=" * 60)
        print("Creating backup...")
        
        for nacl_id in NACL_IDS:
            update_nacl(client, nacl_id, ALLOWED_IPS, backup_data)
        
        # Save backup after all updates
        backup_path = save_backup(backup_data, backup_file)
        
        print("\n" + "=" * 60)
        print("✓ All Network ACLs updated successfully!")
        print(f"✓ Backup saved to: {backup_path}")
        print("\nTo restore from backup, run:")
        print(f"  python3 restore_nacl.py {backup_path}")
        print("=" * 60)
        
    except Exception as e:
        print(f"\n✗ ERROR: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
