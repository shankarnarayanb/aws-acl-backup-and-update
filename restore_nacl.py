#!/usr/bin/env python3
"""
AWS Network ACL Restore Script
Restores Network ACL rules from a backup file created by update_nacl.py
"""

import boto3
import sys
import json
import os


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


def delete_egress_rule(client, nacl_id, rule_number):
    """Delete a specific egress rule"""
    print(f"  Deleting rule {rule_number}")
    client.delete_network_acl_entry(
        NetworkAclId=nacl_id,
        Egress=True,
        RuleNumber=rule_number
    )


def restore_egress_rule(client, nacl_id, rule):
    """Restore a single egress rule"""
    rule_number = rule['RuleNumber']
    
    # Skip the default rule as it can't be modified
    if rule_number == 32767:
        print(f"  Skipping default rule {rule_number}")
        return
    
    print(f"  Restoring rule {rule_number}: {rule['RuleAction']} {rule.get('CidrBlock', rule.get('Ipv6CidrBlock', 'N/A'))}")
    
    # Prepare parameters for creating the rule
    params = {
        'NetworkAclId': nacl_id,
        'RuleNumber': rule_number,
        'Protocol': rule['Protocol'],
        'RuleAction': rule['RuleAction'],
        'Egress': True
    }
    
    # Add CIDR block (IPv4 or IPv6)
    if 'CidrBlock' in rule:
        params['CidrBlock'] = rule['CidrBlock']
    elif 'Ipv6CidrBlock' in rule:
        params['Ipv6CidrBlock'] = rule['Ipv6CidrBlock']
    
    # Add port range if present
    if 'PortRange' in rule:
        params['PortRange'] = rule['PortRange']
    
    # Add ICMP type/code if present
    if 'IcmpTypeCode' in rule:
        params['IcmpTypeCode'] = rule['IcmpTypeCode']
    
    client.create_network_acl_entry(**params)


def restore_nacl(client, nacl_id, backup_rules):
    """Restore a single NACL from backup"""
    print(f"\nRestoring NACL: {nacl_id}")
    
    # Get existing egress rules
    existing_rules = get_existing_egress_rules(client, nacl_id)
    print(f"Found {len(existing_rules)} existing egress rules")
    
    # Delete all existing egress rules except the default (32767)
    for rule in existing_rules:
        rule_number = rule['RuleNumber']
        if rule_number != 32767:
            delete_egress_rule(client, nacl_id, rule_number)
    
    # Restore rules from backup
    print(f"Restoring {len(backup_rules)} rules from backup")
    for rule in backup_rules:
        restore_egress_rule(client, nacl_id, rule)
    
    print(f"✓ Successfully restored {nacl_id}")


def load_backup(backup_file):
    """Load backup data from JSON file"""
    if not os.path.exists(backup_file):
        raise Exception(f"Backup file not found: {backup_file}")
    
    with open(backup_file, 'r') as f:
        return json.load(f)


def list_available_backups():
    """List all available backup files"""
    backup_dir = './nacl_backups'
    if not os.path.exists(backup_dir):
        return []
    
    backups = [f for f in os.listdir(backup_dir) if f.startswith('nacl_backup_') and f.endswith('.json')]
    backups.sort(reverse=True)  # Most recent first
    return [os.path.join(backup_dir, f) for f in backups]


def main():
    """Main function"""
    print("=" * 60)
    print("AWS Network ACL Restore Script")
    print("=" * 60)
    
    # Check if backup file was provided
    if len(sys.argv) < 2:
        print("\nUsage: python3 restore_nacl.py <backup_file>")
        
        # List available backups
        backups = list_available_backups()
        if backups:
            print("\nAvailable backups:")
            for i, backup in enumerate(backups, 1):
                print(f"  {i}. {backup}")
            print("\nRun the script again with the backup file path:")
            print(f"  python3 restore_nacl.py {backups[0]}")
        else:
            print("\nNo backup files found in ./nacl_backups/")
        
        sys.exit(1)
    
    backup_file = sys.argv[1]
    
    try:
        # Load backup data
        print(f"\nLoading backup from: {backup_file}")
        backup_data = load_backup(backup_file)
        
        print(f"Backup created: {backup_data.get('datetime', 'Unknown')}")
        print(f"Number of NACLs in backup: {len(backup_data['nacls'])}")
        
        # Show what will be restored
        print("\nNACLs to restore:")
        for nacl_id, nacl_data in backup_data['nacls'].items():
            num_rules = len(nacl_data['egress_rules'])
            print(f"  - {nacl_id}: {num_rules} egress rules")
        
        print("\n" + "=" * 60)
        response = input("Proceed with restore? (yes/no): ")
        if response.lower() != 'yes':
            print("Aborted.")
            sys.exit(0)
        
        # Restore each NACL
        client = get_nacl_client()
        
        for nacl_id, nacl_data in backup_data['nacls'].items():
            restore_nacl(client, nacl_id, nacl_data['egress_rules'])
        
        print("\n" + "=" * 60)
        print("✓ All Network ACLs restored successfully!")
        print("=" * 60)
        
    except Exception as e:
        print(f"\n✗ ERROR: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
