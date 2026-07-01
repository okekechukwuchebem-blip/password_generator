"""
Example usage of the password automation system with comprehensive logging.
"""

from password_manager import create_password_automation_system, PasswordGenerator
import json
from datetime import datetime


def main():
    """Demonstrate password automation and logging system."""
    
    print("=" * 70)
    print("PASSWORD AUTOMATION & LOGGING SYSTEM DEMO")
    print("=" * 70)
    print()
    
    # Initialize the system
    logger, generator, manager = create_password_automation_system()
    
    # Example 1: Generate passwords with different complexity levels
    print("1. GENERATING PASSWORDS WITH DIFFERENT COMPLEXITY LEVELS")
    print("-" * 70)
    
    complexity_levels = ["low", "medium", "high", "critical"]
    passwords = {}
    
    for level in complexity_levels:
        password = generator.generate(complexity=level)
        is_valid, strength = generator.validate_strength(password)
        
        print(f"   {level.upper():10s} | Length: {len(password):2d} | {strength}")
        passwords[level] = password
    
    print()
    
    # Example 2: Password strength validation
    print("2. PASSWORD STRENGTH VALIDATION")
    print("-" * 70)
    
    test_passwords = [
        "weak",
        "Medium123",
        "Strong@Pass123",
        "VeryStr0ng!@#$%^&*"
    ]
    
    for pwd in test_passwords:
        is_valid, strength = generator.validate_strength(pwd)
        status = "✓ VALID" if is_valid else "✗ INVALID"
        print(f"   {pwd:25s} | {strength:30s} | {status}")
    
    print()
    
    # Example 3: Automated password rotation with logging
    print("3. AUTOMATED PASSWORD ROTATION WITH LOGGING")
    print("-" * 70)
    
    rotations = [
        ("database", "prod_db_01", "admin_user", "high"),
        ("api_key", "api_service_prod", "automation_user", "critical"),
        ("ssh_key", "server_01", "root_admin", "high"),
    ]
    
    for system, target, user, complexity in rotations:
        print(f"\n   Rotating: {system:12s} | Target: {target:20s}")
        
        result = manager.rotate_password(
            system=system,
            target=target,
            user=user,
            complexity=complexity
        )
        
        if result["success"]:
            print(f"   ✓ SUCCESS | Duration: {result['duration']:.3f}s | Hash: {result.get('password_hash', 'N/A')}")
        else:
            print(f"   ✗ FAILED  | Error: {result['error']}")
    
    print()
    
    # Example 4: Multi-system rotation scenario
    print("4. MULTI-SYSTEM PASSWORD ROTATION SCENARIO")
    print("-" * 70)
    
    systems = [
        ("production_db", "primary_server", "dba_team"),
        ("cache_cluster", "redis_01", "ops_team"),
        ("backup_vault", "vault_service", "security_admin"),
    ]
    
    print("\n   Performing bulk rotation across systems...")
    
    for system, target, user in systems:
        result = manager.rotate_password(
            system=system,
            target=target,
            user=user,
            complexity="critical"
        )
        status_icon = "✓" if result["success"] else "✗"
        print(f"   {status_icon} {system:20s} ({target:20s})")
    
    print()
    
    # Example 5: Rotation history
    print("5. ROTATION HISTORY")
    print("-" * 70)
    
    history = manager.get_rotation_history(limit=5)
    for i, record in enumerate(history, 1):
        timestamp = datetime.fromisoformat(record["timestamp"]).strftime("%Y-%m-%d %H:%M:%S")
        status = "✓" if record["success"] else "✗"
        print(f"   {i}. {status} {record['system']:15s} | {record['target']:20s} | {timestamp}")
    
    print()
    
    # Example 6: Demonstrate logging behavior
    print("6. LOGGING SUMMARY")
    print("-" * 70)
    
    log_files = [
        ("logs/password_audit.log", "AUDIT LOG"),
        ("logs/password_rotation.log", "ROTATION LOG"),
        ("logs/password_errors.log", "ERROR LOG"),
    ]
    
    for log_file, label in log_files:
        try:
            with open(log_file, 'r') as f:
                lines = f.readlines()
            print(f"\n   {label} - Last 3 entries:")
            for line in lines[-3:]:
                print(f"   {line.strip()[:80]}")
        except FileNotFoundError:
            print(f"\n   {label} - No entries yet")
    
    print()
    
    # Example 7: Export audit log
    print("7. EXPORTING AUDIT LOG")
    print("-" * 70)
    
    export_file = "logs/audit_log_export.json"
    manager.export_audit_log(export_file)
    print(f"   ✓ Audit log exported to: {export_file}")
    
    print()
    print("=" * 70)
    print("DEMO COMPLETED")
    print("=" * 70)
    print("\nNotes:")
    print("  - All password rotation events have been logged")
    print("  - Sensitive data (actual passwords) are NOT stored in logs")
    print("  - Log files are located in the 'logs/' directory")
    print("  - Audit logs contain timestamps and user information")
    print()


if __name__ == "__main__":
    main()
