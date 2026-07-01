"""
Advanced password management features including scheduled rotation,
policy enforcement, and security monitoring.
"""

import time
from typing import Callable, Dict, List
from datetime import datetime, timedelta
from password_manager import PasswordLogger, PasswordGenerator, PasswordRotationManager


class PasswordPolicy:
    """Enforce and manage password policies."""
    
    def __init__(self, logger: PasswordLogger):
        """Initialize password policy enforcer."""
        self.logger = logger
        self.policies = {
            "min_length": 16,
            "require_uppercase": True,
            "require_lowercase": True,
            "require_numbers": True,
            "require_special": True,
            "max_age_days": 90,
            "rotation_frequency_days": 90,
            "failed_login_threshold": 5,
            "lockout_duration_minutes": 15,
        }
    
    def enforce_policy(self, password: str) -> tuple[bool, List[str]]:
        """
        Enforce password policy on given password.
        
        Args:
            password: Password to validate
        
        Returns:
            Tuple of (is_valid, list_of_violations)
        """
        violations = []
        
        if len(password) < self.policies["min_length"]:
            violations.append(
                f"Password too short (min {self.policies['min_length']} chars)"
            )
        
        if self.policies["require_uppercase"] and not any(c.isupper() for c in password):
            violations.append("Missing uppercase letters")
        
        if self.policies["require_lowercase"] and not any(c.islower() for c in password):
            violations.append("Missing lowercase letters")
        
        if self.policies["require_numbers"] and not any(c.isdigit() for c in password):
            violations.append("Missing numbers")
        
        if self.policies["require_special"] and not any(c in "!@#$%^&*()" for c in password):
            violations.append("Missing special characters")
        
        if violations:
            self.logger.log_policy_violation(
                "password_policy",
                f"Violations: {', '.join(violations)}"
            )
        
        return len(violations) == 0, violations
    
    def is_rotation_due(self, last_rotation: datetime) -> bool:
        """Check if password rotation is due."""
        days_since_rotation = (datetime.now() - last_rotation).days
        return days_since_rotation >= self.policies["rotation_frequency_days"]
    
    def get_policy(self, key: str) -> any:
        """Get specific policy value."""
        return self.policies.get(key)
    
    def set_policy(self, key: str, value: any) -> None:
        """Set specific policy value."""
        self.policies[key] = value


class ScheduledPasswordRotation:
    """Handle scheduled automatic password rotations."""
    
    def __init__(self, manager: PasswordRotationManager, 
                 logger: PasswordLogger,
                 policy: PasswordPolicy):
        """Initialize scheduled rotation manager."""
        self.manager = manager
        self.logger = logger
        self.policy = policy
        self.rotation_schedule = {}
        self.rotation_tasks = {}
    
    def schedule_rotation(self, system: str, target: str, interval_hours: int) -> None:
        """
        Schedule periodic password rotation.
        
        Args:
            system: System to rotate
            target: Target identifier
            interval_hours: Interval in hours between rotations
        """
        key = f"{system}:{target}"
        self.rotation_schedule[key] = {
            "system": system,
            "target": target,
            "interval_hours": interval_hours,
            "last_rotation": None,
            "next_rotation": datetime.now(),
        }
        self.logger.audit_logger.info(
            f"Scheduled rotation: {system}/{target} every {interval_hours} hours"
        )
    
    def get_due_rotations(self) -> List[Dict]:
        """Get list of rotations that are due."""
        due = []
        now = datetime.now()
        
        for key, schedule in self.rotation_schedule.items():
            if schedule["next_rotation"] <= now:
                due.append(schedule)
        
        return due
    
    def execute_due_rotations(self, user: str = "automation") -> Dict:
        """
        Execute all due rotations.
        
        Args:
            user: User executing the rotations
        
        Returns:
            Summary of execution results
        """
        due_rotations = self.get_due_rotations()
        results = {
            "timestamp": datetime.now().isoformat(),
            "total": len(due_rotations),
            "successful": 0,
            "failed": 0,
            "rotations": []
        }
        
        for schedule in due_rotations:
            system = schedule["system"]
            target = schedule["target"]
            
            result = self.manager.rotate_password(
                system=system,
                target=target,
                user=user,
                complexity="high"
            )
            
            results["rotations"].append(result)
            
            if result["success"]:
                results["successful"] += 1
                schedule["last_rotation"] = datetime.now()
                schedule["next_rotation"] = datetime.now() + timedelta(
                    hours=schedule["interval_hours"]
                )
            else:
                results["failed"] += 1
                self.logger.error_logger.error(
                    f"Scheduled rotation failed: {system}/{target}"
                )
        
        return results


class SecurityAuditLog:
    """Advanced security audit logging and analysis."""
    
    def __init__(self, logger: PasswordLogger):
        """Initialize security audit logger."""
        self.logger = logger
        self.security_events = []
    
    def log_failed_login_attempt(self, user: str, system: str, 
                                attempt_count: int = 1) -> None:
        """Log failed login attempts."""
        self.logger.audit_logger.warning(
            f"Failed login attempt | User: {user} | System: {system} | "
            f"Attempt: {attempt_count}"
        )
        
        self.security_events.append({
            "timestamp": datetime.now().isoformat(),
            "event_type": "failed_login",
            "user": user,
            "system": system,
            "attempt_count": attempt_count,
        })
        
        if attempt_count >= 5:
            self.logger.error_logger.critical(
                f"Multiple failed login attempts detected for user {user} on {system}"
            )
    
    def log_unauthorized_access_attempt(self, user: str, resource: str, 
                                       action: str) -> None:
        """Log unauthorized access attempts."""
        self.logger.error_logger.critical(
            f"Unauthorized access attempt | User: {user} | Resource: {resource} | "
            f"Action: {action}"
        )
        
        self.security_events.append({
            "timestamp": datetime.now().isoformat(),
            "event_type": "unauthorized_access",
            "user": user,
            "resource": resource,
            "action": action,
        })
    
    def log_administrative_action(self, admin_user: str, action: str, 
                                 target: str) -> None:
        """Log administrative actions."""
        self.logger.audit_logger.info(
            f"Administrative action | Admin: {admin_user} | Action: {action} | "
            f"Target: {target}"
        )
        
        self.security_events.append({
            "timestamp": datetime.now().isoformat(),
            "event_type": "admin_action",
            "admin": admin_user,
            "action": action,
            "target": target,
        })
    
    def get_security_summary(self, hours: int = 24) -> Dict:
        """
        Get security summary for specified period.
        
        Args:
            hours: Number of hours to look back
        
        Returns:
            Security summary dictionary
        """
        cutoff_time = datetime.now() - timedelta(hours=hours)
        recent_events = [
            e for e in self.security_events
            if datetime.fromisoformat(e["timestamp"]) > cutoff_time
        ]
        
        summary = {
            "period_hours": hours,
            "timestamp": datetime.now().isoformat(),
            "total_events": len(recent_events),
            "failed_logins": len([e for e in recent_events if e["event_type"] == "failed_login"]),
            "unauthorized_access": len([e for e in recent_events if e["event_type"] == "unauthorized_access"]),
            "admin_actions": len([e for e in recent_events if e["event_type"] == "admin_action"]),
        }
        
        return summary
    
    def alert_if_suspicious(self, threshold: int = 5) -> None:
        """
        Alert if suspicious activity detected.
        
        Args:
            threshold: Number of failed attempts to trigger alert
        """
        summary = self.get_security_summary(hours=1)
        
        if summary["failed_logins"] >= threshold:
            self.logger.error_logger.critical(
                f"ALERT: {summary['failed_logins']} failed login attempts in the last hour"
            )
        
        if summary["unauthorized_access"] > 0:
            self.logger.error_logger.critical(
                f"ALERT: {summary['unauthorized_access']} unauthorized access attempts detected"
            )


# Example usage
def demonstrate_advanced_features():
    """Demonstrate advanced password management features."""
    
    from password_manager import create_password_automation_system
    
    logger, generator, manager = create_password_automation_system()
    policy = PasswordPolicy(logger)
    scheduled = ScheduledPasswordRotation(manager, logger, policy)
    audit = SecurityAuditLog(logger)
    
    print("Advanced Password Management Features Demo")
    print("=" * 50)
    
    # Test policy enforcement
    print("\n1. Policy Enforcement:")
    test_pwd = "MyP@ssw0rd123"
    is_valid, violations = policy.enforce_policy(test_pwd)
    print(f"   Password valid: {is_valid}")
    if violations:
        print(f"   Violations: {violations}")
    
    # Schedule rotations
    print("\n2. Scheduling Rotations:")
    scheduled.schedule_rotation("database", "prod_db", interval_hours=720)  # 30 days
    scheduled.schedule_rotation("api_keys", "api_prod", interval_hours=168)  # 7 days
    print("   ✓ Scheduled 2 rotation tasks")
    
    # Log security events
    print("\n3. Security Event Logging:")
    audit.log_failed_login_attempt("user123", "production_db", 3)
    audit.log_administrative_action("admin001", "password_reset", "user456")
    print("   ✓ Logged security events")
    
    # Get security summary
    print("\n4. Security Summary:")
    summary = audit.get_security_summary(hours=1)
    print(f"   Failed logins: {summary['failed_logins']}")
    print(f"   Unauthorized access: {summary['unauthorized_access']}")
    print(f"   Admin actions: {summary['admin_actions']}")


if __name__ == "__main__":
    demonstrate_advanced_features()
