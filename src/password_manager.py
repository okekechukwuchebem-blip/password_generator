"""
Secure Password Management and Automation Module

This module provides functionality for automated password generation,
rotation, and comprehensive logging for audit trails.
"""

import os
import logging
import json
import hashlib
import secrets
import string
from datetime import datetime, timedelta
from typing import Dict, Optional, Tuple
from pathlib import Path
import logging.handlers


class PasswordLogger:
    """Handles all password-related logging with security measures."""
    
    def __init__(self, log_dir: str = "logs", log_level: str = "INFO"):
        """
        Initialize the password logger.
        
        Args:
            log_dir: Directory to store log files
            log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        """
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(exist_ok=True)
        
        # Create loggers for different purposes
        self.audit_logger = self._create_logger(
            "audit",
            "password_audit.log",
            log_level
        )
        self.rotation_logger = self._create_logger(
            "rotation",
            "password_rotation.log",
            log_level
        )
        self.error_logger = self._create_logger(
            "error",
            "password_errors.log",
            logging.ERROR
        )
    
    def _create_logger(self, name: str, filename: str, level) -> logging.Logger:
        """
        Create a configured logger instance.
        
        Args:
            name: Logger name
            filename: Log file name
            level: Log level (string or int)
            
        Returns:
            Configured logger instance
        """
        logger = logging.getLogger(name)
        if isinstance(level, str):
            logger.setLevel(getattr(logging, level))
        else:
            logger.setLevel(level)
        
        # File handler with rotation
        log_path = self.log_dir / filename
        handler = logging.handlers.RotatingFileHandler(
            log_path,
            maxBytes=10 * 1024 * 1024,  # 10MB
            backupCount=5
        )
        
        # Formatter - never log sensitive data
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        
        return logger
    
    def log_rotation_start(self, system: str, user: str, target: str) -> None:
        """Log the start of password rotation."""
        self.audit_logger.info(
            f"Password rotation started | System: {system} | User: {user} | Target: {target}"
        )
        self.rotation_logger.info(
            f"[ROTATION_START] system={system}, user={user}, target={target}"
        )
    
    def log_rotation_success(self, system: str, user: str, target: str, 
                           duration: float) -> None:
        """Log successful password rotation."""
        self.audit_logger.info(
            f"Password rotation completed | System: {system} | Target: {target} | "
            f"Duration: {duration:.2f}s | User: {user}"
        )
        self.rotation_logger.info(
            f"[ROTATION_SUCCESS] system={system}, target={target}, duration={duration:.2f}s"
        )
    
    def log_rotation_failure(self, system: str, user: str, target: str, 
                           error: str) -> None:
        """Log failed password rotation."""
        self.audit_logger.warning(
            f"Password rotation failed | System: {system} | Target: {target} | User: {user}"
        )
        self.error_logger.error(
            f"[ROTATION_FAILED] system={system}, target={target}, error_type={error}"
        )
    
    def log_password_generation(self, length: int, complexity: str) -> None:
        """Log password generation event."""
        self.audit_logger.info(
            f"New password generated | Length: {length} | Complexity: {complexity}"
        )
    
    def log_access_attempt(self, user: str, system: str, success: bool) -> None:
        """Log authentication attempt."""
        status = "SUCCESS" if success else "FAILED"
        self.audit_logger.info(
            f"Authentication attempt | User: {user} | System: {system} | Status: {status}"
        )
        if not success:
            self.error_logger.warning(
                f"[AUTH_FAILED] user={user}, system={system}"
            )
    
    def log_policy_violation(self, violation_type: str, details: str) -> None:
        """Log password policy violations."""
        self.error_logger.warning(
            f"[POLICY_VIOLATION] type={violation_type}, details={details}"
        )


class PasswordGenerator:
    """Generates cryptographically secure passwords."""
    
    # Password complexity levels
    COMPLEXITY_LEVELS = {
        "low": {
            "length": 12,
            "chars": string.ascii_letters + string.digits
        },
        "medium": {
            "length": 16,
            "chars": string.ascii_letters + string.digits + "!@#$"
        },
        "high": {
            "length": 20,
            "chars": string.ascii_letters + string.digits + "!@#$%^&*"
        },
        "critical": {
            "length": 24,
            "chars": string.ascii_letters + string.digits + "!@#$%^&*()_+-=[]{}|;:,.<>?"
        }
    }
    
    def __init__(self, logger: PasswordLogger):
        """
        Initialize password generator.
        
        Args:
            logger: PasswordLogger instance for logging
        """
        self.logger = logger
    
    def generate(self, complexity: str = "high") -> str:
        """
        Generate a cryptographically secure password.
        
        Args:
            complexity: Password complexity level
                       (low, medium, high, critical)
        
        Returns:
            Generated password
            
        Raises:
            ValueError: If complexity level is invalid
        """
        if complexity not in self.COMPLEXITY_LEVELS:
            self.logger.log_policy_violation(
                "invalid_complexity",
                f"Invalid complexity level: {complexity}"
            )
            raise ValueError(f"Invalid complexity level: {complexity}")
        
        config = self.COMPLEXITY_LEVELS[complexity]
        length = config["length"]
        chars = config["chars"]
        
        # Generate password using secrets for cryptographic security
        password = ''.join(secrets.choice(chars) for _ in range(length))
        
        # Verify password meets requirements
        if not self._validate_password(password, complexity):
            return self.generate(complexity)  # Retry if validation fails
        
        self.logger.log_password_generation(length, complexity)
        return password
    
    def _validate_password(self, password: str, complexity: str) -> bool:
        """
        Validate password meets complexity requirements.
        
        Args:
            password: Password to validate
            complexity: Complexity level to validate against
        
        Returns:
            True if valid, False otherwise
        """
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        
        if complexity in ["medium", "high", "critical"]:
            has_special = any(c in "!@#$%^&*()" for c in password)
            return has_upper and has_lower and has_digit and has_special
        
        return has_upper and has_lower and has_digit
    
    def validate_strength(self, password: str) -> Tuple[bool, str]:
        """
        Validate password strength and return score.
        
        Args:
            password: Password to validate
        
        Returns:
            Tuple of (is_valid, strength_message)
        """
        score = 0
        feedback = []
        
        if len(password) >= 12:
            score += 1
        else:
            feedback.append("Missing uppercase letters")
        
        if len(password) >= 16:
            score += 1
        
        if any(c.isupper() for c in password):
            score += 1
        else:
            feedback.append("Missing uppercase letters")
        
        if any(c.islower() for c in password):
            score += 1
        else:
            feedback.append("Missing lowercase letters")
        
        if any(c.isdigit() for c in password):
            score += 1
        else:
            feedback.append("Missing numbers")
        
        if any(c in "!@#$%^&*()" for c in password):
            score += 1
        else:
            feedback.append("Missing special characters")
        
        is_valid = score >= 5
        score = min(score, 5)  # Cap score at 5 for strength levels
        strength = ["Weak", "Fair", "Good", "Strong", "Very Strong", "Excellent"][score]
        
        return is_valid, f"{strength} - Score: {score}/6"


class PasswordRotationManager:
    """Manages automated password rotation with full audit logging."""
    
    def __init__(self, logger: PasswordLogger, generator: PasswordGenerator):
        """
        Initialize password rotation manager.
        
        Args:
            logger: PasswordLogger instance
            generator: PasswordGenerator instance
        """
        self.logger = logger
        self.generator = generator
        self.rotation_history = []
    
    def rotate_password(self, system: str, target: str, user: str,
                       complexity: str = "high",
                       verify_callback=None) -> Dict[str, any]:
        """
        Perform password rotation with full logging.
        
        Args:
            system: System name (e.g., 'database', 'api_key')
            target: Target identifier (e.g., 'prod_db_01')
            user: User performing rotation
            complexity: Password complexity level
            verify_callback: Optional callback to verify password works
        
        Returns:
            Dictionary with rotation results
        """
        import time
        start_time = time.time()
        
        result = {
            "timestamp": datetime.now().isoformat(),
            "system": system,
            "target": target,
            "user": user,
            "success": False,
            "error": None,
            "duration": 0
        }
        
        try:
            self.logger.log_rotation_start(system, user, target)
            
            # Generate new password
            new_password = self.generator.generate(complexity)
            
            # Verify password strength
            is_valid, strength = self.generator.validate_strength(new_password)
            if not is_valid:
                raise ValueError(f"Generated password failed validation: {strength}")
            
            # Simulate system update (replace with actual API call)
            if verify_callback:
                verify_callback(system, target, new_password)
            
            duration = time.time() - start_time
            result["duration"] = duration
            result["success"] = True
            result["password_hash"] = self._hash_password(new_password)
            
            self.logger.log_rotation_success(system, user, target, duration)
            self._record_rotation(result)
            
        except Exception as e:
            result["error"] = str(e)
            self.logger.log_rotation_failure(system, user, target, type(e).__name__)
        
        return result
    
    def _hash_password(self, password: str) -> str:
        """
        Create SHA256 hash of password for audit trail.
        
        Note: This is for audit purposes only, not for authentication.
        
        Args:
            password: Password to hash
        
        Returns:
            SHA256 hash of password
        """
        return hashlib.sha256(password.encode()).hexdigest()[:16] + "..."
    
    def _record_rotation(self, result: Dict) -> None:
        """Record rotation in history."""
        self.rotation_history.append(result)
    
    def get_rotation_history(self, system: Optional[str] = None,
                            limit: int = 10) -> list:
        """
        Get rotation history.
        
        Args:
            system: Optional filter by system
            limit: Maximum number of records to return
        
        Returns:
            List of rotation records
        """
        history = self.rotation_history
        
        if system:
            history = [h for h in history if h["system"] == system]
        
        return sorted(
            history,
            key=lambda x: x["timestamp"],
            reverse=True
        )[:limit]
    
    def export_audit_log(self, filename: str) -> None:
        """
        Export audit log to JSON file.
        
        Args:
            filename: Output filename
        """
        with open(filename, 'w') as f:
            json.dump(self.rotation_history, f, indent=2)
        
        self.logger.audit_logger.info(f"Audit log exported to {filename}")


def create_password_automation_system() -> Tuple[PasswordLogger, PasswordGenerator, PasswordRotationManager]:
    """
    Factory function to create a complete password automation system.
    
    Returns:
        Tuple of (logger, generator, manager)
    """
    logger = PasswordLogger(log_dir="logs", log_level="INFO")
    generator = PasswordGenerator(logger)
    manager = PasswordRotationManager(logger, generator)
    
    return logger, generator, manager
