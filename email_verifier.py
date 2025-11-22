"""
Email Verifier Module
Validates email addresses and classifies them by risk level
"""

import re
import dns.resolver
from email_validator import validate_email, EmailNotValidError
from datetime import datetime


class EmailVerifier:
    """Email verification and risk assessment"""
    
    # Disposable email domains (common ones)
    DISPOSABLE_DOMAINS = {
        'tempmail.com', 'throwaway.email', '10minutemail.com', 'guerrillamail.com',
        'mailinator.com', 'maildrop.cc', 'temp-mail.org', 'getnada.com',
        'trashmail.com', 'fakeinbox.com', 'yopmail.com', 'mohmal.com'
    }
    
    # High-risk patterns
    SUSPICIOUS_PATTERNS = [
        r'^\d+@',  # Starts with numbers
        r'test\d+@',  # Test emails
        r'demo\d+@',  # Demo emails
        r'noreply@',  # No-reply addresses
        r'no-reply@',  # No-reply addresses
    ]
    
    def __init__(self):
        self.dns_resolver = dns.resolver.Resolver()
        self.dns_resolver.timeout = 5
        self.dns_resolver.lifetime = 5
    
    def verify_email(self, email):
        """
        Verify an email address and return detailed results
        
        Returns:
            dict: {
                'email': str,
                'status': str ('valid', 'invalid'),
                'risk_level': str ('Valid', 'Low Risk', 'Medium Risk', 'Invalid'),
                'details': str,
                'timestamp': str
            }
        """
        result = {
            'email': email,
            'status': 'invalid',
            'risk_level': 'Invalid',
            'details': '',
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        
        # Step 1: Basic syntax validation
        if not self._check_syntax(email):
            result['details'] = 'Invalid email syntax'
            return result
        
        # Step 2: Email validator library check
        try:
            validation = validate_email(email, check_deliverability=False)
            normalized_email = validation.normalized
            domain = validation.domain
        except EmailNotValidError as e:
            result['details'] = f'Invalid email format: {str(e)}'
            return result
        
        # Step 3: Check for disposable email
        if self._is_disposable(domain):
            result['status'] = 'valid'
            result['risk_level'] = 'Medium Risk'
            result['details'] = 'Disposable email domain detected'
            return result
        
        # Step 4: Check for suspicious patterns
        if self._has_suspicious_pattern(email):
            result['status'] = 'valid'
            result['risk_level'] = 'Medium Risk'
            result['details'] = 'Email matches suspicious pattern'
            return result
        
        # Step 5: DNS/MX record check
        mx_check = self._check_mx_records(domain)
        
        if mx_check['has_mx']:
            result['status'] = 'valid'
            
            # Risk assessment based on MX records
            if mx_check['mx_count'] == 0:
                result['risk_level'] = 'Medium Risk'
                result['details'] = 'Domain has no MX records (may use A record)'
            elif mx_check['mx_count'] >= 2:
                result['risk_level'] = 'Valid'
                result['details'] = 'Valid email with proper MX configuration'
            else:
                result['risk_level'] = 'Low Risk'
                result['details'] = 'Valid email with single MX record'
        else:
            result['status'] = 'invalid'
            result['risk_level'] = 'Invalid'
            result['details'] = 'Domain has no mail server (no MX or A records)'
        
        return result
    
    def _check_syntax(self, email):
        """Check basic email syntax"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None
    
    def _is_disposable(self, domain):
        """Check if domain is a known disposable email provider"""
        return domain.lower() in self.DISPOSABLE_DOMAINS
    
    def _has_suspicious_pattern(self, email):
        """Check if email matches suspicious patterns"""
        for pattern in self.SUSPICIOUS_PATTERNS:
            if re.search(pattern, email.lower()):
                return True
        return False
    
    def _check_mx_records(self, domain):
        """
        Check MX records for the domain
        
        Returns:
            dict: {'has_mx': bool, 'mx_count': int}
        """
        result = {'has_mx': False, 'mx_count': 0}
        
        try:
            # Try to get MX records
            mx_records = dns.resolver.resolve(domain, 'MX')
            result['has_mx'] = True
            result['mx_count'] = len(mx_records)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
            # Domain doesn't exist
            return result
        except dns.resolver.NoAnswer:
            # No MX records, try A record as fallback
            try:
                a_records = dns.resolver.resolve(domain, 'A')
                if a_records:
                    result['has_mx'] = True
                    result['mx_count'] = 0  # Using A record
            except Exception:
                pass
        except Exception:
            # DNS timeout or other error - assume valid to avoid false negatives
            result['has_mx'] = True
            result['mx_count'] = 1
        
        return result