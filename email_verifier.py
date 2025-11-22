"""
Email Verifier Module
Validates email addresses and classifies them by risk level
"""

import re
import smtplib
import socket
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
        
        if not mx_check['has_mx']:
            result['status'] = 'invalid'
            result['risk_level'] = 'Invalid'
            result['details'] = 'Domain has no mail server (no MX or A records)'
            return result
        
        # Step 6: SMTP mailbox verification
        smtp_check = self._check_smtp_mailbox(email, domain, mx_check.get('mx_servers', []))
        
        if not smtp_check['mailbox_exists']:
            result['status'] = 'invalid'
            result['risk_level'] = 'Invalid'
            result['details'] = smtp_check['message']
            return result
        
        # Email passed all checks - assess risk level
        result['status'] = 'valid'
        
        if smtp_check['verification_failed']:
            # SMTP check inconclusive - classify based on MX records only
            # Note: Major providers (Gmail, Outlook, etc.) block mailbox verification
            if mx_check['mx_count'] == 0:
                result['risk_level'] = 'Medium Risk'
                result['details'] = 'Domain accepts mail (no MX records, using A record) - mailbox unverified'
            elif mx_check['mx_count'] >= 2:
                result['risk_level'] = 'Valid'
                result['details'] = 'Domain can receive mail (proper MX config) - mailbox unverified'
            else:
                result['risk_level'] = 'Low Risk'
                result['details'] = 'Domain can receive mail (single MX) - mailbox unverified'
        else:
            # SMTP verification successful
            if mx_check['mx_count'] >= 2:
                result['risk_level'] = 'Valid'
                result['details'] = 'Mailbox verified - domain has proper MX configuration'
            else:
                result['risk_level'] = 'Valid'
                result['details'] = 'Mailbox verified at this domain'
        
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
            dict: {'has_mx': bool, 'mx_count': int, 'mx_servers': list}
        """
        result = {'has_mx': False, 'mx_count': 0, 'mx_servers': []}
        
        try:
            # Try to get MX records
            mx_records = dns.resolver.resolve(domain, 'MX')
            result['has_mx'] = True
            result['mx_count'] = len(mx_records)
            # Sort by priority and extract server names
            result['mx_servers'] = [str(mx.exchange).rstrip('.') for mx in sorted(mx_records, key=lambda x: x.preference)]
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
                    result['mx_servers'] = [domain]  # Use domain itself for SMTP
            except Exception:
                pass
        except Exception:
            # DNS timeout or other error - be conservative
            return result
        
        return result
    
    def _check_smtp_mailbox(self, email, domain, mx_servers):
        """
        Check if the mailbox exists using SMTP RCPT TO command
        
        Returns:
            dict: {'mailbox_exists': bool, 'message': str, 'verification_failed': bool}
        """
        result = {
            'mailbox_exists': True,  # Default to True if verification fails
            'message': '',
            'verification_failed': True  # Track if we couldn't verify
        }
        
        # If no MX servers, skip SMTP check
        if not mx_servers:
            result['message'] = 'Cannot verify mailbox - no mail servers found'
            return result
        
        # Try each MX server
        for mx_server in mx_servers[:3]:  # Try up to 3 servers
            try:
                # Connect to SMTP server
                smtp = smtplib.SMTP(timeout=10)
                smtp.connect(mx_server, 25)
                
                # Send HELO
                smtp.helo('verify.example.com')
                
                # Send MAIL FROM
                smtp.mail('verify@example.com')
                
                # Send RCPT TO - this checks if mailbox exists
                code, message = smtp.rcpt(email)
                smtp.quit()
                
                # Check response code
                if code == 250:
                    # Mailbox exists
                    result['mailbox_exists'] = True
                    result['verification_failed'] = False
                    result['message'] = 'Mailbox verified'
                    return result
                elif code >= 500:
                    # Mailbox doesn't exist (5xx codes are permanent failures)
                    result['mailbox_exists'] = False
                    result['verification_failed'] = False
                    result['message'] = 'Mailbox does not exist on this domain'
                    return result
                # If 4xx code, try next server
                
            except (socket.timeout, socket.error, smtplib.SMTPException) as e:
                # Connection failed, try next server
                continue
            except Exception:
                # Unexpected error, try next server
                continue
        
        # If we couldn't verify, assume mailbox exists to avoid false negatives
        result['mailbox_exists'] = True
        result['verification_failed'] = True
        result['message'] = 'Could not verify mailbox (mail server not responding)'
        return result