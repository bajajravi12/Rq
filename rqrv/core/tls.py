import ssl
import socket
import datetime

class TLSInspector:
    @staticmethod
    def inspect(hostname, port=443):
        try:
            context = ssl.create_default_context()
            # Disable certificate verification for diagnostics if needed, 
            # but usually we want to see if it's valid
            with socket.create_connection((hostname, port), timeout=3) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    version = ssock.version()
                    cipher = ssock.cipher()
                    
                    # Not after extraction
                    expiry = cert.get('notAfter')
                    issuer = dict(x[0] for x in cert.get('issuer', []))
                    subject = dict(x[0] for x in cert.get('subject', []))
                    san = cert.get('subjectAltName', [])
                    
                    return {
                        "version": version,
                        "cipher": cipher[0],
                        "expiry": expiry,
                        "issuer": issuer.get('organizationName', 'Unknown'),
                        "common_name": subject.get('commonName', 'Unknown'),
                        "san": [x[1] for x in san]
                    }
        except Exception as e:
            return {"error": str(e)}
