import ssl
import socket
import OpenSSL
import httpx

class Inspector:
    @staticmethod
    def get_tls_info(hostname, port=443):
        context = ssl.create_default_context()
        try:
            with socket.create_connection((hostname, port), timeout=3) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    version = ssock.version()
                    cipher = ssock.cipher()
                    cert_bin = ssock.getpeercert(True)
                    x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert_bin)
                    
                    san = []
                    for i in range(x509.get_extension_count()):
                        ext = x509.get_extension(i)
                        if ext.get_short_name() == b'subjectAltName':
                            san.append(str(ext))
                            
                    return {
                        "version": version,
                        "cipher": cipher[0],
                        "issuer": x509.get_issuer().commonName,
                        "expiry": x509.get_notAfter().decode('utf-8'),
                        "san": san
                    }
        except:
            return None

    @staticmethod
    async def analyze_host(target, ports=[80, 443]):
        results = []
        async with httpx.AsyncClient(verify=False, timeout=5.0, follow_redirects=False) as client:
            for port in ports:
                protocol = "https" if port == 443 else "http"
                url = f"{protocol}://{target}:{port}"
                try:
                    resp = await client.get(url)
                    headers = resp.headers
                    
                    # CDN Detection
                    cdn = None
                    if "CF-Ray" in headers or "cf-cache-status" in headers:
                        cdn = "Cloudflare"
                    elif "x-amz-cf-id" in headers:
                        cdn = "CloudFront"
                    elif "x-fastly-request-id" in headers:
                        cdn = "Fastly"
                    elif "X-Akamai-Transformed" in headers:
                        cdn = "Akamai"
                    
                    # WebSocket
                    ws_supported = "upgrade" in headers.get("connection", "").lower() and "websocket" in headers.get("upgrade", "").lower()
                    
                    # TLS
                    tls_info = None
                    if port == 443:
                        tls_info = Inspector.get_tls_info(target, port)

                    results.append({
                        "port": port,
                        "server": headers.get("Server", "Unknown"),
                        "status": resp.status_code,
                        "version": f"HTTP/{resp.http_version}",
                        "cdn": cdn,
                        "ws": ws_supported,
                        "tls": tls_info["version"] if tls_info else "N/A",
                        "headers": dict(headers)
                    })
                except:
                    continue
        return results
