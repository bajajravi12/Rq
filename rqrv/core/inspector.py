import httpx
import asyncio
from .tls import TLSInspector

class WebInspector:
    def __init__(self):
        self.timeout = httpx.Timeout(5.0, connect=2.0)

    async def analyze(self, target, port=80):
        protocol = "https" if port == 443 else "http"
        url = f"{protocol}://{target}:{port}"
        
        async with httpx.AsyncClient(timeout=self.timeout, verify=False, follow_redirects=False) as client:
            try:
                resp = await client.get(url)
                headers = resp.headers
                
                # CDN Detection
                cdn = None
                cdn_sigs = {
                    "CF-Ray": "Cloudflare",
                    "cf-cache-status": "Cloudflare",
                    "x-amz-cf-id": "CloudFront",
                    "x-amz-cf-pop": "CloudFront",
                    "x-fastly-request-id": "Fastly",
                    "X-Akamai-Transformed": "Akamai",
                    "x-cache": "Cache Server",
                    "x-served-by": "Load Balancer",
                    "via": "Proxy/CDN",
                }
                
                for h_key, h_label in cdn_sigs.items():
                    if h_key in headers:
                        cdn = h_label
                        break
                
                # Server
                server = headers.get("Server", "Unknown")
                
                # WebSocket
                ws = "upgrade" in headers.get("Connection", "").lower() and \
                     "websocket" in headers.get("Upgrade", "").lower()

                # Alt-Svc
                alt_svc = headers.get("Alt-Svc", "None")

                return {
                    "status": resp.status_code,
                    "server": server,
                    "version": resp.http_version,
                    "cdn": cdn,
                    "ws": ws,
                    "alt_svc": alt_svc,
                    "headers": dict(headers)
                }
            except Exception as e:
                return {"error": str(e)}
