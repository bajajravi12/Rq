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
                if "CF-Ray" in headers or "cf-cache-status" in headers:
                    cdn = "Cloudflare"
                elif "x-amz-cf-id" in headers or "x-amz-cf-pop" in headers:
                    cdn = "CloudFront"
                elif "x-fastly-request-id" in headers:
                    cdn = "Fastly"
                elif "X-Akamai-Transformed" in headers:
                    cdn = "Akamai"
                
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
