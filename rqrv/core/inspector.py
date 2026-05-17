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
                    "cf-ray": "Cloudflare",
                    "cf-cache-status": "Cloudflare",
                    "x-amz-cf-id": "CloudFront",
                    "x-amz-cf-pop": "CloudFront",
                    "x-fastly-request-id": "Fastly",
                    "x-akamai-transformed": "Akamai",
                    "x-edge-request-id": "Edge",
                    "x-goog-meta-": "Google",
                    "alt-svc": "Alt-Svc",
                    "via": "Proxy/Via",
                    "x-cache": "Cache Hit",
                    "x-served-by": "LoadBalancer"
                }
                
                headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
                for h_key, h_label in cdn_sigs.items():
                    if h_key in headers_lower:
                        cdn = h_label
                        break
                
                # Server
                server = headers.get("Server", "Unknown")
                
                # WebSocket
                conn_val = headers_lower.get("connection", "")
                upgrade_val = headers_lower.get("upgrade", "")
                ws = "upgrade" in conn_val and "websocket" in upgrade_val

                # Additional Headers
                alt_svc = headers.get("Alt-Svc", "None")
                cache_control = headers.get("Cache-Control", "None")
                via = headers.get("Via", "None")

                return {
                    "status": resp.status_code,
                    "server": server,
                    "version": resp.http_version,
                    "cdn": cdn,
                    "ws": ws,
                    "alt_svc": alt_svc,
                    "cache_control": cache_control,
                    "via": via,
                    "headers": dict(headers)
                }
            except Exception as e:
                return {"error": str(e)}
