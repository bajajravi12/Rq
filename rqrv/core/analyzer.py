class MethodAnalyzer:
    @staticmethod
    def analyze_response(resp_data):
        headers = resp_data.get('headers', {})
        analysis = {
            "Server": headers.get("Server", "Unknown"),
            "Cache": headers.get("Cache-Control", "Not Set"),
            "Via": headers.get("Via", "None"),
            "ALPN": resp_data.get("alpn", "None"),
            "Alt-Svc": headers.get("Alt-Svc", "None"),
            "WebSocket": "Supported" if resp_data.get('ws') else "No",
            "CDN": resp_data.get('cdn', 'Direct')
        }
        return analysis
