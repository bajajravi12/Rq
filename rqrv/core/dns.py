import dns.resolver
import dns.reversename

class DNSInspector:
    @staticmethod
    def get_ptr(ip):
        try:
            addr = dns.reversename.from_address(ip)
            answers = dns.resolver.resolve(addr, "PTR")
            return [str(ans).strip('.') for ans in answers]
        except Exception:
            return []

    @staticmethod
    def get_a(hostname):
        try:
            answers = dns.resolver.resolve(hostname, "A")
            return [str(ans) for ans in answers]
        except Exception:
            return []

    @staticmethod
    def reverse_dns_pro(ip):
        ptrs = DNSInspector.get_ptr(ip)
        results = []
        for ptr in ptrs:
            # Check if this hostname points back or has multiple hostnames
            results.append(ptr)
        return results
