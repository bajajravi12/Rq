import dns.resolver
import dns.reversename
import socket

class DNSInspector:
    @staticmethod
    def get_ptr(ip):
        if not ip: return []
        try:
            addr = dns.reversename.from_address(ip)
            resolver = dns.resolver.Resolver()
            resolver.timeout = 3.0
            resolver.lifetime = 3.0
            answers = resolver.resolve(addr, "PTR")
            return [str(ans).strip('.') for ans in answers]
        except Exception:
            try:
                # Fallback to socket
                name, alias, addresslist = socket.gethostbyaddr(ip)
                return list(set([name] + alias))
            except:
                return []

    @staticmethod
    def reverse_dns_pro(ip):
        ptrs = DNSInspector.get_ptr(ip)
        results = list(set(ptrs)) # Deduplicate
        return results
