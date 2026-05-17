import dns.resolver
import dns.reversename
from ipwhois import IPWhois
import tldextract

class NetworkTool:
    @staticmethod
    def get_reverse_dns(ip):
        try:
            addr = dns.reversename.from_address(ip)
            answers = dns.resolver.resolve(addr, "PTR")
            return [str(ans) for ans in answers]
        except:
            return []

    @staticmethod
    def ip_to_asn(ip):
        try:
            obj = IPWhois(ip)
            results = obj.lookup_rdap(depth=1)
            return {
                "asn": results.get("asn"),
                "cidr": results.get("asn_cidr"),
                "org": results.get("asn_description"),
                "country": results.get("asn_country_code")
            }
        except:
            return None

    @staticmethod
    def extract_tld(domain):
        ext = tldextract.extract(domain)
        return {
            "subdomain": ext.subdomain,
            "domain": ext.domain,
            "suffix": ext.suffix,
            "registered": ext.registered_domain
        }
