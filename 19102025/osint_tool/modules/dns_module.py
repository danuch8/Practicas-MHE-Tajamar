import dns.resolver

class DNSModule:
    def __init__(self, domain: str):
        self.domain = domain

    def run(self) -> dict:
        if not self.domain:
            return {"error": "No domain provided"}
        records = {}
        for rtype in ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']:
            try:
                answers = dns.resolver.resolve(self.domain, rtype)
                records[rtype] = [str(a) for a in answers]
            except Exception as e:
                records[rtype] = str(e)
        return records
