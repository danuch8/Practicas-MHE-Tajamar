import whois

class WhoisModule:
    def __init__(self, domain: str):
        self.domain = domain

    def run(self) -> dict:
        if not self.domain:
            return {"error": "No domain provided"}
        try:
            data = whois.whois(self.domain)
            return {
                "domain_name": str(data.get("domain_name")),
                "registrar": str(data.get("registrar")),
                "creation_date": str(data.get("creation_date")),
                "expiration_date": str(data.get("expiration_date")),
                "name_servers": [str(ns) for ns in (data.get("name_servers") or [])],
                "raw": {k: str(v) for k, v in data.items()}
            }
        except Exception as e:
            return {"error": str(e)}
