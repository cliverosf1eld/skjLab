import dns.message
import dns.query
import dns.rdatatype
import dns.exception

# A known root server (a.root-servers.net)
ROOT_SERVER = "198.41.0.4"

def resolve(domain, record_type="A", server=ROOT_SERVER, depth=0):
    indent = "  " * depth
    print(f"{indent}Querying {server} for {domain} {record_type}")

    # Build query
    query = dns.message.make_query(domain, record_type)

    try:
        response = dns.query.udp(query, server, timeout=3)
    except dns.exception.Timeout:
        print(f"{indent}[!] Timeout querying {server}")
        return None
    except Exception as e:
        print(f"{indent}[!] Error: {e}")
        return None

    # --- Case 1: Got ANSWER section ---
    if response.answer:
        for ans in response.answer:
            for item in ans.items:
                if item.rdtype == dns.rdatatype.CNAME:
                    cname = item.to_text()
                    print(f"{indent}CNAME → {cname}")
                    return resolve(cname, record_type, ROOT_SERVER, depth+1)
                elif item.rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA):
                    print(f"{indent}ANSWER: {item.to_text()}")
                    return item.to_text()

    # --- Case 2: No answer, try to follow referrals ---
    # Check ADDITIONAL for glue records (IP of next NS)
    if response.additional:
        for add in response.additional:
            for item in add.items:
                if item.rdtype == dns.rdatatype.A:
                    next_ip = item.to_text()
                    return resolve(domain, record_type, next_ip, depth+1)

    # --- Case 3: Use AUTHORITY section (need to resolve NS hostname) ---
    if response.authority:
        for auth in response.authority:
            for item in auth.items:
                if item.rdtype == dns.rdatatype.NS:
                    ns_name = item.to_text()
                    print(f"{indent}Need to resolve NS {ns_name}")

                    # Resolve NS hostname starting again from root
                    ns_ip = resolve(ns_name, "A", ROOT_SERVER, depth+1)
                    if ns_ip:
                        return resolve(domain, record_type, ns_ip, depth+1)

    print(f"{indent}[!] Resolution failed at {server}")
    return None


if __name__ == "__main__":
    domain = "google.com"
    print(f"Resolving {domain} ...")
    result = resolve(domain, "A")
    print(f"\nFinal Result: {result}")
