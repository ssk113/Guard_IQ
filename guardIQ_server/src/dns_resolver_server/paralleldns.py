import dns.message
import dns.query
import dns.resolver
import dns.zone
import dns.exception 
from dns.rdatatype import *
import tldextract

# DNS Cache
import time  # Import the time module for managing cache expiry

# Define a dictionary to store cached DNS responses
dns_cache = {}

# Define the cache expiry time in seconds
CACHE_EXPIRY_TIME = 300  # Set to expire after 5 minutes (adjust as needed)


resolver = dns.resolver.Resolver()




def extract_domain(url):
    # Use tldextract to extract the domain
    ext = tldextract.extract(url)
    domain = f"{ext.domain}.{ext.suffix}"
    return domain



## Make a function to create response


def resolve_dns(domain_name):
    """
    Resolves a domain name using the system-configured DNS resolver.
    
    Args:
        domain_name (str): The domain name to resolve.
    
    Returns:
        tuple or None: A tuple containing the resolved DNS record value and its type if found, or None if not found.
    """
    cached_record = dns_cache.get(domain_name)
    if cached_record and time.time() - cached_record[1] < CACHE_EXPIRY_TIME:
        print("Retrieving from cache:", domain_name)
        return cached_record[0]
    
    # Perform the DNS query
    for q_type in ["CNAME", "A", "AAAA", "SOA", "MX", "NS", "TXT"]:
        try:
            answer = resolver.resolve(domain_name, q_type)
            record = (str(answer[0]), q_type)
            # Cache the resolved record with the current timestamp
            dns_cache[domain_name] = (record, time.time())
            return record
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            pass
        except dns.resolver.Timeout:
            print("DNS resolution timed out.")
            return None
        except dns.exception.DNSException as e:
            print(f"DNS resolution failed: {e}")
            return None
        
def handle_dns_record_type(resp, query_name):
    """_summary_
    Please create the following parts of response prior to passing as argument
        response = dns.message.make_response(request)
        response.question = request.question
    Args:
        resp (_type_): _description_
        query_name (_type_): _description_

    Returns:
        _type_: _description_
    """
    response = resp
    try:
        ip_addresses = resolve_dns(query_name)
        query_type = ip_addresses[1]
    except TypeError:
        print(f"Could not resolve {query_name}.")
        ip_addresses = ("0.0.0.0", "A")
        query_type = ip_addresses[1]
        
    if query_type == "CNAME":
        RRset = dns.rrset.from_text(query_name, 300, dns.rdataclass.IN, dns.rdatatype.CNAME, ip_addresses[0])
        response.answer.append(RRset)
        response = handle_dns_record_type(response, ip_addresses[0])
    if query_type == "MX":
        RRset = dns.rrset.from_text(query_name, 300, dns.rdataclass.IN, dns.rdatatype.MX, ip_addresses[0])
        response.answer.append(RRset)
    if query_type == "A":
        RRset = dns.rrset.from_text(query_name, 300, dns.rdataclass.IN, dns.rdatatype.A, ip_addresses[0])
        response.answer.append(RRset)
    if query_type == "AAAA":
        RRset = dns.rrset.from_text(query_name, 300, dns.rdataclass.IN, dns.rdatatype.AAAA, ip_addresses[0])
        response.answer.append(RRset)
    if query_type == "SOA":  # Handling SOA record type
        RRset = dns.rrset.from_text(query_name, 300, dns.rdataclass.IN, dns.rdatatype.SOA, ip_addresses[0])
        response.authority.append(RRset)
    # Add more record types as needed
    
    return response
