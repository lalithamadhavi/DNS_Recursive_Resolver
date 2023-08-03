import logging
import argparse
# Install dnspython if not already installed
import dns.message
import dns.name
import dns.query
import dns.rdata
import dns.rdataclass
import dns.rdatatype
from dns.exception import DNSException, Timeout
# import PySimpleGUI as fs

# # This is the normal print that comes with simple GUI
# fs.Print('Re-routing the stdout', do_not_reroute_stdout=False)

# # this is clobbering the print command, and replacing it with sg's Print()
# print = fs.Print

# # this will now output to the sg display.
# print('This is a normal print that has been re-routed.')

# Root Servers IP addresses as of 12 November 2021
IP_ROOT_SERVERS = (
    # IP Address        # Name of the Root Servers
    "198.41.0.4",       # a.root-servers.net
    "199.9.14.201",     # b.root-servers.net
    "192.33.4.12",      # c.root-servers.net
    "199.7.91.13",      # d.root-servers.net
    "192.203.230.10",   # e.root-servers.net
    "192.5.5.241",      # f.root-servers.net
    "192.112.36.4",     # g.root-servers.net
    "198.97.190.53",    # h.root-servers.net
    "192.36.148.17",    # i.root-servers.net
    "192.58.128.30",    # j.root-servers.net
    "193.0.14.129",     # k.root-servers.net
    "199.7.83.42",      # l.root-servers.net
    "202.12.27.33",     # m.root-servers.net
)

FORMATS = (
    ("CNAME", "{alias} -> alias -> {name}"),
    ("A", "{name} -> IPv4 address -> {address}"),
    ("AAAA", "{name} -> IPv6 address -> {address}"),
    ("MX", "{name} -> mail by -> #{preference} {exchange}"),
)
Count = 0

def Results_Collect_DNS(name: str, Dns_cache: dict) -> dict:
    """
    Function parses final answers into the proper data structure that
    print_results requires.
    """
    Responses_Full = {}
    Domain_Name = dns.name.from_text(name)

    # Query A records
    response = Dns_lookup(Domain_Name, dns.rdatatype.A, Dns_cache)
    A = []
    for answers in response.answer:
        A_Rec = answers.name
        for answer in answers:
            if answer.rdtype == 1:  # A record
                A.append({"name": A_Rec, "address": str(answer)})

    # Query AAAA records
    response = Dns_lookup(Domain_Name, dns.rdatatype.AAAA, Dns_cache)
    AAAA = []
    for answers in response.answer:
        AAAA_Rec = answers.name
        for answer in answers:
            if answer.rdtype == 28:  # AAAA record
                AAAA.append({"name": AAAA_Rec, "address": str(answer)})

    # Query CNAME records
    response = Dns_lookup(Domain_Name, dns.rdatatype.CNAME, Dns_cache)
    CNAME = []
    for answers in response.answer:
        for answer in answers:
            CNAME.append({"name": answer, "alias": name})

    # Query MX records
    response = Dns_lookup(Domain_Name, dns.rdatatype.MX, Dns_cache)
    MX = []
    for answers in response.answer:
        mx_name = answers.name
        for answer in answers:
            if answer.rdtype == 15:  # MX record
                MX.append(
                    {
                        "name": mx_name,
                        "preference": answer.preference,
                        "exchange": str(answer.exchange),
                    }
                )

    Responses_Full["CNAME"] = CNAME
    Responses_Full["A"] = A
    Responses_Full["AAAA"] = AAAA
    Responses_Full["MX"] = MX

    Dns_cache.get("response_cache")[name] = Responses_Full
    return Responses_Full

def Recurse_Look(
    Domain_Name: dns.name.Name, qtype: dns.rdata.Rdata, ip_, resolved, Dns_cache: dict
) -> dns.message.Message:
    """
    This function uses a recursive resolver to find the relevant answer to the
    query.
    """
    global Count
    Count += 1
    outbound_query = dns.message.make_query(Domain_Name, qtype)
    try:
        response = dns.query.udp(outbound_query, ip_, 3)
        if response.answer:
            resolved = True
            return response, resolved

        elif response.additional:
            if response.authority:
                update_cache(response, Dns_cache)
            response, resolved = lookup_additional(
                response, Domain_Name, qtype, resolved, Dns_cache
            )

        elif response.authority and not resolved:
            response, resolved = lookup_authority(
                response, Domain_Name, qtype, resolved, Dns_cache
            )
        return response, resolved

    except Timeout:
        return dns.message.Message(), False
    except DNSException:
        return dns.message.Message(), False

def Dns_lookup(
    Domain_Name: dns.name.Name, qtype: dns.rdata.Rdata, Dns_cache: dict
) -> dns.message.Message:
    """
    Recursive resolver has been used by a function to get the response for the
    query.
    """
    incre = 0
    Resolved = False
    while incre < len(IP_ROOT_SERVERS):
        get_Ip_cache = ""
        Name_Find = str(Domain_Name)
        next_dot = str(Domain_Name).find(".")

        while not get_Ip_cache and next_dot > -1:
            get_Ip_cache = Dns_cache.get(Name_Find)
            Name_Find = str(Name_Find)[next_dot + 1 :]
            next_dot = Name_Find.find(".")

        if get_Ip_cache:
            ip_ = get_Ip_cache
            logging.debug("======== Found in cache =======\n")

        else:
            ip_ = IP_ROOT_SERVERS[incre]

        try:
            response, Resolved = Recurse_Look(
                Domain_Name, qtype, ip_, Resolved, Dns_cache
            )

            if response.answer:
                answer_type = response.answer[0].rdtype
                if qtype != dns.rdatatype.CNAME and answer_type == dns.rdatatype.CNAME:
                    Domain_Name = dns.name.from_text(str(response.answer[0][0]))
                    Resolved = False
                    logging.debug(
                        "--------- LOOKUP CNAME ----------- %s \n %s",
                        Domain_Name,
                        response.answer[0],
                    )
                    response = Dns_lookup(Domain_Name, qtype, Dns_cache)
                return response

            elif (
                response.authority and response.authority[0].rdtype == dns.rdatatype.SOA
            ):
                break
            else:
                incre += 1

        except Timeout:
            incre += 1
        except DNSException:
            incre += 1
    return response

def update_cache(response: dns.message.Message, Dns_cache):
    """
    Function updates the cache latest results
    """
    domain_name = response.authority[0].to_text().split(" ")[0]

    A_Records = []
    rrsets = response.additional
    for rrset in rrsets:
        for rr_ in rrset:
            if rr_.rdtype == dns.rdatatype.A:
                A_Records.append(str(rr_))
                Dns_cache[domain_name] = str(rr_)

def lookup_additional(
    response,
    Domain_Name: dns.name.Name,
    qtype: dns.rdata.Rdata,
    resolved,
    Dns_cache: dict,
):
    """
    Function recursively finds additional data
    """
    rrsets = response.additional
    for rrset in rrsets:
        for rr_ in rrset:
            if rr_.rdtype == dns.rdatatype.A:
                response, resolved = Recurse_Look(
                    Domain_Name, qtype, str(rr_), resolved, Dns_cache
                )
            if resolved:
                break
        if resolved:
            break
    return response, resolved

def lookup_authority(
    response,
    Domain_Name: dns.name.Name,
    qtype: dns.rdata.Rdata,
    resolved,
    Dns_cache: dict,
):
    """
    Function recursively finds authority
    """
    rrsets = response.authority
    ns_ip = ""
    for rrset in rrsets:
        for rr_ in rrset:
            if rr_.rdtype == dns.rdatatype.NS:
                ns_ip = Dns_cache.get(str(rr_))
                if not ns_ip:
                    ns_arecords = Dns_lookup(str(rr_), dns.rdatatype.A, Dns_cache)
                    ns_ip = str(ns_arecords.answer[0][0])
                    Dns_cache[str(rr_)] = ns_ip

                response, resolved = Recurse_Look(
                    Domain_Name, qtype, ns_ip, resolved, Dns_cache
                )
            elif rr_.rdtype == dns.rdatatype.SOA:
                resolved = True
                break
        if resolved:
            break

    return response, resolved

def print_results(results: dict) -> None:
    """
    Function takes results from Dns_lookup, prints to the screen.
    """
    for rtype, fmt_str in FORMATS:
        for result in results.get(rtype, []):
            print(fmt_str.format(**result))

def MainFn():
    global Count
    Dns_cache = {}
    Dns_cache["response_cache"] = {}
    Args_Parse = argparse.ArgumentParser()
    Args_Parse.add_argument("NAME", nargs="+", help="Domain name(s) to query")
    Args_Parse.add_argument(
        "-v", help="Increase the verbosity", action="store_true"
    )
    Proj_Args = Args_Parse.parse_args()
    for Domain in Proj_Args.NAME:
        Count = 0
        cache_result = Dns_cache.get("response_cache").get(Domain)
        if cache_result:
            print_results(cache_result)
            return(cache_result)
        else:
            print_results(Results_Collect_DNS(Domain, Dns_cache))
            # print(f"DNS Lookup Count: {Count}")
            print(f"DNS Lookup Completed for {Domain}")
            print("==================================")
            # return(Results_Collect_DNS(Domain, Dns_cache))
    
        #logging.debug("Count %s", Count)
    
    
if __name__ == "__main__":
    #logging.basicConfig(level=logging.DEBUG)
    MainFn()