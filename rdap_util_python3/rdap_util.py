#!/usr/env/python3
"""
module that takes cli parameter pointing to a list file of ip addresses
and returns the json dump of single depth rdap queries
"""
import json
import sys
from ipwhois import IPWhois


def rdapify_32(inputaddress: str) -> dict:
    """
    non-recursive rdap lookup for a given ip address
    """
    print("SENDING RDAP QUERY FOR " + inputaddress)
    addr = IPWhois(str(inputaddress).strip())
    results = addr.lookup_rdap(depth=1)
    return results


def reserved_in_rfc5735(inputaddress: str) -> bool:
    """
    computationally inexpensive way to determine if ipv4 addr is private
    """
    reserved_ipv4 = [
        "0.",
        "10.",
        "100.64.",
        "100.65.",
        "100.66.",
        "100.67.",
        "100.68.",
        "100.69.",
        "100.7",
        "100.8",
        "100.9",
        "100.100.",
        "100.101.",
        "100.102.",
        "100.103.",
        "100.104.",
        "100.105.",
        "100.106.",
        "100.107.",
        "100.108.",
        "100.109.",
        "100.110.",
        "100.111.",
        "100.112.",
        "100.113.",
        "100.114.",
        "100.115.",
        "100.116.",
        "100.117.",
        "100.118.",
        "100.119.",
        "100.120.",
        "100.121.",
        "100.122.",
        "100.123.",
        "100.124.",
        "100.125.",
        "100.126.",
        "100.127.",
        "127.",
        "169.254.",
        "172.16.",
        "172.17.",
        "172.18.",
        "172.19.",
        "172.20.",
        "172.21.",
        "172.22.",
        "172.23.",
        "172.24.",
        "172.25.",
        "172.26.",
        "172.27.",
        "172.28.",
        "172.29.",
        "172.30.",
        "172.31.",
        "192.0.0.",
        "192.0.2.",
        "192.88.99.",
        "192.168.",
        "198.18.",
        "198.19.",
        "198.51.100.",
        "203.0.113.",
        "224.",
        "225.",
        "226.",
        "227.",
        "228.",
        "229.",
        "230.",
        "231.",
        "232.",
        "233.",
        "234.",
        "235.",
        "236.",
        "237.",
        "238.",
        "239.",
        "240.",
        "241.",
        "242.",
        "243.",
        "244.",
        "245.",
        "246.",
        "247.",
        "248.",
        "249.",
        "250.",
        "251.",
        "252.",
        "253.",
        "254.",
        "255.",
    ]
    return inputaddress.startswith(tuple(reserved_ipv4))


def main():
    """
    is main function
    does the main thing
    is a cli script if not being referenced by another module
    """
    if len(sys.argv) > 1:
        listfile = sys.argv[1]
        outfile = "./json_out_last.txt"
        query_cache = {}
        invalid_list = []
        out_cache = {}
        valid_ctr = 0
        sanitized_line = ""

        # Validate the input /32 ip addresses and cache only the valid ones
        with open(listfile, "r", encoding="UTF-8") as inputfile:
            for line in inputfile:
                sanitized_line = str(line).strip()
                if (
                    reserved_in_rfc5735(inputaddress=sanitized_line)
                    or any(c.isalpha() for c in sanitized_line)
                    or "/" in sanitized_line
                ):
                    invalid_list.append(sanitized_line)
                    print(
                        "SOMETHING WEIRD IF THIS LIST IS SUPPOSED TO BE ONLY PUBLIC ADDRESSES: "
                        + sanitized_line
                    )

                else:
                    query_cache[valid_ctr] = sanitized_line
                    valid_ctr += 1

        # Print to terminal what is about to be run and what was invalid
        print("WILL_QUERY: ", json.dumps(query_cache, indent=4))
        print("INVALID: ", invalid_list)

        # Nest the dictionary of results in a new dictionary
        for value in query_cache.values():
            out_cache[value] = rdapify_32(value)

        # Write the data set to a file
        with open(outfile, "w", encoding="UTF-8") as outputfile:
            outputfile.write(json.dumps(out_cache, indent=2))


if __name__ == "__main__":
    main()
