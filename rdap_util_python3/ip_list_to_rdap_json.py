#!/usr/env/python3
from ipwhois import IPWhois
import json
import sys

def rdapify_32(inputaddress: str) -> dict:
    addr = IPWhois(inputaddress.strip())
    results = addr.lookup_rdap(depth=1)
    return results

def reserved_in_RFC5735(inputaddress: str) -> bool:
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
            "255."
            ]
    return inputaddress.startswith(tuple(reserved_ipv4))


def main():
    out_addr_dict = {}
    outfile = "json_out_last.txt"
    ohno = "items_not_queried.txt"
    listfile = sys.argv[1]
    cidrmetachar = "/"
    with open(listfile, "r") as fileptr:
        for lines in fileptr:
            line = str(lines)
            if cidrmetachar in line:
                itsbroken = ("error(cidr logic not yet written) on entry" + line)
                with open(ohno, 'a+') as the_table:
                    the_table.write(itsbroken)
            elif line[:1].isalpha():
                itsbroken = ("error(alpha_char) on entry: " + line)
                with open(ohno, 'a+') as the_table:
                    the_table.write(itsbroken)
            elif not reserved_in_RFC5735(line):
                reply = (rdapify_32(line))
                json_reply = json.dumps(reply, indent = 4)
                with open(outfile, 'a+') as f:
                    json.dump(json_reply, f, separators=(',', ':'), indent=4)
            elif reserved_in_RFC5735(line):
                itsbroken = ("error(reserved in RFC5735) on entry: " + line)
                with open(ohno, 'a+') as the_table:
                    the_table.write(itsbroken)
            else:
                itsbroken = ("error(unknown) on entry: " + line)
                with open(ohno, 'a+') as the_table:
                    the_table.write(itsbroken)

if __name__ == "__main__":
    main()




