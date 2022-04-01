# Isashark
Czech version [here](README_CZ.md).

Assignment (zadani) in CZ [here](Zadani.txt).

## Description
    Isashark is offline packet analyzer, which is able to parse headers data of supported protocols and print them or use them to further processing. Further processing depends on selected program options and arguments.
    Program expects .pcap files with saved traffic.
    Output format depends on given options, see Usage for more information.

### Extensions and known issues
    Defragmentation of ipv4 - I've chosen to implement fragmentation handling by myself, but this results in wrong results in case of overlapping fragments and two last values in TCP header. UDP works fine.
    No other issues were found.

## Build
    Program is build by running the command "make".

## Usage
```
    isashark [-h] [-a aggr-key] [-s sort-key] [-l limit] [-f filter-expression] file ...
```

## Examples
```
    ./isashark -h
        Prints help and exits with success.

    ./isashark -a dstip inputfile.pcap
        Agregates packets by given key - in this case: "dstip".

    ./isashark -l 20 inputfile.pcap
        Prints 20 packets at max.

    ./isashark -f "src host 2001:db8::1" inputfile.pcap
        Process only packets that match the filter.
```

## Submitted files
- isashark.cpp
- isashark.h
- Makefile
- README.md
- manual.pdf

## Dependencies
- libpcap
- libpcap-devel

## Useful Resources
- [DNS primer, headers](https://www2.cs.duke.edu/courses/fall16/compsci356/DNS/DNS-primer.pdf)
- [Sample traffic in pcap](https://wiki.wireshark.org/SampleCaptures)
- [Retriving the data from UDP packet](https://www.winpcap.org/pipermail/winpcap-users/2007-September/002104.html)
- [Dealing with pcup.h library](https://www.tcpdump.org/pcap.html)
- [Understanding the IPv6 headers](https://www.microsoftpressstore.com/articles/article.aspx?p=2225063&seqNum=4)
- [Wikipedia - Ethernet Frame](https://en.wikipedia.org/wiki/Ethernet_frame)
- [rfc791 - INTERNET PROTOCOL](https://datatracker.ietf.org/doc/html/rfc791)
- [rfc815 - IP DATAGRAM REASSEMBLY ALGORITHMS](https://datatracker.ietf.org/doc/html/rfc815)
- [Managed Ethernet Switches & VLANs](https://erg.abdn.ac.uk/users/gorry/course/lan-pages/vlan.html)
- [Netfilter - What Packets Look Like](https://www.netfilter.org/documentation/HOWTO/networking-concepts-HOWTO-8.html)
- [The Lost Art of Structure Packing](http://www.catb.org/esr/structure-packing/)
- [Flattening a C structure to a byte array](https://os.mbed.com/forum/mbed/topic/1041/?page=1#comment-5022)
- [Parsing Binary Data in C](https://stackoverflow.com/questions/321423/parsing-binary-data-in-c)
- [Parsing a TCP Packet data](https://stackoverflow.com/questions/27296160/parsing-a-tcp-packet-data)
- [Correct way to parse network packet in C](https://stackoverflow.com/questions/14634027/correct-way-to-parse-network-packet-in-c)
- [protocol parsing in c](https://stackoverflow.com/questions/2974061/protocol-parsing-in-c)
- [Packet parsing in C using struct](https://stackoverflow.com/questions/43702877/packet-parsing-in-c-using-struct)
