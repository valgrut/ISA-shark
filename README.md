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

## Useful Resources
- [DNS primer, headers](https://www2.cs.duke.edu/courses/fall16/compsci356/DNS/DNS-primer.pdf)
- [Sample traffic in pcap](https://wiki.wireshark.org/SampleCaptures)
- [Retriving the data from UDP packet](https://www.winpcap.org/pipermail/winpcap-users/2007-September/002104.html)
- [Dealing with pcup.h library](https://www.tcpdump.org/pcap.html)
