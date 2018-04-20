/*
 * File: isashark.h
 * Author: Jiri Peska
 * Login:  xpeska05
 * Subject: ISA
 */

#include <iostream>
#include <fstream>
#include <sstream>
#include <pcap.h>
#include <unistd.h>
#include <vector>
#include <string>
#include <algorithm>
#include <map>
#include <list>
#include <cstdint>
#include <cctype>

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <err.h>

#ifdef __linux__
#include <netinet/ether.h>
#include <time.h>
#include <pcap/pcap.h>
#endif

/*
 * Struktura urcena k vypreparovani vlanid
 */
struct vlan_t
{
	uint16_t tpid;
	uint16_t vlanid;
};

/*
 * Obsahuje cislo dalsi hlavicky a delku aktualni hlavicky
 */
struct ipv6_ext_hdr
{
	unsigned char next;
	unsigned char len;
};

/*
 * Urceno puvodne k otestovani obsahu hlavicky po bytech
 */
struct ipv6_ext_hdr_test
{
	char ext[100];
};

/*
 *
 */
struct message
{
	const u_char msg[8];
};

/* definice velikosti hlavicek */
#ifndef PCAP_ERRBUF_SIZE
#define PCAP_ERRBUF_SIZE (256)
#endif

#define SIZE_ETHERNET (14) // velikost ethernet ethernet hlavicky(dst mac(6), src mac(6), ethertype(2))
#define SIZE_IPV6 (40)

/* container pro fragmentovany paket a jeho fragmenty */
class FragmentIdentificator
{
public:
	FragmentIdentificator() : fragment_id(0), dstip(""), srcip(""), protocol(0), lastLen(0), fragments() {};
	FragmentIdentificator(unsigned int id, std::string dst, std::string src, unsigned int prot)
		: fragment_id(id), dstip(dst), srcip(src), protocol(prot), lastLen(0), fragments() {}
	~FragmentIdentificator() {for(auto frags : fragments) delete frags.second;}
	unsigned int fragment_id;
	std::string dstip;
	std::string srcip;
	unsigned int protocol;
	unsigned int lastLen;
	std::vector< std::pair<unsigned int, u_char*> > fragments;
};

/*
 * Funkce vraci true, pokud se vsechyn hodnoty rovnaji, jinak false
 */
bool compareFragments(FragmentIdentificator *f, unsigned int fid, unsigned int prot, std::string srcip, std::string dstip)
{
	return (f->fragment_id == fid && f->protocol == prot && f->dstip == dstip && f->srcip == srcip);
}

/*
 * Trida v sobe uchovava data z hlavicek aktualne parsovaneho paketu
 */
class ParsedPacket
{
public:
	ParsedPacket() : valid(true), ipv4flag(false), ipv6flag(false), icmpv4flag(false), icmpv6flag(false), tcpflag(false), udpflag(false),
		cisloPacketu(0), ts(), len(0), srcMac(), dstMac(), IEEEval(), l3Protocol(), srcIP(), dstIP(),
		ttlorhop(), l4Protocol(), srcPort(), dstPort(), seq(), ack() , tcp_flags(), icmpType(), icmpCode(), icmpTypeDesc(), icmpCodeDesc()
	{
		// konstruktor
	}

	ParsedPacket(int packet_n) : valid(true), ipv4flag(false), ipv6flag(false), icmpv4flag(false), icmpv6flag(false), tcpflag(false), udpflag(false),
		cisloPacketu(packet_n), ts(), len(0), srcMac(), dstMac(), IEEEval(), l3Protocol(), srcIP(), dstIP(),
		ttlorhop(), l4Protocol(), srcPort(), dstPort(), seq(), ack(), tcp_flags(), icmpType(""), icmpCode(""), icmpTypeDesc(""), icmpCodeDesc("")
	{
		// konstruktor
	}

	bool valid;

	bool ipv4flag;
	bool ipv6flag;
	bool icmpv4flag;
	bool icmpv6flag;
	bool tcpflag;
	bool udpflag;

	unsigned int cisloPacketu;
	std::string ts;
 	unsigned int len;

	std::string srcMac;
	std::string dstMac;
	std::string IEEEval;

	// pro ipv4 i ipv6
	std::string l3Protocol;
	std::string srcIP; // ipv4/6
	std::string dstIP; // ipv4/6
	std::string ttlorhop;

	std::string l4Protocol; //tcp / udp / icmpv4 / icmpv6
	std::string srcPort;    // TCP / UDP
	std::string dstPort;    // TCP / UDP
	std::string seq;        // u TCP
	std::string ack;        // u TCP
	std::string tcp_flags;  // S,A,P,F,...

	// pro icmpv4 i icmpv6
	std::string icmpType;
	std::string icmpCode;
	std::string icmpTypeDesc;
	std::string icmpCodeDesc;

	void assemble();
};
void ParsedPacket::assemble()
{
	if(valid == false) return;

	std::cout << this->cisloPacketu << ": " << ts << " " << len << " | "
	<< "Ethernet: " << srcMac << " " << dstMac << " " << IEEEval << "| "         // v IEEEval bude na konci mezera!!!
	<< l3Protocol << ": " << srcIP << " " << dstIP << " " << ttlorhop << " | ";

	if(tcpflag)
		std::cout << l4Protocol << ": " << srcPort << " " << dstPort << " " << seq << " " << ack << " " << tcp_flags << "";
	else if(udpflag)
		std::cout << l4Protocol << ": " << srcPort << " " << dstPort << "";
	else if(icmpv4flag || icmpv6flag)
		std::cout << l4Protocol << ": " << icmpType << " " << icmpCode << " " << icmpTypeDesc << icmpCodeDesc;

	std::cout << std::endl;
}

/* definice funkci */
bool compareBytes(const ParsedPacket *p1, const ParsedPacket *p2);
void parseTcpHeader(ParsedPacket *output, struct tcphdr* tcp_header);
void parseUdpHeader(ParsedPacket *output, struct udphdr* udp_header);
void printHelp();

bool compareBytes(const ParsedPacket *p1, const ParsedPacket *p2)
{
	return (p1->len > p2->len);
}

void parseTcpHeader(ParsedPacket *output, struct tcphdr* tcp_header)
{
	output->tcpflag = true;
	output->l4Protocol = "TCP";
	output->srcPort = std::to_string(ntohs(tcp_header->source)); // zdrojovy port
	output->dstPort = std::to_string(ntohs(tcp_header->dest));   // cilovy port
	output->seq = std::to_string(ntohs(tcp_header->seq));	      // cislo sekvence
	output->ack = std::to_string(ntohs(tcp_header->ack_seq));	 // potvrzeny-bajt

	/* priznaky */
	//if(tcp_header->cwr == 1) output->tcp_flags.push_back('C'); else output->tcp_flags.push_back('.'); // cwr
	//if(tcp_header->ece == 1) output->tcp_flags.push_back('E'); else output->tcp_flags.push_back('.'); // ece

     output->tcp_flags.push_back('.');
     output->tcp_flags.push_back('.');
	if(tcp_header->urg == 1) output->tcp_flags.push_back('U'); else output->tcp_flags.push_back('.');
	if(tcp_header->ack == 1) output->tcp_flags.push_back('A'); else output->tcp_flags.push_back('.');
	if(tcp_header->psh == 1) output->tcp_flags.push_back('P'); else output->tcp_flags.push_back('.');
	if(tcp_header->rst == 1) output->tcp_flags.push_back('R'); else output->tcp_flags.push_back('.');
	if(tcp_header->syn == 1) output->tcp_flags.push_back('S'); else output->tcp_flags.push_back('.');
	if(tcp_header->fin == 1) output->tcp_flags.push_back('F'); else output->tcp_flags.push_back('.');
}

void parseUdpHeader(ParsedPacket *output, struct udphdr* udp_header)
{
	output->udpflag = true;
	output->l4Protocol = "UDP";

	output->srcPort = std::to_string(ntohs(udp_header->source)); // zdrojovy port
	output->dstPort = std::to_string(ntohs(udp_header->dest));   // cilovy port
}

void printHelp()
{
	using std::cout;
	using std::endl;
	cout << "Usage:" << endl;
	cout << "isashark [-h] [-a aggr-key] [-s sort-key] [-l limit] [-f filter-expression] file ..." << endl;
	cout << "  -h  Vypise napovedu a ukonci program." << endl;
	cout << "  -a aggr-key  Zapnuti agregace dle klice aggr-key, coz muze byt srcmac, dstmac, srcip, dstip, srcport, dstport." << endl;
	cout << "  -s sort-key  Zapnuti razeni podle klice sort-key, coz muze byt packets (pocet paketu) nebo bytes (pocet bytu). Radit lze agregovane tak i neagregovane polozky. Ve druhem pripade je klic packets bez efektu, protoze vsechny polozky obsahuji pouze jeden paket. Radi se vzdy sestupne." << endl;
	cout << "  -l limit  Nezaporne cele cislo v desitkove soustave udavajici limit poctu vypsanych paketu." << endl;
	cout << "  -f filter-expression  Program zpracuje pouze pakety, ktere vyhovuji filtru danemu retezcem filter-expression. " << endl;
	cout << "  file  Cesta k souboru ve formatu pcap. Mozne je zadat jeden a vice souboru." << endl;
	cout << endl;
	cout << "Example:" << endl;
	cout << "  ./isashark -h" << endl;
	cout << "  ./isashark -a dstip inputfile.pcap" << endl;
	cout << "  ./isashark -l 20 inputfile.pcap" << endl;
	cout << "  ./isashark -f \"src host 2001:db8::1\" inputfile.pcap" << endl;
}
