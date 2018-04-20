/*
 * isashark
 * Author: Jiri Peska
 * Login:  xpeska05
 * Subject: ISA
 */

#define __FAVOR_BSD
#include "isashark.h"

int main(int argc, char *argv[])
{
	bool TEST2_ENABLE = false;

	#define _USE_BSD
	// zpracovani argumentu programu
	if(argc < 2)
	{
		std::cerr << "Too few arguments.Try -h for help." << std::endl;
		return -1;
	}

	std::vector<std::string> inputFiles;
	std::map<std::string, std::pair<int,int> > packetAggregation; // packetAggregation[aggr_key] = std::make_pair(suma,suma);
	std::vector<ParsedPacket*> packetSorting;

	std::vector<FragmentIdentificator*> fragmentedPackets;

	std::string aggr_key		= "";
	std::string sort_key		= "";
	unsigned int limit   		= 0;
	std::string filter_expression = "";

	bool aggr_key_flag 			= false;
	bool sort_key_flag 			= false;
	bool limit_flag 			= false;
	bool filter_expression_flag   = false;

	/* zpracovani argumentu programu  a nastaveni prislusnych flagu */
	int option;
	while ((option = getopt (argc, argv, "ha:s:l:f:")) != -1)
	{
	  	switch (option)
	    	{
	    	case 'h':

			printHelp();
			return 0;
	    	case 'a':

			aggr_key = std::string(optarg);
			aggr_key_flag = true;
			break;
	    	case 's':
			sort_key = std::string(optarg);
			sort_key_flag = true;
			break;
	    	case 'l':
		 	limit = std::atoi(optarg);
			limit_flag = true;
		 	break;
	    	case 'f':
			filter_expression = std::string(optarg);
			filter_expression_flag = true;
			break;
	    	case '?':
			if (optopt == 'c')
			{
				std::cerr << "Argument required for '-" << (char)optopt << "'. Try -h for help." << std::endl;
			}
			else if (isprint (optopt))
			{
				 std::cerr << "Unresolved option '-" << (char)optopt << "'. Try -h for help." << std::endl;
			}
			else
			{
				std::cerr << "Unresolved option '-" << (char)optopt << "'. Try -h for help." << std::endl;
			}
			return -1;
	     default:
		 	return -1;
		}
     }

	/* overeni platnosti agregacniho klice a sort klice */
	if(aggr_key_flag == true)
	{
		if(aggr_key == "srcip" || aggr_key == "dstip" || aggr_key == "srcport" || aggr_key == "dstport" || aggr_key == "srcmac" || aggr_key == "dstmac")
		{
			//std::cerr << "agregacni klic je OK" << std::endl;
		}
		else
		{
			std::cerr << "Invalid aggregation key." << std::endl;
			return -1;
		}
	}
	if(sort_key_flag == true)
	{
		if(sort_key == "bytes" || sort_key == "packets")
		{
			//std::cerr << "sort key je OK" << std::endl;
		}
		else
		{
			std::cerr << "Invalid sort key." << std::endl;
			return -1;
		}
	}

	/* vlozime vstupni pcap soubory do vectoru, ktery pak budeme postupne zpracovavat */
	for (int index = optind; index < argc; index++)
	{
		inputFiles.push_back(argv[index]);
	}

	/*****************************************************************************************************************************************************************************/
	/* definice potrebnych promennych */
	char errorBuffer[PCAP_ERRBUF_SIZE];
	unsigned int packet_counter = 1; 		//cislo udavajici cislo paketu. (kontrola limitu)
	pcap_t *handle = NULL;    		 	//descriptor aktualne otevreneho souboru
	const u_char *packet;      			//paket holder
	struct pcap_pkthdr header; 			//hlavicka paketu
	struct ether_header *eth_header = NULL; //hlavicka Ethernet
	struct ip *ip_header = NULL;
	struct ip6_hdr *ip6_header = NULL; 	//hlavicka pro ipv6
	u_int size_ip; 					//velikost hlavicky ip_datagramu
	struct tcphdr *tcp_header = NULL; 		//hlavicka TCP
	struct udphdr *udp_header = NULL; 		//hlavicka UDP
	struct icmp *icmp_header = NULL;  		//hlavicka icmpv4
	struct icmp6_hdr *icmp6_header = NULL;	//hlavicka icmpv6
	struct bpf_program fp;			 	//struktura, ve ktere se filter bude nachazet

	/* cyklus bude postupne prochazet vstupni soubory */
	for(auto file : inputFiles)
	{
		/* Otevreni souboru pro zpracovani */
		if((handle = pcap_open_offline(file.c_str(), errorBuffer)) == NULL)
		{
			std::cerr << "Error while opening input file " << file << std::endl;
			return -1;
		}

		if(TEST2_ENABLE) std::cout << "Uspesne otevren soubor: " << file << std::endl;

		/* spusteni filteru */
		if(filter_expression_flag == true)
		{
			if(pcap_compile(handle, &fp, filter_expression.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1)
			{
				std::cerr << "Error while compiling of a filter." << std::endl;
				return -1;
			}
			if(pcap_setfilter(handle, &fp))
			{
				std::cerr << "Error while installing of a filter." << std::endl;
				return -1;
			}
		}

		/* Cteme postupne pakety ze souboru, dokud tam nejake jsou */
		while((packet = pcap_next(handle, &header)) != NULL)
		{
			/* kontrola LIMITU */
			if(limit_flag == true && aggr_key_flag == false && sort_key_flag == false && packet_counter > limit)
			{
				//std::cerr << "Limit poctu vypsanych paketu byl dosazen!" << std::endl;
				break;
			}

			// trida obsahujici vsechny data analyzovaneho paketu
			ParsedPacket *output = new ParsedPacket(packet_counter);

			/* vypsat paket header informace */
			output->ts = std::to_string(((header.ts.tv_sec*1000000) + header.ts.tv_usec)); // TS
			output->len = header.len; // LEN

			/* Ethernet hlavicka - srcMAC destMAC */
			eth_header = (struct ether_header*) packet; // dstmac, srcmac

			char srcmacformatted[17]; // pole pro formatovanou MAC adresu
			char dstmacformatted[17]; // pole pro formatovanou MAC adresu
			sprintf(srcmacformatted, "%02x:%02x:%02x:%02x:%02x:%02x",eth_header->ether_shost[0], eth_header->ether_shost[1], eth_header->ether_shost[2], eth_header->ether_shost[3], eth_header->ether_shost[4], eth_header->ether_shost[5]);
			sprintf(dstmacformatted, "%02x:%02x:%02x:%02x:%02x:%02x",eth_header->ether_dhost[0], eth_header->ether_dhost[1], eth_header->ether_dhost[2], eth_header->ether_dhost[3], eth_header->ether_dhost[4], eth_header->ether_dhost[5]);
			output->srcMac = srcmacformatted;
			output->dstMac = dstmacformatted;

			int pocetIEEE = 0;
			int ether_type = ntohs(eth_header->ether_type);

			/* rezoluce IP typu nebo IEEE */
			while((ether_type != ETHERTYPE_IP && ether_type != ETHERTYPE_IPV6) && (ether_type == ETHERTYPE_VLAN || ether_type == 0x88A8)) // TODO upravit, pokud priijde jiny protokol nez tyhle 2 tak to pojede do nekonecna!!!!!!!!!!!!!!
			{
				/* IEEE 802.1Q VLAN tagging  (0x8100) || IEEE 802.1ad VLAN tagging (0x88A8) */
				if(ether_type == ETHERTYPE_VLAN || ether_type == 0x88A8)
				{
					struct vlan_t *vlan = (struct vlan_t*) (packet+14 + pocetIEEE*4);

					output->IEEEval += std::to_string((ntohs(vlan->tpid)& 0xFFF));
					output->IEEEval += " ";

					ether_type = ntohs(vlan->vlanid);
					pocetIEEE++;
				}
				else
				{
					std::cerr << "Wrong IEEE tag detected." << std::endl;
					break;
				}
				//std::cout << "smycka!!" << std::endl;
			}

			/* Rezoluce IP typu */
			int IEEE_offset = pocetIEEE * 4;
			switch(ether_type)
			{
				case ETHERTYPE_IP: // IPv4 paket (0x0800)
				{
					ip_header = (struct ip*) (packet + SIZE_ETHERNET + IEEE_offset); // skip Ethernet header
		      		size_ip = ip_header->ip_hl * 4;

					output->l3Protocol = "IPv4";
					output->srcIP = inet_ntoa(ip_header->ip_src);         // zdrojova IP
					output->dstIP = inet_ntoa(ip_header->ip_dst);	    // cilova IP
					output->ttlorhop = std::to_string(ip_header->ip_ttl); // time to live

					/**************************************************************************************************************************************************************************************/
					/********************************************************************** FRAGMENTACE ***************************************************************************************************/
					/**************************************************************************************************************************************************************************************/
					bool isPacketCompleted = false;
					u_char completedPacket[1000];

					/* TODO kontrola fragmentace: ip_chk(pouzit po seskladani celeho paketu),.. */
					if(((ntohs(ip_header->ip_off) & IP_DF) == false)) // DF == 0 - lze fragmentovat
					{
						unsigned int fragOff = (ntohs(ip_header->ip_off) & 0xFF);
						// (OFF == 0 && MF == 1) || (OFF > 0 && MF == 1) || (MF == 0 && OFF > 0)
						if((((ntohs(ip_header->ip_off) & 0xFF) == 0) && (ntohs(ip_header->ip_off) & IP_MF)) ||
						   (((ntohs(ip_header->ip_off) & 0xFF) > 0)  && (ntohs(ip_header->ip_off) & IP_MF)) ||
						   (((ntohs(ip_header->ip_off) & 0xFF) > 0)  && (((ntohs(ip_header->ip_off) & IP_MF) == false)))
					     )
						{
							bool found = false;

							/* prochazim pole rozdelanych nekompletnich paketu a hledam shodu, abych mohl zaradit fragment */
							if( !fragmentedPackets.empty())
							{
								for(auto fragPack : fragmentedPackets)
								{
									/* pokud je nalezen paket, do ktereho fragment patri, tak... */
									if(compareFragments(fragPack, ip_header->ip_id, (int)ip_header->ip_p, inet_ntoa(ip_header->ip_src), inet_ntoa(ip_header->ip_dst)))
									{
										found = true;
										using std::cout;
										using std::endl;

										// ulozime si obsah L4 vrsvy (preskocime L2 a L3)
										struct message *mess = (struct message*) (packet + SIZE_ETHERNET + IEEE_offset + size_ip);
										uint len = strlen((const char*)mess->msg);
										u_char *ptr = new u_char [len+1];

										for(uint i = 0; i < len; i++) ptr[i] = mess->msg[i];
										ptr[len] = '\0';

										std::pair<unsigned int, u_char *> newPair;
										newPair.first = fragOff;
										newPair.second = ptr;
										fragPack->fragments.push_back(newPair);

										/* pokud je fragment POSLEDNI, zjistime jeho delku a tu pak budeme dÄlit 8 (tak asi nebudem) a
										kontrolovat, jestli je vysledek rovny poctu prichozich fragmentu */
										if(((ntohs(ip_header->ip_off) & 0xFF) > 0)  && (((ntohs(ip_header->ip_off) & IP_MF) == false)))
										{
											fragPack->lastLen = (ntohs(ip_header->ip_off) & 0xFF);
										}

										/* Pokud je paket kompletni... */
										if(fragPack->lastLen == fragPack->fragments.size() -1 )
										{
											//std::cout << "Fragment je Kompletni!" << std::endl;
											uint buffIndex = 0;
											isPacketCompleted = true;

											// seradime podle offsetu
											std::sort(fragPack->fragments.begin(), fragPack->fragments.end(), [](auto &left, auto &right) {return left.first < right.first;});

											// -zkontrolovat prekryti a duplikaci
											// -vlozit (pouze) hlavicky L4 do bufferu
											// -z nej vycist data a vypsat/vlozit do agregace...

											/*******vvvvvvvvvvvvvv*********/

											/* jen vypis
											std::cout << std::endl << "-----vv-------------" << std::endl;
											for(uint i = 0; i < fragPack->fragments.size(); i++)
											{
												for(uint fin = 0; fin < strlen((const char*)fragPack->fragments[i].second); fin++)
												{
													std::cout << fragPack->fragments[i].second[fin];
												}
											}
											std::cout << std::endl << "-------^^----------" << std::endl;
											*/

											for(uint i = 0; i < fragPack->fragments.size(); i++)
											{
												for(uint fin = 0; fin < strlen((const char*)fragPack->fragments[i].second); fin++)
												{
													completedPacket[buffIndex++] = fragPack->fragments[i].second[fin];
												}
											}
											//std::cout << "My packet: " << completedPacket << std::endl;



											/**********^^^^^^^^^^^^^^************/
										}

										/* nasli jsme, kam fragment patri, takze uz nemusime dal prohledavat pole */
										break;
									}
								}
							}

							// pokud jsme nenalezli misto pro fragment, zalozime nove misto
							if(found == false)
							{
								//std::cout << "Vytvarim novy zaznam pro novy paket a jeho fragmenty" << std::endl;
								FragmentIdentificator *newPacketFrag = new FragmentIdentificator();
								newPacketFrag->fragment_id = ip_header->ip_id;
								newPacketFrag->srcip = inet_ntoa(ip_header->ip_src);
								newPacketFrag->dstip = inet_ntoa(ip_header->ip_dst);
								newPacketFrag->protocol = (int)ip_header->ip_p;

								struct message *mess = (struct message*) (packet+ SIZE_ETHERNET + IEEE_offset + size_ip);
								uint len = strlen((const char*)mess->msg);
								u_char *ptr = new u_char [len+1];

								for(uint i = 0; i < len; i++) ptr[i] = mess->msg[i];
								ptr[len] = '\0';

								std::pair <unsigned int, u_char *> newPair;
								newPair.first = fragOff;
								newPair.second = ptr;
								newPacketFrag->fragments.push_back(newPair);

								fragmentedPackets.push_back(newPacketFrag);

								/* pokud je fragment POSLEDNI, zjistime jeho delku a tu pak budeme dÄlit 8 (tak asi nebudem) a
								kontrolovat, jestli je vysledek rovny poctu prichozich fragmentu */
								if(((ntohs(ip_header->ip_off) & 0xFF) > 0)  && (((ntohs(ip_header->ip_off) & IP_MF) == false)))
								{
									newPacketFrag->lastLen = (ntohs(ip_header->ip_off) & 0xFF);
								}
							}

							/* vypisu si rozdelane pakety */
							//std::cout << std::endl;
							//for(auto fr : fragmentedPackets)
							//{
								//std::cout << "Param. frag. paketu: id:" << fr->fragment_id << " protocol:" << fr->protocol << " dstip:" << fr->dstip << " srcip:" << fr->srcip << " lastLen:" << fr->lastLen << " ||| POCET FRAGMENTU ZDE: " << fr->fragments.size() <<  std::endl;
							//}

							/* pokud je paket kompletni, tak budem pokracovat ve zpracovani paketu, jinak nacteme novy paket */
							if(isPacketCompleted == false)
								continue;
						}
					}
					/**************************************************************************************************************************************************************************************/


					/* Rezoluce L4 protokolu */
					switch(ip_header->ip_p)  //IPPPROTO_*
					{
						case 6: // TCP protocol
						{
							if(isPacketCompleted)
								tcp_header = (struct tcphdr*) (completedPacket);
							else
								tcp_header = (struct tcphdr*) (packet + SIZE_ETHERNET + IEEE_offset + size_ip);

							parseTcpHeader(output, tcp_header);
						}
						break;

						case 17: // UDP protocol
						{
							if(isPacketCompleted)
								udp_header = (struct udphdr*) (completedPacket);
							else
								udp_header = (struct udphdr*) (packet + SIZE_ETHERNET + IEEE_offset + size_ip);

							parseUdpHeader(output, udp_header);
						}
						break;

						case 1: // ICMP protokol
						{
							output->icmpv4flag = true;
							output->l4Protocol = "ICMPv4";

							if(isPacketCompleted)
								icmp_header = (struct icmp*) (completedPacket);
							else
								icmp_header = (struct icmp*) (packet + SIZE_ETHERNET + IEEE_offset+size_ip);

							output->icmpType = std::to_string((int)icmp_header->icmp_type);
							output->icmpCode = std::to_string((int)icmp_header->icmp_code);

							int icmpcode = icmp_header->icmp_code;
							switch(icmp_header->icmp_type)
							{
								case  0: // echorep
									output->icmpTypeDesc = "Echo reply";
									break;

								case  3: // unreach
								{
									output->icmpTypeDesc = "Destination unreachable";
									if(icmpcode == 0)  output->icmpCodeDesc = " Network unreachable"; //net-unr
									if(icmpcode == 1)  output->icmpCodeDesc = " Host unreachable"; //host-unr
									if(icmpcode == 2)  output->icmpCodeDesc = " Protocol unreachable"; //proto-unr
									if(icmpcode == 3)  output->icmpCodeDesc = " Port unreachable"; // port-unr
									if(icmpcode == 4)  output->icmpCodeDesc = " Fragmentation needed but DF bit set"; //needfrag
									if(icmpcode == 5)  output->icmpCodeDesc = " Source routing failed"; // srcfail
									if(icmpcode == 6)  output->icmpCodeDesc = " Network unknown"; //net-unk
									if(icmpcode == 7)  output->icmpCodeDesc = " Host unknown"; //host-unk
									if(icmpcode == 8)  output->icmpCodeDesc = " Host isolated"; //isolate
									if(icmpcode == 9)  output->icmpCodeDesc = " Network administratively prohibited"; //net-prohib
									if(icmpcode == 10) output->icmpCodeDesc = " Host administratively prohibited"; //host-prohib
									if(icmpcode == 11) output->icmpCodeDesc = " Invalid TOS for network"; //net-tos
									if(icmpcode == 12) output->icmpCodeDesc = " Invalid TOS for host"; //host-tos
									if(icmpcode == 13) output->icmpCodeDesc = " Prohibited access"; //filter-prohib
									if(icmpcode == 14) output->icmpCodeDesc = " Precedence violation"; //host-preced
									if(icmpcode == 15) output->icmpCodeDesc = " Precedence cutoff"; //cutoff-preced
								}
								break;

								case  4: // squench
									output->icmpTypeDesc = "Packet loss, slow down";
									break;
								case  5: // redir
								{
									output->icmpTypeDesc = "Shorter route exists";
									if(icmpcode == 0) output->icmpCodeDesc = " Shorter route for network"; //redir-net
									if(icmpcode == 1) output->icmpCodeDesc = " Shorter route for host"; //edir-host
									if(icmpcode == 2) output->icmpCodeDesc = " Shorter route for TOS and network"; //redir-tos-net
									if(icmpcode == 3) output->icmpCodeDesc = " Shorter route for TOS and host"; //redir-tos-host
								}
								break;

								case  6: // althost
									output->icmpTypeDesc = "Alternate host address";
								break;

								case  8: // echoreq
									output->icmpTypeDesc = "Echo request";
								break;

								case  9: // routeradv
								{
									output->icmpTypeDesc = "Router advertisement";
									if(icmpcode == 0) output->icmpCodeDesc = " Normal advertisement"; //normal-adv
									if(icmpcode == 16) output->icmpCodeDesc = " Selective advertisement"; //common-adv
								}
								break;

								case 10: // routersol
									output->icmpTypeDesc = "Router solicitation";
									break;

								case 11: // timex
								{
									output->icmpTypeDesc = "Time exceeded";
									if(icmpcode == 0) output->icmpCodeDesc = " Time exceeded in transit"; // transit
									if(icmpcode == 1) output->icmpCodeDesc = " Time exceeded in reassembly"; // reassemb
								}
								break;

								case 12: // paramprob
								{
									output->icmpTypeDesc = "Invalid IP header";
									if(icmpcode == 0) output->icmpCodeDesc = " Invalid option pointer"; // badhead
									if(icmpcode == 1) output->icmpCodeDesc = " Missing option"; // optmiss
									if(icmpcode == 2) output->icmpCodeDesc = " Invalid length"; // badlen
								}
								break;

								case 13: // timereq
									output->icmpTypeDesc = "Timestamp request";
									break;

								case 14: // timerep
									output->icmpTypeDesc = "Timestamp reply";
									break;

								case 15: // inforeq
									output->icmpTypeDesc = "Information request";
									break;

								case 16: // inforep
									output->icmpTypeDesc = "Information reply";
									break;

								case 17: // maskreq
									output->icmpTypeDesc = "Address mask request";
									break;

								case 18: // maskrep
									output->icmpTypeDesc = "Address mask reply";
									break;

								case 30: // trace
									output->icmpTypeDesc = "Traceroute";
									break;

								case 31: // dataconv
									output->icmpTypeDesc = "Data conversion problem";
									break;

								case 32: // mobredir
									output->icmpTypeDesc = "Mobile host redirection";
									break;

								case 33: // ipv6-where
									output->icmpTypeDesc = "IPv6 where-are-you";
									break;

								case 34: // ipv6-here
									output->icmpTypeDesc = "IPv6 i-am-here";
									break;

								case 35: // mobregreq
									output->icmpTypeDesc = "Mobile registration request";
									break;

								case 36: // mobregrep
									output->icmpTypeDesc = "Mobile registration reply";
									break;

								case 39: // skip
									output->icmpTypeDesc = "SKIP";
									break;

								case 40: // photuris
								{
									output->icmpTypeDesc = "Photuris";
									if(icmpcode == 1) output->icmpCodeDesc = " Unknown security index"; //unknown-ind
									if(icmpcode == 2) output->icmpCodeDesc = " Authentication failed"; //auth-fail
									if(icmpcode == 3) output->icmpCodeDesc = " Decryption failed"; //decrypt-fail
								}
								break;

								default:
									output->icmpTypeDesc = "";
									output->icmpCodeDesc = "";
									break;
							} //switchEND
						} //KONEC ICMP
						break;

						default: // jiny nez icmp, tcp, udp
							std::cerr << "Unresolved L4 protocol ( Protocol no.: "+ std::to_string(ip_header->ip_p)+" ). Paket dropped." << std::endl;
							output->valid = false;
							packet_counter--;

						break;
					} //KONEC switch(ICMP/UDP/TCP)
				} //KONEC ETHERTYPE_IPv4
				break;

				case ETHERTYPE_IPV6: // IPv6 paket (0x86DD)
				{
					ip6_header = (struct ip6_hdr*) (packet + SIZE_ETHERNET + IEEE_offset); // skip Ethernet header

					char srcIP[INET_ADDRSTRLEN];

					output->l3Protocol = "IPv6";
					output->srcIP = inet_ntop(AF_INET6, &(ip6_header->ip6_src), srcIP, INET6_ADDRSTRLEN);
					output->dstIP = inet_ntop(AF_INET6, &(ip6_header->ip6_dst), srcIP, INET6_ADDRSTRLEN);
					output->ttlorhop = std::to_string(ip6_header->ip6_hlim);

					/* IPv6 extended header zpracovani */
					u_int8_t next_header_type = (int)ip6_header->ip6_nxt;

					if(TEST2_ENABLE) std::cout << std::endl << "------" <<(int)next_header_type << "---OK---" << std::endl;

					bool found = false;
					int final_extension_offset = 0; // offset nutny k preskoceni vsech ipv6 extended hlavicek

					if(next_header_type != 1 && next_header_type != 6 && next_header_type != 17)
					{
						bool modify_offset = false;

						while(!found && next_header_type != 1 && next_header_type != 6 && next_header_type != 17)
						{
							// hop by hop option (val: 0)
							if(next_header_type == IPPROTO_HOPOPTS)
							{
								if(TEST2_ENABLE) std::cout << std::endl << "Hop-By-Hop Options header" << std::endl;
								modify_offset = true;
							}
 							// destination option header (val: 60)
							else if(next_header_type == IPPROTO_DSTOPTS)
							{
								if(TEST2_ENABLE) std::cout << std::endl << "Destionation options" << std::endl;
								modify_offset = true;
							}
							// routing header (val: 43)
							else if(next_header_type == 43)
							{
								if(TEST2_ENABLE) std::cout << std::endl << "ROUTING" << std::endl;
								modify_offset = true;
							}
							// fragmentation header (val: 44)
							else if(next_header_type == IPPROTO_FRAGMENT)
							{
								if(TEST2_ENABLE) std::cout << std::endl << "FRAGMENT" << std::endl;
								modify_offset = true;
							}
							// Authentication header (val: 51)
							else	if(next_header_type == IPPROTO_AH)
							{
								if(TEST2_ENABLE) std::cout << std::endl << "Authentisation Header" << std::endl;
								modify_offset = true;
							}
							// encapsulation security payload (val: 50)
							else	if(next_header_type == IPPROTO_ESP)
							{
								if(TEST2_ENABLE) std::cout << std::endl << "Encapsulating security payload header" << std::endl;
								// ?????????????????
							}

							else if(next_header_type == IPPROTO_ICMPV6)
							{
								if(TEST2_ENABLE) std::cout << std::endl << "ICMPV6" << std::endl;
								next_header_type = 1;
								found = true;
							}
							// ipv6 NO NEXT HEADER (val: 59)
							else if(next_header_type == IPPROTO_NONE)
							{
								std::cerr << "IPv6 Extended Header: ( 59 - No Next Header ). Paket dropped." << std::endl;
								if(TEST2_ENABLE) std::cout << std::endl << "NONE" << std::endl;
								found = true;
								output->valid = false;
								packet_counter--;
							}

							// uprava offsetu -> pricteni delky ext hlavicky k aktualnimu offsetu
							if(modify_offset == true)
							{
								// spolecne pro hlavicky
								struct ipv6_ext_hdr *extended = (struct ipv6_ext_hdr*) (packet + SIZE_ETHERNET + IEEE_offset + SIZE_IPV6 + final_extension_offset);
								next_header_type = extended->next;
								final_extension_offset += (8 * (1 + (int)extended->len));

								if(TEST2_ENABLE) std::cout << "dalsi ipv6 hlavicka bude: " << (int)next_header_type << std::endl;
								if(TEST2_ENABLE) std::cout << "Len: " << (int)extended->len << std::endl;
							}
						}
					}

					/** L4 Rezoluce a zpracovani **/
					switch(next_header_type)
					{
						case 1: // ICMPv6 protokol
						{
							output->icmpv6flag = true;
							output->l4Protocol = "ICMPv6";
							icmp6_header = (icmp6_hdr*) (packet + SIZE_ETHERNET + IEEE_offset + SIZE_IPV6 + final_extension_offset);

							output->icmpType = std::to_string((int)icmp6_header->icmp6_type);
							output->icmpCode = std::to_string((int)icmp6_header->icmp6_code);

							int icmp6code = icmp6_header->icmp6_code;
							switch((int)icmp6_header->icmp6_type)
							{
								case 1: //unreach
								{
									output->icmpTypeDesc = "Destination Unreachable";
									if(icmp6code == 0) output->icmpCodeDesc = " No route to destination"; //noroute-unr
									if(icmp6code == 1) output->icmpCodeDesc = " Communication with destination administratively prohibited"; //admin-unr
									if(icmp6code == 2) output->icmpCodeDesc = " Beyond scope of source address"; //beyond-unr
									if(icmp6code == 3) output->icmpCodeDesc = " Address unreachable"; //addr-unr
									if(icmp6code == 4) output->icmpCodeDesc = " Port unreachable"; //port-unr
									if(icmp6code == 5) output->icmpCodeDesc = " Source address failed ingress/egress policy"; //port-unr
									if(icmp6code == 6) output->icmpCodeDesc = " Reject route to destination"; //port-unr
								}
								break;

								case 2: //toobig
									output->icmpTypeDesc = "Packet Too Big";
									break;

								case 3: //timex
								{
									output->icmpTypeDesc = "Time Exceeded";
									if(icmp6code == 1) output->icmpCodeDesc = " Fragment reassembly time exceeded"; //reassemb
									if(icmp6code == 0) output->icmpCodeDesc = " Hop limit exceeded in transit"; //transit
								}
								break;

								case 4: //paramprob
								{
									output->icmpTypeDesc = "Destination Unreachable";
									if(icmp6code == 0) output->icmpCodeDesc = " Erroneous header field encountered"; //Codes 1 and 2 are more informative subsets of Code 0.
									if(icmp6code == 1) output->icmpCodeDesc = " Unrecognized Next Header type encountered";
									if(icmp6code == 2) output->icmpCodeDesc = " Unrecognized IPv6 option encountered";
								}
								break;

								case 128:
								{
									output->icmpTypeDesc = "Echo Request";
								}
								break;

								case 129:
								{
									output->icmpTypeDesc = "Echo Reply";
								}
								break;

								default:
									output->icmpTypeDesc = "";
									output->icmpCodeDesc = "";
								break;
							} // KONEC switch
						}
						break;

						case 6: // TCP protocol
						{
							tcp_header = (struct tcphdr*) (packet + SIZE_ETHERNET + IEEE_offset + SIZE_IPV6 + final_extension_offset);
							parseTcpHeader(output, tcp_header);
						}
						break;

						case 17: // UDP protocol
						{
							udp_header = (struct udphdr*) (packet + SIZE_ETHERNET + IEEE_offset + SIZE_IPV6 + final_extension_offset);
							parseUdpHeader(output, udp_header);
						}
						break;

						default:
						{
							output->l4Protocol = "JINE";
							output->valid = false;
							packet_counter--;

							std::cerr << "Unresolved L4 protocol ( Protocol no.: "+ std::to_string(next_header_type) + " ). Packet dropped" << std::endl;
						}
						break;
					} // KONEC switch (tcp/udp/icmp)
					break;

				}
				default:
				{
					std::cerr << "Unresolved L3 protocol ( Protocol no.: "+ std::to_string(ether_type)+" ). Packet dropped." << std::endl;
					output->valid = false;
					packet_counter--;
				}
				break;

			} // konec switch

			packet_counter++;

			/* vypsani / vlozeni paketu do vectoru */
			if(aggr_key_flag == true)
			{
				if(aggr_key == "srcmac"){
					if(!output->srcMac.empty()){
						packetAggregation[output->srcMac].first += 1;
						packetAggregation[output->srcMac].second += output->len;
					}
				}
				if(aggr_key == "dstmac"){
					if(!output->dstMac.empty()){
						packetAggregation[output->dstMac].first += 1;
						packetAggregation[output->dstMac].second += output->len;
					}
				}
				if(aggr_key == "srcip"){
					if(!output->srcIP.empty()){
						packetAggregation[output->srcIP].first += 1;
						packetAggregation[output->srcIP].second += output->len;
					}
				}
				if(aggr_key == "dstip"){
					if(!output->dstIP.empty()){
						packetAggregation[output->dstIP].first += 1;
						packetAggregation[output->dstIP].second += output->len;
					}
				}
				if(aggr_key == "srcport"){
					if(!output->srcPort.empty()){
						packetAggregation[output->srcPort].first += 1;
						packetAggregation[output->srcPort].second += output->len;
					}
				}
				if(aggr_key == "dstport"){
					if(!output->dstPort.empty()){
						packetAggregation[output->dstPort].first += 1;
						packetAggregation[output->dstPort].second += output->len;
					}
				}
			}
			else if(sort_key_flag == true)
			{
				if(output->valid == true) // pokud packet neobsahuje neznamy protokol
					packetSorting.push_back(output);
			}
			else
			{
				output->assemble();
				delete output;
			}
		}

		/* konec souboru byl dosazen */
		if(TEST2_ENABLE) std::cout << "Konec souboru " << file << std::endl;
		if(TEST2_ENABLE) std::cout << std::endl;

		/* zavreme zpracovany soubor */
		pcap_close(handle);
	}

	if(aggr_key_flag == true && sort_key_flag == true)
	{
		// kvuli sortovani podle hodnot ve value presunu mapu do vectoru dvojic typu string a dvojice int(packety) a int(bytes)
		std::vector<std::pair<std::string, std::pair<int,int> > > aggregation(packetAggregation.size());
		int i = 0;
		for(auto packet: packetAggregation)
		{
			aggregation[i].first = packet.first;
			aggregation[i].second.first = packet.second.first;
			aggregation[i].second.second = packet.second.second;
			i++;
		}

		if(sort_key == "bytes") std::sort(aggregation.begin(), aggregation.end(), [](auto &left, auto &right)   {return left.second.second > right.second.second;});
		if(sort_key == "packets") std::sort(aggregation.begin(), aggregation.end(), [](auto &left, auto &right) {return left.second.first > right.second.first;});

		uint lim = 0;
		for(auto packet: aggregation)
		{
			if(limit_flag)
			{
				lim++;
				if(lim > limit)
					break;
			}
			std::cout << packet.first << ": " << packet.second.first << " " << packet.second.second << std::endl;
		}
	}
	else if(aggr_key_flag == true && sort_key_flag == false)
	{
		uint lim = 0;
		for(auto packet: packetAggregation)
		{
			if(limit_flag)
			{
				lim++;
				if(lim > limit)
					break;
			}
			std::cout << packet.first << ": " << packet.second.first << " " << packet.second.second << std::endl;
		}
	}
	else if(sort_key_flag == true && aggr_key_flag == false)
	{
		if(sort_key == "bytes")
		{
			std::sort(packetSorting.begin(), packetSorting.end(), compareBytes);
		}

		uint lim = 0;
		for(auto packet: packetSorting)
		{
			if(limit_flag)
			{
				lim++;
				if(lim > limit)
					break;
			}

			packet->assemble();
			delete packet;
		}
	}

	/***********************************************************************************************/
	inputFiles.clear();
	packetAggregation.clear();
	packetSorting.clear();
} /* </MAIN> */
