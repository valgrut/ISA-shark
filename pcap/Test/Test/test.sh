#!/usr/bin/env bash
#author: Adam Skurla

# Subor isashark umiestnit do priecinku
# Spustit bash test.sh
# Ak sa nezhoduje vystup s referencnym, su vypisane na stdout

RUNFILE="isashark"

OUT_PATH="./ref/"
TN=0
#################################################################
TN=$(($TN+1))
./$RUNFILE eth_ipv4_tcp.pcap 2>ttt$TN.err 1> ttt$TN.out; echo $? 1> ttt$TN.exit
temp="$(cat ttt$TN.exit)"
if diff ttt$TN.out ${OUT_PATH}test01.out > /dev/null
then
	echo "TEST $TN RETURNED $temp OK"
else
	echo "TEST $TN: FAILED RETURNED: $temp"
	cat ${OUT_PATH}test01.out
	cat ttt$TN.out
fi
rm ttt$TN.out
rm ttt$TN.err
rm ttt$TN.exit
# #################################################################
TN=$(($TN+1))
./$RUNFILE eth_dot1q_ipv6_udp.pcap 2>ttt$TN.err 1> ttt$TN.out; echo $? 1> ttt$TN.exit
temp="$(cat ttt$TN.exit)"
if diff ttt$TN.out ${OUT_PATH}test02.out > /dev/null
then
	echo "TEST $TN RETURNED $temp OK"
else
	echo "TEST $TN: FAILED RETURNED: $temp"
	cat ${OUT_PATH}test02.out
	cat ttt$TN.out
fi
rm ttt$TN.out
rm ttt$TN.err
rm ttt$TN.exit
# #################################################################
TN=$(($TN+1))
./$RUNFILE eth_dot1ad_ipv4_icmpv4.pcap 2>ttt$TN.err 1> ttt$TN.out; echo $? 1> ttt$TN.exit
temp="$(cat ttt$TN.exit)"
if diff ttt$TN.out ${OUT_PATH}test03.out > /dev/null
then
	echo "TEST $TN RETURNED $temp OK"
else
	echo "TEST $TN: FAILED RETURNED: $temp"
	cat ${OUT_PATH}test03.out
	cat ttt$TN.out
fi
rm ttt$TN.out
rm ttt$TN.err
rm ttt$TN.exit
# #################################################################
TN=$(($TN+1))
./$RUNFILE eth_ipv6_icmpv6.pcap 2>ttt$TN.err 1> ttt$TN.out; echo $? 1> ttt$TN.exit
temp="$(cat ttt$TN.exit)"
if diff ttt$TN.out ${OUT_PATH}test04.out > /dev/null
then
	echo "TEST $TN RETURNED $temp OK"
else
	echo "TEST $TN: FAILED RETURNED: $temp"
	cat ${OUT_PATH}test04.out
	cat ttt$TN.out
fi
rm ttt$TN.out
rm ttt$TN.err
rm ttt$TN.exit
# #################################################################
TN=$(($TN+1))
./$RUNFILE mix.pcap 2>ttt$TN.err 1> ttt$TN.out; echo $? 1> ttt$TN.exit
temp="$(cat ttt$TN.exit)"
if diff ttt$TN.out ${OUT_PATH}test05.out > /dev/null
then
	echo "TEST $TN RETURNED $temp OK"
else
	echo "TEST $TN: FAILED RETURNED: $temp"
	cat ${OUT_PATH}test05.out
	cat ttt$TN.out
fi
rm ttt$TN.out
rm ttt$TN.err
rm ttt$TN.exit
# #################################################################
TN=$(($TN+1))
./$RUNFILE -f "src host 2001:db8::1" mix.pcap 2>ttt$TN.err 1> ttt$TN.out; echo $? 1> ttt$TN.exit
temp="$(cat ttt$TN.exit)"
if diff ttt$TN.out ${OUT_PATH}test06.out > /dev/null
then
	echo "TEST $TN RETURNED $temp OK"
else
	echo "TEST $TN: FAILED RETURNED: $temp"
	cat ${OUT_PATH}test06.out
	cat ttt$TN.out
fi
rm ttt$TN.out
rm ttt$TN.err
rm ttt$TN.exit
# #################################################################
TN=$(($TN+1))
./$RUNFILE -l 3 mix.pcap 2>ttt$TN.err 1> ttt$TN.out; echo $? 1> ttt$TN.exit
temp="$(cat ttt$TN.exit)"
if diff ttt$TN.out ${OUT_PATH}test07.out > /dev/null
then
	echo "TEST $TN RETURNED $temp OK"
else
	echo "TEST $TN: FAILED RETURNED: $temp"
	cat ${OUT_PATH}test07.out
	cat ttt$TN.out
fi
rm ttt$TN.out
rm ttt$TN.err
rm ttt$TN.exit
# #################################################################
TN=$(($TN+1))
./$RUNFILE -a srcip mix.pcap 2>ttt$TN.err 1> ttt$TN.out; echo $? 1> ttt$TN.exit
temp="$(cat ttt$TN.exit)"
if diff ttt$TN.out ${OUT_PATH}test08.out > /dev/null
then
	echo "TEST $TN RETURNED $temp OK"
else
	echo "TEST $TN: FAILED RETURNED: $temp"
fi
rm ttt$TN.out
rm ttt$TN.err
rm ttt$TN.exit
# #################################################################
TN=$(($TN+1))
./$RUNFILE -a srcip -s bytes mix.pcap 2>ttt$TN.err 1> ttt$TN.out; echo $? 1> ttt$TN.exit
temp="$(cat ttt$TN.exit)"
if diff ttt$TN.out ${OUT_PATH}test09.out > /dev/null
then
	echo "TEST $TN RETURNED $temp OK"
else
	echo "TEST $TN: FAILED RETURNED: $temp"
	cat ${OUT_PATH}test09.out
	cat ttt$TN.out
fi
rm ttt$TN.out
rm ttt$TN.err
rm ttt$TN.exit
# #################################################################
TN=$(($TN+1))
./$RUNFILE -s bytes mix.pcap 2>ttt$TN.err 1> ttt$TN.out; echo $? 1> ttt$TN.exit
temp="$(cat ttt$TN.exit)"
if diff ttt$TN.out ${OUT_PATH}test10.out > /dev/null
then
	echo "TEST $TN RETURNED $temp OK"
else
	echo "TEST $TN: FAILED RETURNED: $temp"
fi
rm ttt$TN.out
rm ttt$TN.err
rm ttt$TN.exit
# #################################################################
TN=$(($TN+1))
./$RUNFILE fragmentation.pcap 2>ttt$TN.err 1> ttt$TN.out; echo $? 1> ttt$TN.exit
temp="$(cat ttt$TN.exit)"
if diff ttt$TN.out ${OUT_PATH}test11.out > /dev/null
then
	echo "TEST $TN RETURNED $temp OK"
else
	echo "TEST $TN: FAILED RETURNED: $temp"
fi
rm ttt$TN.out
rm ttt$TN.err
rm ttt$TN.exit
# #################################################################
