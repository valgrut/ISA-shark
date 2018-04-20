Isashark

Popis:
  Isashark je off-line analyzátor paketù, který doká¾e vyèíst data z hlavièek podporovaných protokolù a následnì je vypsat nebo je dále zpracovat podle argumentù programu. 
  Na vstupu oèekává soubry .pcap obsahující pakety urèené k rozboru. 
  Formát výstupu závisí na vstupních argumentech. Viz usage.

Omezení a roz¹íøení:
  Defragmentace ipv4 - zvolil jsem vlastní implementaci zpracování fragmentace, která se ukázala jako nevyhovující v pøípadì pøekrývání fragmentù a u dvou posledních hodnot u TCP. Hlavièka UDP je v poøádku.
  ¾ádná dal¹í omezení nejsou a v¹e ostatní by mìlo fungovat korektnì.

Pøeklad:
  Pøeklad se spustí pomocí pøíkazu "make".

Usage:
  isashark [-h] [-a aggr-key] [-s sort-key] [-l limit] [-f filter-expression] file ...

pøíklady pou¾ití:

  ./isashark -h
	Vypí¹e nápovìdu a ukonèí program.

  ./isashark -a dstip inputfile.pcap
	Agregace paketù podle zadaného klíèe - v tomto pøípadì dstip.

  ./isashark -l 20 inputfile.pcap
	Vypí¹e maximálnì 20 paketù.

  ./isashark -f "src host 2001:db8::1" inputfile.pcap
	Zpracovává pouze pakety, které vyhovují filtru.


Odevzdané soubory:
	isashark.cpp
	isashark.h
	Makefile
	README
	manual.pdf 
