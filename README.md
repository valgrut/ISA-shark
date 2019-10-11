# Isashark

## Popis:
    Isashark je off-line analyzátor paket¿, který doká¿e vuy¿ít data z hlavi¿ek podporovaných protokol¿ a následn¿ je vypsat nebo je dále zpracovat podle argument¿ programu.
    Na vstupu o¿ekává soubory .pcap obsahující pakety ur¿ené k rozboru.
    Formát výstupu závisí na vstupních argumentech. Viz usage.

### Omezení a roz¿í¿ení:
    Defragmentace ipv4 - zvolil jsem vlastní implementaci zpracování fragmentace, která se ukázala jako nevyhovující v p¿ípad¿ p¿ekrývání fragment¿ a u dvou posledních hodnot u TCP. Hlavi¿ka UDP je v po¿ádku.
    ¿ádná dal¿í omezení nejsou a v¿e ostatní by m¿lo fungovat korektn¿.

### P¿eklad:
    P¿eklad se spustí pomocí p¿íkazu "make".

### Usage:
```
    isashark [-h] [-a aggr-key] [-s sort-key] [-l limit] [-f filter-expression] file ...
```
### P¿íklady pou¿ití:
```
    ./isashark -h
        Vypí¿e nápov¿du a ukon¿í program.

    ./isashark -a dstip inputfile.pcap
        Agregace paket¿ podle zadaného klí¿e - v tomto p¿ípad¿ 'dstip'.

    ./isashark -l 20 inputfile.pcap
        Vypí¿e maximáln¿ 20 paket¿.

    ./isashark -f "src host 2001:db8::1" inputfile.pcap
        Zpracovává pouze pakety, které vyhovují filtru.
```

### Odevzdané soubory:
- isashark.cpp
- isashark.h
- Makefile
- README
- manual.pdf
