# Isashark
English version [here](README.md).

## Popis:
    Isashark je offline analyzátor paketů, který dokáže využít data z hlaviček podporovaných protokolů a následně je vypsat nebo dále zpracovat dle předaných přepínačů a argumentů programu.
    Program na vstupu očekává soubory .pcap obsahující pakety určené k rozboru.
    Záznamové soubory internetové komunikace lze získat například z programu Wireshark.
    Formát výstupu závisí na vstupních argumentech, viz. Použití.

### Rozšíření a známá omezení:
    Defragmentace ipv4 - zvolil jsem vlastní implementaci zpracování fragmentace, která se ale ukázala nedostatečná v případě překrývajících se fragmentů a u posledních dvou hodnot TCP hlaviček. Protokol UDP funguje dobře.
    Žádná další omezení nejsou známa.

## Překlad:
    Program je přeložen zadáním příkazu "make".

## Použití:
```
    isashark [-h] [-a aggr-key] [-s sort-key] [-l limit] [-f filter-expression] file ...
```

## Příklady:
```
    ./isashark -h
        Vypíše nápovědu a ukončí program s úspěchem.

    ./isashark -a dstip inputfile.pcap
        Agrefuje pakety podle daného klíče - v tomto případě "dstip".

    ./isashark -l 20 inputfile.pcap
        Vypíše maximálně 20 paketů.

    ./isashark -f "src host 2001:db8::1" inputfile.pcap
        Zpracuje pouze pakety vyhovující výrazu filtru.
```

## Submitted files:
- isashark.cpp
- isashark.h
- Makefile
- README.md
- manual.pdf
