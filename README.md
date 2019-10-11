# Isashark

## Popis:
    Isashark je off-line analyz�tor paket�, kter� dok�e vuy��t data z hlavi�ek podporovan�ch protokol� a n�sledn� je vypsat nebo je d�le zpracovat podle argument� programu.
    Na vstupu o�ek�v� soubory .pcap obsahuj�c� pakety ur�en� k rozboru.
    Form�t v�stupu z�vis� na vstupn�ch argumentech. Viz usage.

### Omezen� a roz��en�:
    Defragmentace ipv4 - zvolil jsem vlastn� implementaci zpracov�n� fragmentace, kter� se uk�zala jako nevyhovuj�c� v p��pad� p�ekr�v�n� fragment� a u dvou posledn�ch hodnot u TCP. Hlavi�ka UDP je v po��dku.
    ��dn� dal�� omezen� nejsou a v�e ostatn� by m�lo fungovat korektn�.

### P�eklad:
    P�eklad se spust� pomoc� p��kazu "make".

### Usage:
```
    isashark [-h] [-a aggr-key] [-s sort-key] [-l limit] [-f filter-expression] file ...
```
### P��klady pou�it�:
```
    ./isashark -h
        Vyp�e n�pov�du a ukon�� program.

    ./isashark -a dstip inputfile.pcap
        Agregace paket� podle zadan�ho kl�e - v tomto p��pad� 'dstip'.

    ./isashark -l 20 inputfile.pcap
        Vyp�e maxim�ln� 20 paket�.

    ./isashark -f "src host 2001:db8::1" inputfile.pcap
        Zpracov�v� pouze pakety, kter� vyhovuj� filtru.
```

### Odevzdan� soubory:
- isashark.cpp
- isashark.h
- Makefile
- README
- manual.pdf
