/***********************************

        Autor:  Matej Slivka
        login:  xslivk03
        IPK Projekt 2
        Sniffer packetov
        
***********************************/
Zoznam odovzdaných súborov: README.md ,packet-sniffer.cpp, manual.pdf , Makefile
Implementacia packet snifferu v predmete Počítačové komunikácie a siete
Packet sniffer dokaže spracovať protokoly ICMP UDP ARP TCP

Projekt bol implementovany v jazyku C++

**** Prerekvizity:
        Linuxovy OS
        zdrojový súbor packet-sniffer.cpp
        Makefile
        prekladací systém make

**** Inštalácia:
        1. do jedného súboru si rozbalíme zdrojový súbor packet-sniffer.cpp a Makefile
        2. spustime Makefile pomocou konzole a príkazu [make]
        3. tymto by sa nám mal vytvoriť spustiteľný súbor [ipk-sniffer]

**** Spustenie:
        Program by sa mal spustiť pomocou príkazu
        ./ipk-sniffer [-i rozhraní | --interface rozhraní] {-p ­­port} {[--tcp|-t] [--udp|-u] [--arp] [--icmp] } {-n num}
        kde 
            -i alebo --interface je rozhranie z ktoreho budu packety čitané
            -p je číslo portu ktoré môže bližšie špecifikovať TCP alebo UDP protokoly
            --tcp alebo -t je parameter ktorý špecifkuje či sa budu vypisovať TCP packety
            --udp alebo -u je parameter ktorý špecifkuje či sa budu vypisovať UDP packety
            --arp je parameter ktorý špecifkuje či sa budu vypisovať ARP packety
            --icmp je parameter ktorý špecifkuje či sa budu vypisovať ICMP packety
            -n je parameter ktorý špecifkuje koľko packetov sa ma vypisať

        Je nutne spustiť progam ako super user.
        Príklad spustenia:
        sudo ./ipk-sniffer  --udp --tcp  -i eth0 -n 5

        timestamp    : 2022-04-24T19:30:47.432378 + 2:00
        src MAC      : 0:15:5d:a2:3f:66
        dst MAC      : 1:0:5e:0:0:fb
        frame length : 87 bytes
        src IP       : 172.28.160.1
        dst IP       : 224.0.0.251
        src port     : 5353
        dst port     : 5353

        0x0000: 01 00 5e 00 00 fb 00 15  5d a2 3f 66 08 00 45 00   ..^..... ].?f..E.
        0x0010: 00 49 9f 5e 00 00 ff 11  ef 2b ac 1c a0 01 e0 00   .I.^.... .+......
        0x0020: 00 fb 14 e9 14 e9 00 35  81 59 00 00 00 00 00 01   .......5 .Y......
        0x0030: 00 00 00 00 00 00 10 5f  73 70 6f 74 69 66 79 2d   ......._ spotify-
        0x0040: 63 6f 6e 6e 65 63 74 04  5f 74 63 70 05 6c 6f 63   connect. _tcp.loc
        0x0050: 61 6c 00 00 0c 00 01   
**** Poznámka k implementácii:
        Pri spustení program s argumentom -i, do ktorého nebola prirdená žiadna hodnota, vypisať všetky dostupné rozhrania.
        Túto funkčnosť program nemá. Ak je treba vypisať všetky rozhrania tak je potrebné argument nevypísať.
        Teda treba spustiť program ako:         sudo ./ipk-sniffer      namiesto         sudo ./ipk-sniffer  -i

Projekt bol testovaný porovnaním outputov s Wirsharkom
