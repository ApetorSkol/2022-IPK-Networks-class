/***********************************

        Autor:  Matej Slivka
        Jednoduchý server
	
***********************************/

Server dokáže vrátiť domenové meno, informácie o CPU a aktualnú záťaž procesoru

Projekt bol implementovany v jazyku **C++**

## Prerekvizity:
- Linuxovy OS
- zdrojový súbor server.cpp
- Makefile
- prekladací systém make

## Inštalácia:
1. do jedného séboru si rozbalíme zdrojový súbor server.cpp a Makefile
2. spustime Makefile pomocou konzole a príkazu `make`
3. tymto by sa nám mal vytvoriť spustiteľný súbor `hinfosvc`

## Použitie:
### Server:
1. server sa spúšta cez konzolu zadaním príkazu 
    ```
    ./hinfosvc <port>
    ``` 
    kde `<port>` je číslo portu na ktorom bude server očakávať klienta.

2. server sa vypína pomocou klávesovej skraty CTRL + C
### Klient:
1. klient sa pripojuje na server pomocou konzole zadaním jedného z týchto troch príkazov (v priapde ze port je 12345)
    - `curl http://localhost:12345/hostname`
    - `curl http://localhost:12345/cpu-name`
    - `curl http://localhost:12345/load`
    
    kde 
    - `curl http://localhost:12345/hostname` vypíše sieťové meno počíťača na ktorom je server spustený. Na výstupe by mohlo byt napr.
        ```
        merlin.fit.vutbr.cz
        ```
    - `curl http://localhost:12345/cpu-name` vypíše informácie o procesoru. Na výstupe by mohlo byt napr.
        ```
        Intel(R) Xeon(R) CPU E5-2640 0 @ 2.50GHz
        ```
    - `curl http://localhost:12345/load` vypíše záťaž procesoru v percentách. Na výstupe by mohlo byť napr.
        ```
        13%
        ```

Projekt bol testovaný na servery `merlin.fit.vutbr.cz`
