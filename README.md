# Návod k překladu a používání programu

## Překlad

K překladu byl použit překladač GCC verze 10.2.1. Pro překlad je nutná také knihovna [libpcap](https://www.tcpdump.org). Při vývoji byla použita verze knihovny 1.10.0-2.
Kód by měl být překladatelný na libovolné Linuxové distribuci. Při vývoji byla použita distribuce Debian 11 s linuxovým jádrem verze 6.2.5.

Pro překlad je přiložený soubor Makefile. Nativní název binárního souboru, do kterého je program překládán je `BTMonitor`.
Tento název lze modifikovat argumentem `TRG` při volání příkazu `make` (make TRG=foo).

Soubor Makefile obsahuje cíl `build`, který je volán nativně. Pro překlad programu je třeba zavolat příkaz: `make`.
Soubor obsahuje také cíl `clean`, který vyčistí mezisoubory a binární soubor programu: `make clean`.

Pro vygenerování dokumentace je možné použít cíl `doxygen`. Tento cíl použije program Doxygen pro vytvoření HTML dokumentace do adresáře `docs`.

## Používání

Při používání programu v režimu aktivního monitorování je třeba program spouštět s právy uživatele root: `sudo ./BTMonitor`.
Program obsahuje argument `--help`, který vypíše veškeré možné argumenty programu.

Příklad používání v režimu aktivního monitorování:

    `sudo ./BTMonitor -i enp4s0 -f monitor.csv`

Příklad používání v režimu offline analýzy souboru pcap:

    `./BTMonitor -p packets.pcap -f monitor.csv`

