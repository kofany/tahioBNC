# tahioBNC - prosty Bouncer sieci IRC z obsługą vhostów

tahioBNC to prosty Bouncer sieci IRC napisany w języku Python z obsługą vhostów. Program umożliwia połączenie się z serwerem IRC za pośrednictwem bouncera.

## Dostępne komendy

* `/quote vh4 <IPv4 address>` - Ustawia IPv4 VHOST.
* `/quote vh6 <IPv6 address>` - Ustawia IPv6 VHOST.
* `/quote vh` - Wyświetla dostępne adresy IPv4 i IPv6.
* `/quote conn4 <server> <port>` - Łączy się z serwerem IRC za pomocą IPv4.
* `/quote conn6 <server> <port>` - Łączy się z serwerem IRC za pomocą IPv6.
* `/quote help` - Wyświetla ten tekst pomocy.

Przy połączeniu wymagane jest podanie hasła poprzez `/quote PASS hasło`.

## Konfiguracja

Aby uruchomić program, konieczne jest utworzenie pliku `config.ini` z podstawową konfiguracją. Plik musi zawierać sekcję `[Settings]` z następującymi kluczami:

* `listen_ip` - Adres IP, pod którym BNC oczekuje na połączenia (domyślnie `0.0.0.0`).
* `listen_port` - Port, na którym BNC ma oczekiwać na połączenia (domyślnie `4090`).
* `ipv4_vhost` - Adres IPv4, którego Bouncer użyje dla połączeń z IRC po IPv4.
* `ipv6_vhost` - Adres IPv6, którego Bouncer użyje dla połączeń z IRC po IPv6.
* `password` - Hasło w formacie SHA256 hash.

# tahioBNC - Simple IRC Bouncer with VHOST support

tahioBNC is a simple IRC Bouncer written in Python with VHOST support. The program allows you to connect to an IRC server through a bouncer.

## Available Commands

* `/quote vh4 <IPv4 address>` - Set IPv4 VHOST.
* `/quote vh6 <IPv6 address>` - Set IPv6 VHOST.
* `/quote vh` - List available IPv4 and IPv6 addresses.
* `/quote conn4 <server> <port>` - Connect to an IRC server using IPv4.
* `/quote conn6 <server> <port>` - Connect to an IRC server using IPv6.
* `/quote help` - Display this help text.

When connecting, a password must be provided via `/quote PASS password`.

## Configuration

To run the program, you need to create a `config.ini` file with basic configuration. The file must contain a `[Settings]` section with the following keys:

* `listen_ip` - The IP address the BNC is listening on (default `0.0.0.0`).
* `listen_port` - The port the BNC is listening on (default `4090`).
* `ipv4_vhost` - The IPv4 address the Bouncer will use for IRC connections via IPv4.
* `ipv6_vhost` - The IPv6 address the Bouncer will use for IRC connections via IPv6.
* `password` - The password in SHA256 hash format.
