# uwhoisd

**IMPORTANT**: This project is an heavily modified fork of [uWhoisd](https://github.com/kgaughan/uwhoisd/)

The main change is that it uses the linux `whois` command on every call unless otherwise specified in the config.

A 'Universal WHOIS' proxy server: you query it for information about a
particular domain, it works out the correct WHOIS server to query and gives
back the correct details.


# Install guide

## System dependencies

You will need a `whois` command installed on the system, and `poetry`.

On Ubuntu/Debian, `apt install whois` will get you a `whois` client. For `poetry`, please have a look at the [install guide](https://python-poetry.org/docs/).

## Prerequisites

You need to have redis cloned and installed in the same directory you clone `uwhoisd` in: `uwhoisd` and `redis` must be in the same directory, and **not** `redis` cloned in the `uwhoisd` directory. See [this guide](https://www.lookyloo.eu/docs/main/install-lookyloo.html#_install_redis).

## Installation

Follow the [install guide](https://www.lookyloo.eu/docs/main/install-lookyloo.html#_install_uwhoisd) on lookyloo website.

## Start/Stop the server

The install guide above explains how to run `uwhoisd` as a system service. If you want to run it manually, do as follow:

```bash
poetry run start
poetry run stop
```

## Usage

### Telnet

```bash
$ (git::main) telnet 0.0.0.0 4243 
Trying 0.0.0.0...
Connected to 0.0.0.0.
Escape character is '^]'.
www.google.de

% Restricted rights.
% 
% Terms and Conditions of Use
% 
% The above data may only be used within the scope of technical or
% administrative necessities of Internet operation or to remedy legal
% problems.
% The use for other purposes, in particular for advertising, is not permitted.
% 
% The DENIC whois service on port 43 doesn't disclose any information concerning
% the domain holder, general request and abuse contact.
% This information can be obtained through use of our web-based whois service
% available at the DENIC website:
% http://www.denic.de/en/domains/whois-service/web-whois.html
% 
% 

Domain: google.de
Nserver: ns1.google.com
Nserver: ns2.google.com
Nserver: ns3.google.com
Nserver: ns4.google.com
Status: connect
Changed: 2018-03-12T21:44:25+01:00Connection closed by foreign host.
```

### Python

```
import socket

def whois(self, query: str) -> str:
    bytes_whois = b''
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((self.server, self.port))
        sock.sendall(f'{query}\n'.encode())
        while True:
            data = sock.recv(2048)
            if not data:
                break
            bytes_whois += data
    to_return = bytes_whois.decode()
    return to_return
```
