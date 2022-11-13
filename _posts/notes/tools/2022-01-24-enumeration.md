---
title: Notes | Enumeration Tools
author: Zeropio
date: 2022-01-24
categories: [Notes, Tools]
tags: [tool, nmap]
permalink: /notes/tools/enumeration
---

# RustScan

It is recommended to make an alias like `alias rustscan='docker run -it --rm --name rustscan rustscan/rustscan:latest'`.

The basic syntax is:
```console
zero@pio$ rustscan -a <TARGET>
```

We can pass an IP, domain, file with both, subnets...

To perform against ports, the syntax is similar to nmap:
```console
zero@pio$ rustscan -a <TARGET> -p <PORT,PORT>
zero@pio$ rustscan -a <TARGET> --range <NUMBER-NUMBER>
```

We can use a similar syntax, like `-A` or `-sC`.

---

# Nmap

**Network Mapper** (Nmap) is an open-source network analysis and security auditing tool written in C, C++, Python, and Lua. It is designed to scan networks and identify which hosts are available on the network using raw packets, and services and applications, including the name and version, where possible. It can also identify the operating systems and versions of these hosts. Besides other features, Nmap also offers scanning capabilities that can determine if packet filters, firewalls, or intrusion detection systems (IDS) are configured as needed.

Nmap have the following scanning techniques:
- Host discovery
- Port scanning
- Service enumeration and detection
- OS detection
- Scriptable interaction with the target service (Nmap Scripting Engine)

The syntax is:
```console
zero@pio$ nmap <scan types> <options> <target>
```

As always, the flag `--help` will provide us information.

Nmap comes with default options, for example the TCP-SYN scan (`-sS`). This option send packets with the **SYN flag**, so it never complete the handshake, so nmap doesn't stablish connection. Nmap can get three different cases:
- If our target sends an **SYN-ACK flagged** packet back to the scanned port, Nmap detects that the port is **open**.
- If the packet receives an **RST flag**, it is an indicator that the port is **closed**.
- If Nmap does not receive a packet back, it will display it as **filtered**. Depending on the firewall configuration, certain packets may be dropped or ignored by the firewall.

---

## Host Discovery 

Nmap can help discovering all the hosts up through a net. The most effective host discovery method is to use **ICMP echo requests**.

> It is always recommended to store every single scan.
{: .prompt-tip}

To scan a network:
```console
zero@pio$ sudo nmap <ip>/<subnet mask> -sn -oA <file name> | grep for | cut -d" " -f5
```

Also, we can scan a range (for example `10.129.2.18-20`) or using a file with all the hosts we want to scan and replacing `<ip>/<subnet mask>` by `-iL <file>`.

To scan a single host:
```console
zero@pio$ sudo nmap <ip> -sn -oA <file name>
```

We can confirm that we are using ICMP echo request adding at the end `-PE`. Nmap, before sending a ICMP echo request it send a **ARP ping**, resulting in an **ARP reply**. We can confirm with `--packet-trace`:
```console
zero@pio$ sudo nmap <ip> -sn -oA <file name> -PE --packet-trace
```

Another way to check if our target is up is with `--reason`:
```console
zero@pio$ sudo nmap <ip> -sn -oA <file name> -PE --reason
```

If we want to disable the **ARP request** and **ARP reply** use `--disable-arp-ping`:
```console
zero@pio$ sudo nmap <ip> -sn -oA <file name> -PE --packet-trace --disable-arp-ping
```

---

## Host and Port Scanning

The scanned ports can have six different states:

| **State**   | **Description**    |
|--------------- | --------------- |
| `open` | indicates that the connection to the scanned port has been established (TCP, UDP or SCTP) |
| `closed` | the TCP protocol indicates that the packet we received back contains an RST flag |
| `filtered` | Nmap cannot correctly identify whether the scanned port is open or closed because either no response is returned from the target for the port or we get an error code from the target |
| `unfiltered` | during the TCP-ACK scan and means that the port is accessible, but it cannot be determined whether it is open or closed |
| `open|filtered` | If we do not get a response for a specific port, Nmap will set it to that state. This indicates that a firewall or packet filter may protect the port |
| `closed|filtered` | in the IP ID idle scans, indicates that it was impossible to determine if the scanned port is closed or filtered by a firewall |

### Discovering Open TCP Ports 

By default, Nmap scans the **top 1000 TCP ports** with the **SYN scan** (`-sS`). This SYN scan is set only to default when we run it as **root** because of the socket permissions required to create raw TCP packets. Otherwise, the **TCP scan** (`-sT`) is performed by default.

We can define the ports one by one (`-p 21,22,80,443`), by range (`-p 22-443`) or by tops (`--top-ports=10`). Also there is fast options, like all the ports (`-p-`) or the 100 top (`-F`). For example:
```console
zero@pio$ sudo nmap <ip> --top-ports=10 
```

If we want to have a clear view of the SYN scan we can disabled everything, the ICMP echo request (`-Pn`), DNS resolution (`-n`) and ARP ping scan (`--disable-arp-ping`).

### Discovering Open UDP Ports 

To check by UDP ports we will use the option `-sU`.

---

## Saving the Results 

It's important to save the result of our scans for later enumeration. Nmap provides us three types of file:
- **Normal output**(`-oN`): with the .nmap file extension
- **Grepable output**(`-oG`): with the .gnmap file extension
- **XML output**(`-oX`): with the .xml file extension

Or the option `-oA`, which saves in each one. We must specify the output file after the flag:
```console
zero@pio$ sudo nmap <ip> -oA <file>
```

The XML output can be helpful to create HTML reports, with the command `xsltproc`:
```console
zero@pio$ xsltproc target.xml -o target.html
```

---

## Service Enumeration 

It is essential to determine the application and its version as accurately as possible. We can use the `-sV` flag to get the service version. With the options `-v`, `-vv` and `-vvv` we can increase the verbosity.

> We can add `--stats-every=5s` to get the process of the scan without pressing `Space`.
{: .prompt-tip}

One disadvantage to Nmap's presented results is that the automatic scan can miss some information because sometimes Nmap does not know how to handle it. Primarily, Nmap looks at the banners of the scanned ports and prints them out. If it cannot identify versions through the banners, Nmap attempts to identify them through a signature-based matching system, but this significantly increases the scan's duration. Others commands, as **netcat** can help better grabbing banners:
```console
zero@pio$ nc -nv <ip> <port>
```

Even though, nmap provides us with the option `--script` to get banners:
```console
zero@pio$ nmap -sV --script=banner <target> 
```

---

## Nmap Scripting Engine 

Nmap Scripting Engine (**NSE**) provides us with the possibility to create scripts in Lua for interaction with certain services. There are a total of 14 categories into which these scripts can be divided: 

| **Category**   | **Description**    |
|--------------- | --------------- |
| **auth**  | Determination of authentication credentials. |
| **broadcast** | Scripts, which are used for host discovery by broadcasting and the discovered hosts, can be automatically added to the remaining scans. |
| **brute** | Executes scripts that try to log in to the respective service by brute-forcing with credentials. |
| **default** | Default scripts executed by using the `-sC` option. |
| **discovery** | Evaluation of accessible services. |
| **dos** | These scripts are used to check services for denial of service vulnerabilities and are used less as it harms the services. |
| **exploit** | This category of scripts tries to exploit known vulnerabilities for the scanned port. |
| **external** | Scripts that use external services for further processing. |
| **fuzzer** | This uses scripts to identify vulnerabilities and unexpected packet handling by sending different fields, which can take much time. |
| **intrusive** | Intrusive scripts that could negatively affect the target system. |
| **malware** | Checks if some malware infects the target system. |
| **safe** | Defensive scripts that do not perform intrusive and destructive access. |
| **version** | Extension for service detection. |
| **vuln** | Identification of specific vulnerabilities. |

First, update the scripts:
```console
zero@pio$ sudo nmap --script-updatedb
```

To run default scripts:
```console
zero@pio$ sudo nmap -sC <ip>
```

To select a category:
```console
zero@pio$ sudo nmap --script <category> <ip>
```

To run defined scripts:
```console
zero@pio$ sudo nmap --script <script name>,<script name>,... <ip>
```

For example:
```console
zero@pio$ sudo nmap --script banner.smtp-commands <ip>
```

We can also run the **aggressive scan** (`-A`) which do all types of scan-

### Vulnerability Assessment 

```console
zero@pio$ sudo nmap -sV --script vuln <ip>
```

All the scripts are located in `/usr/share/nmap/scripts/`{: .filepath}.

---

## Performance 

Scanning performance plays a significant role when we need to scan an extensive network or are dealing with low network bandwidth. We have many options to tell Nmap host fast (`-T <1-5>`), which frequency (`--min-parallelism <number>`), which timeouts (`--max-rtt-timeout <time>`), packets sent simultaneously (`--min-rate <number>`) or the number of retries (`--max-retries <number>`).

### Timeouts 

The packets send by Nmap takes some time (**Round-Trip-Time - RTT**). Nmap start with a timeout of 100ms (`--min-RTT-timeout`). An example of an optimize scan:
```console
zero@pio$ sudo nmap <target> --initial-rtt-timeout 50ms --max-rtt-timeout 100ms
```

### Max Retries 

Another way to increase the scans' speed is to specify the retry rate of the sent packets. The default value for the retry rate is **10**, so if Nmap does not receive a response for a port, it will not send any more packets to the port and will be skipped.
```console
zero@pio$ sudo nmap <target> --max-retries 0
```

### Rates 

If we know the network bandwidth, we can work with the rate of packets sent, which significantly speeds up our scans with Nmap.
```console
zero@pio$ sudo nmap <target> --min-rate 300
```

### Timing 

Nmap offers six different timing templates for us to use. These values (**0-5**) determine the aggressiveness of our scans. The default is `-T 3`. These are the others:
- `-T 0` / `-T paranoid`
- `-T 1` / `-T sneaky`
- `-T 2` / `-T polite`
- `-T 3` / `-T normal`
- `-T 4` / `-T aggressive`
- `-T 5` / `-T insane`

```console
zero@pio$ sudo nmap <target> -T 5
```

---

## Firewall and IDS/IPS Evasion

Nmap gives us many different ways to bypass firewalls rules and IDS/IPS.

### Determine Firewalls and Their Rules 

The packets can either be **dropped**, or **rejected**. The **dropped** packets are ignored, and no response is returned from the host. This is different for **rejected** packets that are returned with an **RST flag**. These packets contain different types of **ICMP error codes** or contain nothing at all. Such erros can be:
- Net Unreachable
- Net Prohibited
- Host Unreachable
- Host Prohibited
- Port Unreachable
- Proto Unreachable

Nmap's TCP ACK scan (`-sA`) method is much harder to filter for firewalls and IDS/IPS systems than regular SYN (`-sS`) or Connect scans (`-sT`) because they only send a TCP packet with only the ACK flag.

When a port is closed or open, the host must respond with an **RST flag**. Unlike outgoing connections, all connection attempts (with the **SYN flag**) from external networks are usually blocked by firewalls. However, the packets with the **ACK flag** are often passed by the firewall because the firewall cannot determine whether the connection was first established from the external network or the internal network.

Take this example:
- **SYN-Scan**

```console
zero@pio$ sudo nmap 10.129.2.28 -p 21,22,25 -sS -Pn -n --disable-arp-ping --packet-trace

Starting Nmap 7.80 ( https://nmap.org ) at 2020-06-21 14:56 CEST
SENT (0.0278s) TCP 10.10.14.2:57347 > 10.129.2.28:22 S ttl=53 id=22412 iplen=44  seq=4092255222 win=1024 <mss 1460>
SENT (0.0278s) TCP 10.10.14.2:57347 > 10.129.2.28:25 S ttl=50 id=62291 iplen=44  seq=4092255222 win=1024 <mss 1460>
SENT (0.0278s) TCP 10.10.14.2:57347 > 10.129.2.28:21 S ttl=58 id=38696 iplen=44  seq=4092255222 win=1024 <mss 1460>
RCVD (0.0329s) ICMP [10.129.2.28 > 10.10.14.2 Port 21 unreachable (type=3/code=3) ] IP [ttl=64 id=40884 iplen=72 ]
RCVD (0.0341s) TCP 10.129.2.28:22 > 10.10.14.2:57347 SA ttl=64 id=0 iplen=44  seq=1153454414 win=64240 <mss 1460>
RCVD (1.0386s) TCP 10.129.2.28:22 > 10.10.14.2:57347 SA ttl=64 id=0 iplen=44  seq=1153454414 win=64240 <mss 1460>
SENT (1.1366s) TCP 10.10.14.2:57348 > 10.129.2.28:25 S ttl=44 id=6796 iplen=44  seq=4092320759 win=1024 <mss 1460>
Nmap scan report for 10.129.2.28
Host is up (0.0053s latency).

PORT   STATE    SERVICE
21/tcp filtered ftp
22/tcp open     ssh
25/tcp filtered smtp
MAC Address: DE:AD:00:00:BE:EF (Intel Corporate)

Nmap done: 1 IP address (1 host up) scanned in 0.07 seconds
```

- **ACK-Scan**

```console
zero@pio$ sudo nmap 10.129.2.28 -p 21,22,25 -sA -Pn -n --disable-arp-ping --packet-trace

Starting Nmap 7.80 ( https://nmap.org ) at 2020-06-21 14:57 CEST
SENT (0.0422s) TCP 10.10.14.2:49343 > 10.129.2.28:21 A ttl=49 id=12381 iplen=40  seq=0 win=1024
SENT (0.0423s) TCP 10.10.14.2:49343 > 10.129.2.28:22 A ttl=41 id=5146 iplen=40  seq=0 win=1024
SENT (0.0423s) TCP 10.10.14.2:49343 > 10.129.2.28:25 A ttl=49 id=5800 iplen=40  seq=0 win=1024
RCVD (0.1252s) ICMP [10.129.2.28 > 10.10.14.2 Port 21 unreachable (type=3/code=3) ] IP [ttl=64 id=55628 iplen=68 ]
RCVD (0.1268s) TCP 10.129.2.28:22 > 10.10.14.2:49343 R ttl=64 id=0 iplen=40  seq=1660784500 win=0
SENT (1.3837s) TCP 10.10.14.2:49344 > 10.129.2.28:25 A ttl=59 id=21915 iplen=40  seq=0 win=1024
Nmap scan report for 10.129.2.28
Host is up (0.083s latency).

PORT   STATE      SERVICE
21/tcp filtered   ftp
22/tcp unfiltered ssh
25/tcp filtered   smtp
MAC Address: DE:AD:00:00:BE:EF (Intel Corporate)

Nmap done: 1 IP address (1 host up) scanned in 0.15 seconds
```

### Detect IDS/IPS 

Unlike firewalls and their rules, the detection of IDS/IPS systems is much more difficult because these are passive traffic monitoring systems. IDS systems examine all connections between hosts. If the IDS finds packets containing the defined contents or specifications, the administrator is notified and takes appropriate action in the worst case. IPS systems take measures configured by the administrator independently to prevent potential attacks automatically. It is essential to know that IDS and IPS are different applications and that IPS serves as a complement to IDS.

### Decoys 

The **Decoy scanning method** (`-D`) generates various random IP addresses inserted into the IP header to disguise the origin of the packet sent.

Example:
```console
zero@pio$ sudo nmap 10.129.2.28 -p 80 -sS -Pn -n --disable-arp-ping --packet-trace -D RND:5

Starting Nmap 7.80 ( https://nmap.org ) at 2020-06-21 16:14 CEST
SENT (0.0378s) TCP 102.52.161.59:59289 > 10.129.2.28:80 S ttl=42 id=29822 iplen=44  seq=3687542010 win=1024 <mss 1460>
SENT (0.0378s) TCP 10.10.14.2:59289 > 10.129.2.28:80 S ttl=59 id=29822 iplen=44  seq=3687542010 win=1024 <mss 1460>
SENT (0.0379s) TCP 210.120.38.29:59289 > 10.129.2.28:80 S ttl=37 id=29822 iplen=44  seq=3687542010 win=1024 <mss 1460>
SENT (0.0379s) TCP 191.6.64.171:59289 > 10.129.2.28:80 S ttl=38 id=29822 iplen=44  seq=3687542010 win=1024 <mss 1460>
SENT (0.0379s) TCP 184.178.194.209:59289 > 10.129.2.28:80 S ttl=39 id=29822 iplen=44  seq=3687542010 win=1024 <mss 1460>
SENT (0.0379s) TCP 43.21.121.33:59289 > 10.129.2.28:80 S ttl=55 id=29822 iplen=44  seq=3687542010 win=1024 <mss 1460>
RCVD (0.1370s) TCP 10.129.2.28:80 > 10.10.14.2:59289 SA ttl=64 id=0 iplen=44  seq=4056111701 win=64240 <mss 1460>
Nmap scan report for 10.129.2.28
Host is up (0.099s latency).
```

With the option `-S` we can specify the IP who will appear at the scan:
```console
zero@pio$ sudo nmap 10.129.2.28 -n -Pn -p 445 -O -S 10.129.2.200 -e tun0

Starting Nmap 7.80 ( https://nmap.org ) at 2020-06-22 01:16 CEST
Nmap scan report for 10.129.2.28
Host is up (0.010s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds
MAC Address: DE:AD:00:00:BE:EF (Intel Corporate)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 2.6.32 (96%), Linux 3.2 - 4.9 (96%), Linux 2.6.32 - 3.10 (96%), Linux 3.4 - 3.10 (95%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (94%), Synology DiskStation Manager 5.2-5644 (94%), Linux 2.6.32 - 2.6.35 (94%), Linux 2.6.32 - 3.5 (94%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 1 hop

OS detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 4.11 seconds
```

### DNS Proxying

Nmap gives us a way to specify DNS servers ourselves (`--dns-server <ns>,<ns>`), this could be fundamental in a **DMZ** (demilitarized zone). The company's DNS servers are usually more trusted than those from the Internet. So, for example, we could use them to interact with the hosts of the internal network. As another example, we can use **TCP port 53** as a source port (`--source-port`) for our scans.
```console
zero@pio$ sudo nmap 10.129.2.28 -p50000 -sS -Pn -n --disable-arp-ping --packet-trace --source-port 53

SENT (0.0482s) TCP 10.10.14.2:53 > 10.129.2.28:50000 S ttl=58 id=27470 iplen=44  seq=4003923435 win=1024 <mss 1460>
RCVD (0.0608s) TCP 10.129.2.28:50000 > 10.10.14.2:53 SA ttl=64 id=0 iplen=44  seq=540635485 win=64240 <mss 1460>
Nmap scan report for 10.129.2.28
Host is up (0.013s latency).

PORT      STATE SERVICE
50000/tcp open  ibm-db2
MAC Address: DE:AD:00:00:BE:EF (Intel Corporate)

Nmap done: 1 IP address (1 host up) scanned in 0.08 seconds
```

---

## Flags

| **Flag**   | **Description**    |
|------------| --------------- |
| **System Info** |
| `-O` | detect OS |
| `-sV` | services version |
| `-p-` | scan **all** ports |
| `--open` | only show open ports |
| **Scan Options**
| `-sn` | Ping scan |
| `-sS`   | stealth scan   |
| `-sU` | UDP scan |
| `-A` | aggressive scan (all) |
| **Scripts** |
| `-sC` | specify Nmap script |
| **Files** |
| `-iL <inputfilename>` | Input from list of hosts/networks |
| `-oN` | export in a file |
| `-oA` | export in three aviable formats |
| **Disabled** |
| `-Pn` | do not use ping |
| `-n` | disable DNS resolution |
| `--disable-arp-ping` | disable ARP reply and response |
| **Optimization** |
| `--initial-rtt-timeout <number>ms` | change the initial timeout |
| `--max-rtt-timeout <number>ms` | change the max timeout |
| `--max-retries <number>` | Change max retries |
| `--min-rate <number>` | Change the min rate for send packets |
| **Check** |
| `--reason` | check if the target is up |
| `-PE` | ensure ICMP echo requests are sent |
| `--packet-trace` | confirm it would send an ARP ping |
| **Other** |
| `-v` `-vv` `-vvv` | verbosity |
| `--stats-every=5s` | get the process of the scan | 

> `-sC` and `-sV` can be shortened as `-sVC`
{: .prompt-tip }

