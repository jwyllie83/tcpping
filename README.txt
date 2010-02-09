--- Overview ----------------------------------------------------------------

tcpping is a quick utility designed to emulate standard 'ping' in nearly every
meaningful way and only diverge when necessary.  It sends out forged TCP SYN
packets and listens for a SYN/ACK or RST from the server or intermediary.  It
counts and reports on these results using an interface that is nearly identical
to standard UNIX ping.

--- Why Use Instead of Ping -------------------------------------------------

On the global Internet, some routers or systems will firewall ICMP messages
while allowing TCP packets.  Furthermore, some routers or hosts will
'deprioritize' ICMP ping (echo) messages destined for itself or others -- when
the network gets busy, these get dropped.

However, virtually all public servers and the majority of private systems have
at least one TCP port open and will respond to requests on it quickly and
reliably.  This provides greater accuracy (or any accuracy at all) for
determining if a host is available.  It also yields more reliable timing for
sensitive latency and loss measurements as deprioritized packets will not be a
true measure of latency for normal traffic (better simulated by TCP packets).

It was originally written by Steven Kehlet (blog at kehlet.cx); it was taken
over, bugfixed, and now maintained (with the original author's blessing) by Jim
Wyllie.

--- Building ----------------------------------------------------------------

Building tcpping requires that you have a stable build environment as well as
development versions of libnet1 and pcap.  If you're on a Debian-based system
(including Ubuntu) you can install those libraries with the following:

sudo apt-get install build-essential
sudo apt-get install libnet1-dev
sudo apt-get install libpcap-dev

Or, alternatively, libnet1 is conveniently hosted on GitHub:
http://github.com/sam-github/libnet

While libpcap is hosted at http://www.tcpdump.org/

Build with the following:

make

--- Setuid and tcpping ------------------------------------------------------

If you don't want to use root access to use it every time, you can setuid the
program.  Keep in mind that any security vulnerabilities in tcpping could
allow someone to execute arbitrary root-level code.

sudo chmod root:root tcpping
sudo chmod a+s tcpping

--- Compatibility Issues ----------------------------------------------------

libnet1 is a retooling of the old libnet hosted on SourceForge at
http://packetfactory.net/ by Peter Wang.  The note from Sam at GitHub is that
the upstream maintainer is unresponsive and the project is unmaintained.  He
made subtle changes to the API, but it should still mostly work with an old
version of libnet.

--- Related Tools -----------------------------------------------------------

Some tools that have similar functionality that may suit your needs better:

hping
http://www.hping.org/  --  (officially) supports more operating systems.  Has
many more features and is more complicated.

nmap
http://nmap.org/ -- Full-service security standard compiled as a package with
nearly all UNIX-like distributions.  
