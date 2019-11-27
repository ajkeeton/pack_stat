# packstats

Barebones utility that prints some basic network traffic statistics gathered from a pcap.

# Compiling

```
mkdir build ; cd build ; cmake .. ; make
```

# Usage

To analyze live traffic:

```
sudo pack_stat -i eth0 
```

Stats will periodically dump:


```
sudo pstats -i eth0

10.0.2.15:5632 <-> 10.0.2.2:32964	0.066 kbs	retrans: 0	gaps: 0	overlaps: 0
10.0.2.15:5632 <-> 10.0.2.2:31997	0.051 kbs	retrans: 0	gaps: 0	overlaps: 0
```

Sending SIGUSR1...
```
killall -SIGUSR1 pstats
```

... will cause the global stats to print:

```
The epic conclusion:
	Total packets:        86
	Total bytes:          9256

	IPv4 packets:         84
	IPv4 bytes:           7978
	IPv6 packets:         0

	TCP:                  84
	   total bytes:       6124
	   payload bytes:     4444
	   client bytes:      68
	   server bytes:      676
	   client retrans:    0
	   server retrans:    0
	   client gaps:       0
	   server gaps:       1
	   client overlaps:   0
	   server overlaps:   0

	UDP:                  0
	VLAN:                 0
	ARP:                  2
	IPX:                  0
	IPv4 in IPv4:         0
	IP Other:             0
	IP fragments:         0
	MPLS Multicast:       0
	MPLS Unicast:         0
	Other, ignored:       0
	PCAP issue:           0
```

To analyze an existing pcap:

```
pstats -r /var/alertlogic/pcaps/perf_test_environ/perf_test-80.pcap
```

BPFs are supported:

```
sudo pack_stat -i eth0 host 1.2.3.4 and port 1234
```
