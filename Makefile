
CC := gcc
CFLAGS := -g -O2 `pcap-config --cflags --libs` -L /usr/lib -lpcap `mysql_config --cflags --libs`

all:: dnssniff

dnssniff: 

clean::
	-rm -f *.o dnssniff
	-rm -rf dnssniff.dSYM
