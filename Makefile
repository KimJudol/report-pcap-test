LDLIBS += -lpcap

all: report-pcap-test

report-pcap-test: report-pcap-test.o
	gcc -o report-pcap-test report-pcap-test.o -lpcap

report-pcap-test.o: packet_header.h report-pcap-test.c
	gcc -c -o report-pcap-test.o report-pcap-test.c

clean:
	rm -f report-pcap-test *.o
