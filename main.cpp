#include <cstdio>
#include <pcap.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <libnet.h>
#include <netinet/in.h>
#include "airodump.h"
#include <map>
#include <string>

std::map<std::string, std::pair<int, std::string>> m;

void usage() {
        printf("syntax : airodump <interface>\n");
        printf("sample : airodump mon0\n");
}

int main(int argc, char* argv[]) {
    	if (argc != 2 ) {
		usage();
		return -1;
	}
	
	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];

	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	while(true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(handle, &header, &packet); 

		if(res==0) continue;
		if(res==PCAP_ERROR || res==PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			break;
		}
		
		Radiotap* rd=(Radiotap*) packet;
		Beacon* bec=(Beacon*)(packet+rd->it_len);
		if(bec->type!=8) continue;
		std::string bssid=std::string(bec->bssid);
		std::string essid="";
		Param* par=(Param*)((char*)bec+sizeof(Beacon));
	
		for(uint8_t i=0; i<par->tag.len; i++) essid+=*(&(par->tag.essid)+i);
		if(m.find(bssid)==m.end()) m[bssid]={1, essid};
		else m[bssid].first++;
	
		system("clear");
		printf("BSSID\t\t\tBeacons\t\t\tESSID\n");
		for(auto i:m) {
			printf("%s\t\t\t%d\t\t\t%s\n", i.first.c_str(), i.second.first, i.second.second.c_str());
		}	
	
	}
	pcap_close(handle);
}