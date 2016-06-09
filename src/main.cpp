#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <iostream>
#include <list>
#include <iterator>
#include <string.h>

struct my_pkt_format{
	char srcIp[INET_ADDRSTRLEN];
	char dstIp[INET_ADDRSTRLEN];
	u_int8_t srcMAC[6];
	u_int8_t dstMAC[6];
	__time_t seconds;
	__suseconds_t nanoseconds;
};

struct device_list{
	char Ip[INET_ADDRSTRLEN];
	u_int8_t MAC[6];
	bool gateway;
	int interface;
};

using namespace std;

list<my_pkt_format> packetList;
u_int8_t bcastMAC[6] = {255, 255, 255, 255, 255, 255};

void dispatcher_handler(u_char *temp1, const struct pcap_pkthdr *header, const u_char *pkt_data) {

	struct my_pkt_format packet;
	const struct ether_header *ethernetHead;
	const struct ip* ipHead;

	/* Parse pkt_data */
	ethernetHead = (struct ether_header*) pkt_data;
	ipHead = (struct ip *)(pkt_data + sizeof(*ethernetHead));

	ethernetHead = (struct ether_header*) pkt_data;

	if (ntohs(ethernetHead->ether_type) == ETHERTYPE_IP) {
		ipHead = (struct ip*)(pkt_data + sizeof(struct ether_header));

		packet.seconds = header->ts.tv_sec;
		packet.nanoseconds = header->ts.tv_usec;

		memcpy(packet.srcMAC, &ethernetHead->ether_shost, 6);
		memcpy(packet.dstMAC, &ethernetHead->ether_dhost, 6);

		inet_ntop(AF_INET, &(ipHead->ip_src), packet.srcIp, INET_ADDRSTRLEN);
		inet_ntop(AF_INET, &(ipHead->ip_dst), packet.dstIp, INET_ADDRSTRLEN);

		if (ipHead->ip_p == IPPROTO_TCP	|| memcmp(bcastMAC, ethernetHead->ether_dhost, 6) == 0 && strcmp(packet.srcIp, "0.0.0.0")) {
			 packetList.push_back(packet);
		}
	}
}

int open_pcap_file(char *filename){
	pcap_t *fp;
	char errbuf[PCAP_ERRBUF_SIZE];

	cout << "Usage: " << filename << endl;
	/* Open the capture file */
	fp = pcap_open_offline(filename, errbuf);
	if (fp == NULL) {
		cout << "pcap_open_live() failed: " << errbuf << endl;
		return 1;
	}
	/* Read capture packets until EOF */
	if (pcap_loop(fp, 0, dispatcher_handler, NULL) < 0) {
		cout << "pcap_loop() failed: " << pcap_geterr(fp);
		return 1;
	}
	pcap_close(fp);
	return 0;
}

list<device_list> check_devices(list<my_pkt_format> packetList1, list<my_pkt_format> packetList2){

	list<my_pkt_format>::iterator i = packetList1.begin();
	list<my_pkt_format>::iterator j = packetList2.begin();
	list<device_list> deviceList;
	struct device_list device;
	i++; j++;

	while(i != packetList1.end() || j != packetList2.end()){

		int tmpcmp = 0;

		if(memcmp(i->dstMAC, bcastMAC,6) != 0 || memcmp(i->srcMAC, bcastMAC,6) != 0
				|| memcmp(j->dstMAC, bcastMAC,6) != 0 || memcmp(j->srcMAC, bcastMAC,6) != 0){

			/* Check packets inputs to interface 1 */
			if(i->seconds == j->seconds && i->nanoseconds < j->nanoseconds){
				strcpy(device.Ip, i->srcIp);
				memcpy(device.MAC, &i->srcMAC, 6);
				device.interface = 1;
				device.gateway = 0;
			}

			/* Check packets inputs to interface 2 */
			if(i->seconds == j->seconds && i->nanoseconds > j->nanoseconds){
				strcpy(device.Ip, j->srcIp);
				memcpy(device.MAC, &j->srcMAC, 6);
				device.interface = 2;
				device.gateway = 0;
			}

			if(deviceList.empty())
				deviceList.push_front(device);

			for(list<device_list>::iterator deviceIter = deviceList.begin(); deviceIter != deviceList.end(); deviceIter++){
				if(memcmp(device.MAC, deviceIter->MAC, 6) == 0 && memcmp(bcastMAC, device.MAC, 6) != 0){
					if(strcmp(device.Ip, deviceIter->Ip) != 0 && memcmp(i->srcIp, bcastMAC,6)!=0
							&& memcmp(i->dstIp,bcastMAC,6)!=0){
						deviceIter->gateway = 1;
					}
					++tmpcmp;
				}
			}

			if(tmpcmp == 0 && strcmp(device.Ip, "0.0.0.0") != 0){
				deviceList.push_back(device);
			}
			++i;
			++j;
		}
	}
	return deviceList;
}

char *gateway_ip(list<my_pkt_format> packetLs, u_int8_t *gw){
	for(list<my_pkt_format>::iterator iter = packetLs.begin(); iter != packetLs.end(); iter++){
		if(memcmp(iter->srcMAC, gw, 6) == 0 && memcmp(iter->dstMAC, bcastMAC, 6) == 0){
			return iter->srcIp;
		}
		if(memcmp(iter->dstMAC, gw, 6) == 0 && memcmp(iter->srcMAC, bcastMAC, 6) == 0){
			return iter->dstIp;
		}
	}
	return "0.0.0.0";
}

int main() {

	list<my_pkt_format> packetList1;
	list<my_pkt_format> packetList2;
	list<device_list> deviceList;
	string file1;
	string file2;
	char *file_name_int1;
	char *file_name_int2;

	cout << "Input dump file from interface 1: ";
	getline(cin, file1);
	cout << "Input dump file from interface 2: ";
	getline(cin, file2);

	file_name_int1 = new char[file1.length() + 1];
	strcpy(file_name_int1, file1.c_str());
	file_name_int2 = new char[file2.length() + 1];
	strcpy(file_name_int2, file2.c_str());

	open_pcap_file(file_name_int1);
	packetList1 = packetList;
	packetList.clear();

	open_pcap_file(file_name_int2);
	packetList2 = packetList;
	packetList.clear();

	deviceList = check_devices(packetList1, packetList2);

	for(list<device_list>::iterator deviceIter = deviceList.begin(); deviceIter != deviceList.end(); ++deviceIter){

		if(deviceIter->interface > 2){
			cout << "\n You input files from one interface." << endl;
			return 1;
		}

		cout << "\nInterface: " << deviceIter->interface << endl;

		if(deviceIter->gateway == 1){
			strcpy(deviceIter->Ip, gateway_ip(packetList1, deviceIter->MAC));
			cout << "gateway";
		} else {
			cout << "local area";
		}
		cout << "\nIP address: " << deviceIter->Ip << endl;
		cout.unsetf(ios::dec);
		cout.setf(ios::hex);
		cout << "MAC address: ";

		for(int i=0; i<6; i++){
			cout << unsigned(deviceIter->MAC[i]) << ":";
		}
		cout.unsetf(ios::hex);
		cout.setf(ios::dec);
		cout << "\n";
	}
	return 0;
}
