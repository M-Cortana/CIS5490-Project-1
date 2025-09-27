#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define TCP_FLAG_SYN (1<<1)
#define TCP_FLAG_FIN (1<<0)
#define TCP_FLAG_ACK (1<<4)
#define DURATION_CALIBRATION 0.0 //in microseconeds 0.1178

typedef struct  {
        uint32_t magic_number;
        uint16_t version_major;
        uint16_t version_minor;
        int32_t thiszone;
        uint32_t sigfigs;
        uint32_t snaplen;
        uint32_t network;
} Pcap_Global_Header;

typedef struct {
        uint32_t ts_sec;
        uint32_t ts_usec;
        uint32_t incl_len;
        uint32_t orig_len;
        uint8_t *data;
} Pcap_Packet;

typedef struct {
        uint8_t mac_dest[6];
        uint8_t mac_src[6];
        uint32_t payload_len;
        uint32_t vlan;
        uint8_t *payload;
} Ethernet_Frame;

typedef struct {
        uint8_t ttl;
        uint8_t protocol;
        uint8_t ip_src[4];
        uint8_t ip_dest[4];
        uint32_t payload_len;
        uint8_t *payload;
} IPv4_Packet;

typedef struct {
        uint16_t port_src;
        uint16_t port_dest;
        uint32_t seq;
        uint32_t ack;
        uint8_t flag;
        uint32_t payload_len;
        uint8_t *payload;
} TCP_Packet;

typedef struct {
        uint8_t ip_server[4];
        uint8_t ip_client[4];
        uint16_t port_server;
        uint16_t port_client;
        uint32_t num_packet;
        uint32_t traffic_ip;
        uint32_t traffic_user;
        uint32_t start_sec;
        uint32_t start_usec;
        uint32_t end_sec;
        uint32_t end_usec;
        long double duration;
} TCP_Connection;

////////////////////Test Variable////////////////////
//#define IN_FILE_NAME "lengthFixed.pcap"
//#define IN_FILE_NAME "validate-parallel-sessions.pcap"
#define IN_FILE_NAME "valicate-802.1q.pcap"
#define OUT_FILE_NAME "tcpAnalysis.txt"
#define TEST_FILE_NAME "test.txt"

////////////////////Test Function////////////////////
void Print_Global_Header(Pcap_Global_Header *header) {
        printf("{magic_number = 0x%X, version = %u.%u, thiszone = %d, sigfigs = %u, snaplen = %u, network = %u}\n", header->magic_number, header->version_major, header->version_minor, header->thiszone, header->sigfigs, header->snaplen, header->network);
}
void Print_Packet_Header(Pcap_Packet *packet) {
        printf("{ts_sec = %u, ts_usec = %u, incl_len = %u, orig_len = %u}\n", packet->ts_sec, packet->ts_usec, packet->incl_len, packet->orig_len);
}
void Print_Ethernet_Header(Ethernet_Frame *frame) {
        printf("{mac_dest = %02X:%02X:%02X:%02X:%02X:%02X, mac_src = %02X:%02X:%02X:%02X:%02X:%02X, payload_len = %u}\n", frame->mac_dest[0], frame->mac_dest[1], frame->mac_dest[2], frame->mac_dest[3], frame->mac_dest[4], frame->mac_dest[5], frame->mac_src[0], frame->mac_src[1], frame->mac_src[2], frame->mac_src[3], frame->mac_src[4], frame->mac_src[5], frame->payload_len);
}
void Print_IPv4_Header(IPv4_Packet *packet) {
        printf("{ttl = %u, protocol = %u, ip_src = %u.%u.%u.%u, ip_dest = %u.%u.%u.%u, payload_len = %u}\n", packet->ttl, packet->protocol, packet->ip_src[0],  packet->ip_src[1],  packet->ip_src[2],  packet->ip_src[3],  packet->ip_dest[0], packet->ip_dest[1], packet->ip_dest[2], packet->ip_dest[3], packet->payload_len);
}
void Print_TCP_Header(TCP_Packet *packet) {
        printf("{port_src = %u, port_dest = %u, seq = %u, ack = %u, flag = 0x%02X, payload_len = %u}\n", packet->port_src, packet->port_dest, packet->seq, packet->ack, packet->flag, packet->payload_len);
}
void Print_Large_Data(uint8_t *data, uint32_t len) {
        uint32_t group_size = 32;
        uint32_t t = 0;
        while (t < len) {
                printf("%6u: ", t);
                for (int i = 0; i < group_size; i++, t++) {
                        printf("%02X ", data[t]);
                }
                printf("\n");
        }
}

////////////////////Global Variables////////////////////
Pcap_Global_Header Global_Header;

////////////////////Global Function////////////////////
//Input: filepointer *fp.
//Output: Pcap Packet packet.
//Return: 0 success
int Read_Packet(FILE *fp, Pcap_Packet *packet) {
        //Read Packet Header
        fread(packet, sizeof(Pcap_Packet) - sizeof(uint8_t*), 1, fp);

        //Read Packet data;
        packet->data = malloc(packet->incl_len);
        int n = fread(packet->data, 1, packet->incl_len, fp);
        if (n != packet->incl_len) {
                return -1;
        }
        return 0;
}

//Input: Pcap Packet pcap.
//Output: Ethernet Frame eth.
void Parse_Ethernet_Frame(Pcap_Packet *pcap, Ethernet_Frame *eth) {
        //parse destination and source mac address
        memcpy(eth->mac_dest, pcap->data, 6);
        memcpy(eth->mac_src, pcap->data + 6, 6);

        eth->payload_len = pcap->orig_len - 12;
        eth->payload = pcap->data + 12;
}

//Input: Ethernet Frame eth.
//Output: IPv4 Packet ipv4
//Return: -1 means no ipv4 packet in frame, 0 means sucess.
int Parse_IPv4_Packet(Ethernet_Frame *eth, IPv4_Packet *ipv4) {
        if (eth->payload[0] == 0x81 && eth->payload[1] != 0x00) {
                eth->payload += 4;
                eth->payload_len -= 4;
                printf("VLAN!!!!\n");
        }
        if (eth->payload[0] != 0x08 || eth->payload[1] != 0x00) {
                //No IPv4 packet contained in the ethernet frame.
                return -1;
        }
        eth->payload += 2;
        ipv4->ttl = eth->payload[8];
        ipv4->protocol = eth->payload[9];
        *(uint32_t*)(&ipv4->ip_src) = *(uint32_t*)(eth->payload+12);
        *(uint32_t*)(&ipv4->ip_dest) = *(uint32_t*)(eth->payload+16);
        ipv4->payload_len = eth->payload_len - 2 - (eth->payload[0] & 0x0F) * 4;
        ipv4->payload = eth->payload + (eth->payload[0] & 0x0F) * 4;
        eth->payload -= 2;
        return 0;
}

//Input: IPv4 Packet ipv4
//Output: TCP Packet tcp
//Return: -1 means no tcp packet in frame, 0 means sucess.
int Parse_TCP_Packet(IPv4_Packet *ipv4, TCP_Packet *tcp) {
        if (ipv4->protocol != 6) {
                return -1;
        }
        tcp->port_src = (ipv4->payload[0] << 8) + ipv4->payload[1];
        tcp->port_dest = (ipv4->payload[2] << 8) + ipv4->payload[3];
        tcp->seq = (ipv4->payload[4] << 24) + (ipv4->payload[5] << 16) + (ipv4->payload[6] << 8) + ipv4->payload[7];
        tcp->ack = (ipv4->payload[8] << 24) + (ipv4->payload[9] << 16) + (ipv4->payload[10] << 8) + ipv4->payload[11];
        tcp->flag = ipv4->payload[13];
        tcp->payload_len = ipv4->payload_len - (ipv4->payload[12] >> 4) * 4;
        tcp->payload = ipv4->payload +  (ipv4->payload[12] >> 4) * 4;
        return 0;
}


TCP_Connection Tcps[1024];
uint32_t Num_Tcps;
int main(int argc, char* argv[]) {
        //char in_file_name = argv[2];
        //char out_file_name = argv[3];
        char in_file_name[128] = IN_FILE_NAME;
        char out_file_name[128] = OUT_FILE_NAME;
        FILE *in_file = fopen(in_file_name, "rb");
        FILE *out_file = fopen(out_file_name, "w");
        freopen(TEST_FILE_NAME, "w", stdout);
        //Read the Global Header
        int n = fread(&Global_Header, sizeof(Global_Header), 1, in_file);
        Print_Global_Header(&Global_Header);
        Pcap_Packet pp;
        Ethernet_Frame pe;
        IPv4_Packet pi;
        TCP_Packet pt;

        //Start to process the data
        while (Read_Packet(in_file, &pp) != -1) {
                Parse_Ethernet_Frame(&pp, &pe);
                if (Parse_IPv4_Packet(&pe, &pi) == -1) {
                        //NO IP Packet
                        continue;
                }
                if (Parse_TCP_Packet(&pi, &pt) == -1) {
                        //NO TCP Packet
                        continue;
                }
                if (pt.flag & TCP_FLAG_SYN) {
                        if (pt.flag & TCP_FLAG_ACK) {
                                //Starts of a TCP session, server replies the SYN packet.
                                Tcps[Num_Tcps].start_sec = pp.ts_sec;
                                Tcps[Num_Tcps].start_usec = pp.ts_usec;

                                *(uint32_t*)(Tcps[Num_Tcps].ip_client) = *(uint32_t*)(pi.ip_dest);
                                *(uint32_t*)(Tcps[Num_Tcps].ip_server) = *(uint32_t*)(pi.ip_src);
                                Tcps[Num_Tcps].port_client = pt.port_dest;
                                Tcps[Num_Tcps].port_server = pt.port_src;

                                Tcps[Num_Tcps].num_packet++;
                                Tcps[Num_Tcps].traffic_ip += pe.payload_len - 2;
                                Tcps[Num_Tcps].traffic_user += pt.payload_len;
                                Num_Tcps++;
                        }
                        //No need to process the SYN packet sent by client.
                        continue;
                }
                int t = 0;
                while (t < Num_Tcps) {
                        if (*(uint32_t*)(pi.ip_src) == *(uint32_t*)(Tcps[t].ip_server) && *(uint32_t*)(pi.ip_dest) ==  *(uint32_t*)(Tcps[t].ip_client)) {
                                if (pt.port_src == Tcps[t].port_server && pt.port_dest == Tcps[t].port_client && Tcps[t].end_sec == 0) {
                                        //Found the matching tcp connections, and it's not ended;
                                        //This packet is from server to client;
                                        break;
                                }
                        }
                        t++;
                }
                if (t == Num_Tcps) {
                        //No matching tcp connections found;
                        continue;
                }
                Tcps[t].num_packet++;
                Tcps[t].traffic_ip += pe.payload_len - 2;
                Tcps[t].traffic_user += pt.payload_len;
                if (pt.flag & TCP_FLAG_FIN) {
                        //End of a TCP session
                        Tcps[t].end_sec = pp.ts_sec;
                        Tcps[t].end_usec = pp.ts_usec;
                        Tcps[t].duration = (Tcps[t].end_sec - Tcps[t].start_sec) + (1.0 * Tcps[t].end_usec - 1.0 * Tcps[t].start_usec + DURATION_CALIBRATION) * 1E-6;
                        continue;
                }
                //Print_TCP_Header(&pt);
        }
        printf("%u \n", Num_Tcps);
        
        //Start to print the result
        fprintf(out_file, "TCP_session_count, serverIP, clientIP, serverPort, clientPort, num_of_packetSent(server->client), TotalIPtrafficBytesSent(server->client), TotaluserTrafficBytesSent(server->client), sessionDuration, bits/s_IPlayerThroughput(server->client), bits/s_Goodput(server->client)\n=========================================================================================================================\n");
        for (int i = 0; i < Num_Tcps; i++) {
                fprintf(out_file, "%d\t%u.%u.%u.%u\t%u.%u.%u.%u\t%u\t%u\t%u\t%u\t%u\t%.3Lf\t%.3Lf\t%.3Lf\n", i+1, Tcps[i].ip_server[0], Tcps[i].ip_server[1], Tcps[i].ip_server[2], Tcps[i].ip_server[3], Tcps[i].ip_client[0], Tcps[i].ip_client[1],Tcps[i].ip_client[2],Tcps[i].ip_client[3], Tcps[i].port_server, Tcps[i].port_client, Tcps[i].num_packet, Tcps[i].traffic_ip, Tcps[i].traffic_user, Tcps[i].duration, 1.0*Tcps[i].traffic_ip/Tcps[i].duration*8.0, 1.0*Tcps[i].traffic_user/Tcps[i].duration*8.0);
        }
}