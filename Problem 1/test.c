#include <stdio.h>
#include <stdint.h>

typedef struct  {
        uint32_t magic_number;
        uint16_t version_major;
        uint16_t version_minor;
        int32_t thiszone;
        uint32_t sigfigs;
        uint32_t snaplen;
        uint32_t network;
} Pcap_Global_Header;

void Print_Global_Header(Pcap_Global_Header *header) {
        printf("{magic_number = 0x%X, version = %u.%u, thiszone = %d, sigfigs = %u, snaplen = %u, network = %u}\n", header->magic_number, header->version_major, header->version_minor, header->thiszone, header->sigfigs, header->snaplen, header->network);
}