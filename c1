#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/in.h>

void packet_handler(u_char user, const struct pcap_pkthdrpkthdr, const u_char packet) {
    struct ipip_header;

    // IP 헤더 시작 위치 계산
    ip_header = (struct ip)(packet + sizeof(struct ether_header));

    // 패킷 정보 출력
    printf("Source IP: %s\n", inet_ntoa(ip_header->ip_src));
    printf("Destination IP: %s\n", inet_ntoa(ip_header->ip_dst));
}

int main() {
    pcap_thandle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "ip";  // IP 패킷만 캡처

    // 네트워크 디바이스 열기
    handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device: %s\n", errbuf);
        return 2;
    }

    // 필터 설정
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }

    // 패킷 캡처 시작
    pcap_loop(handle, 0, packet_handler, NULL);

    // 리소스 정리
    pcap_freecode(&fp);
    pcap_close(handle);

    return 0;
}
