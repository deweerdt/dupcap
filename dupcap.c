#include <stdio.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
#include <pcap.h>
#include <pthread.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>

void print_packet_info(const u_char *packet, struct pcap_pkthdr packet_header)
{
	printf("Packet capture length: %d\n", packet_header.caplen);
	printf("Packet total length %d\n", packet_header.len);
}

struct thread_config {
	pthread_t t;
	pcap_if_t *dev;
};

void *cap(void *a)
{
	struct thread_config *tc = a;
	pcap_t *handle;
	const u_char *packet;
	struct pcap_pkthdr packet_header;
	int packet_count_limit = 10;
	char err[PCAP_ERRBUF_SIZE];

	/* Open device for live capture */
	handle = pcap_open_live(
			tc->dev->name,
			100,
			packet_count_limit,
			0,
			err);

	if (!handle) {
		fprintf(stderr, "%s\n", err);
		return NULL;
	}

	do {
		packet = pcap_next(handle, &packet_header);
		if (packet == NULL) {
			printf("No packet found.\n");
			return NULL;
		}
	} while(1);
	return NULL;
}

int main(int argc, char *argv[])
{
	char *device;
	char err[PCAP_ERRBUF_SIZE];
	pcap_if_t *alldevs, *dev_it;
	int nr_devs = argc - 1;;

	if (!argv[1]) {
		printf("Missing device name. Usage: %s <dev>\n", argv[0]);
		return 1;
	}

	int ret = pcap_findalldevs(&alldevs, err);
	if (ret != 0) {
		printf("Error finding device: %s\n", err);
		return 1;
	}

	struct thread_config t[nr_devs];
	nr_devs = 0;

	for (int i = 1; i < argc; i++) {
		for (dev_it = alldevs; dev_it; dev_it = dev_it->next) {
			if (!strcmp(argv[i], dev_it->name)) {
				t[nr_devs++].dev = dev_it;
				break;
			}
		}
	}
	for (int i = 0; i < nr_devs; i++) {
		pthread_create(&t[i].t, NULL, cap, &t[i]); 
	}

	pause();
	return 0;
}

