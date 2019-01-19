#include <stdio.h>
#include <time.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#include <pcap.h>
#include <pthread.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>

#define SNAPLEN 100

struct seen {
	uint32_t hash;
	char packet[SNAPLEN];
	size_t len;
	bool set;
}; 

#define SEEN_SIZE 100000

struct thread_config {
	pthread_t t;
	pcap_if_t *dev;
	int snapshot_length;
	int packet_count_limit;
	int to_remove[10000];
	int tr_idx;
	struct seen seen[SEEN_SIZE];
	struct seen **others;
};

static void
dump_line(FILE *out, char *data, int offset, int limit)
{
	int i;

	fprintf(out, "%03x:", offset);
	for (i = 0; i < limit; i++) {
		fprintf(out, " %02x", (unsigned char)data[offset + i]);
	}
	for (i = 0; i + limit < 16; i++) {
		fprintf(out, "   ");
	}
	fprintf(out, " ");
	for (i = 0; i < limit; i++) {
		fprintf(out, "%c", isprint(data[offset + i]) ? data[offset+i]:'.');
	}
	fprintf(out, "\n");
}

static void
dump_zone(FILE *out, void *buf, int len)
{
	int i;
	char *data = buf;

	fprintf(out, "================================================================================\n");
	for (i = 0; i < len; i += 16) {
		int limit;
		limit = 16;
		if (i + limit > len)
			limit = len - i;
		dump_line(out, data, i, limit);
	}
	fprintf(out, "================================================================================\n");
}
/* https://github.com/wolkykim/qlibc/blob/03a8ce035391adf88d6d755f9a26967c16a1a567/src/utilities/qhash.c#L239 */
static uint32_t qhashmurmur3_32(const void *data, size_t nbytes)
{
	if (data == NULL || nbytes == 0)
		return 0;

	const uint32_t c1 = 0xcc9e2d51;
	const uint32_t c2 = 0x1b873593;

	const int nblocks = nbytes / 4;
	const uint32_t *blocks = (const uint32_t *) (data);
	const uint8_t *tail = (const uint8_t *) (data + (nblocks * 4));

	uint32_t h = 0;

	int i;
	uint32_t k;
	for (i = 0; i < nblocks; i++) {
		k = blocks[i];

		k *= c1;
		k = (k << 15) | (k >> (32 - 15));
		k *= c2;

		h ^= k;
		h = (h << 13) | (h >> (32 - 13));
		h = (h * 5) + 0xe6546b64;
	}

	k = 0;
	switch (nbytes & 3) {
		case 3:
			k ^= tail[2] << 16;
			/* fallthrough */
		case 2:
			k ^= tail[1] << 8;
			/* fallthrough */
		case 1:
			k ^= tail[0];
			k *= c1;
			k = (k << 15) | (k >> (32 - 15));
			k *= c2;
			h ^= k;
	};

	h ^= nbytes;

	h ^= h >> 16;
	h *= 0x85ebca6b;
	h ^= h >> 13;
	h *= 0xc2b2ae35;
	h ^= h >> 16;

	return h;
}

#define ARRAY_SIZE(x) (sizeof(x)/sizeof(x[0]))

static void add(struct thread_config *t, const u_char *packet, struct pcap_pkthdr packet_header)
{
	int o = 0;
	uint32_t h = qhashmurmur3_32(packet, packet_header.caplen);
	memset(&t->seen[t->to_remove[t->tr_idx]], 0, sizeof(*t->seen));;

	int idx = h % ARRAY_SIZE(t->seen);

	while (t->others[o]) {
		if (t->others[o][idx].set) {
			struct seen other;
			memcpy(&other, &t->others[o][idx], sizeof(other));
			if (other.hash == h && other.len == packet_header.caplen && !memcmp(packet, other.packet, packet_header.caplen)) {
				dump_zone(stderr, other.packet, other.len);
			}
		}
		o++;
	}

	t->seen[idx].set = 1;
	t->seen[idx].hash = h;
	memcpy(t->seen[idx].packet, packet, packet_header.caplen);
	t->seen[idx].len = packet_header.caplen;

	t->to_remove[t->tr_idx] = idx;
	t->tr_idx = (t->tr_idx + 1) % ARRAY_SIZE(t->to_remove);
}

static void *cap(void *a)
{
	struct thread_config *tc = a;
	pcap_t *handle;
	const u_char *packet;
	struct pcap_pkthdr packet_header;
	char err[PCAP_ERRBUF_SIZE];

	/* Open device for live capture */
	handle = pcap_open_live(
			tc->dev->name,
			tc->snapshot_length,
			0, /* promisc */
			0, /* to_ms */
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
		add(tc, packet, packet_header);
	} while(1);
	return NULL;
}

int main(int argc, char *argv[])
{
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

	struct thread_config *t = calloc(nr_devs, sizeof(*t));
	nr_devs = 0;

	for (int i = 1; i < argc; i++) {
		for (dev_it = alldevs; dev_it; dev_it = dev_it->next) {
			if (!strcmp(argv[i], dev_it->name)) {
				t[nr_devs].snapshot_length = SNAPLEN; 
				t[nr_devs].packet_count_limit = 10; 
				t[nr_devs++].dev = dev_it;
				break;
			}
		}
	}
	for (int i = 0; i < nr_devs; i++) {
		t[i].others = calloc(nr_devs, sizeof(*t->others));
		int n = 0;
		for (int j = 0; j < nr_devs; j++) {
			if (i != j) {
				t[i].others[n++] = t[j].seen;
			}
		}
		t[i].others[n] = NULL;
	}

	for (int i = 0; i < nr_devs; i++) {
		pthread_create(&t[i].t, NULL, cap, &t[i]); 
	}

	pause();
	return 0;
}

