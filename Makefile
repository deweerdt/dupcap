dupcap: dupcap.c
	gcc -O3 -g -Wall -Wextra -o $@ $< -lpcap -lpthread
