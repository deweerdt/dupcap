dupcap: dupcap.c
	gcc -o $@ $< -lpcap -lpthread
