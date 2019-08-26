all: nfqnl_test

nfqnl_test: nfqnl_test.o
	gcc -o netfilter_test netfilter_test.o -lnetfilter_queue
	rm netfilter_test.o

nfqnl_test.o: netfilter_test.c
	gcc -c -o netfilter_test.o netfilter_test.c -lnetfilter_queue

clean:  
	rm -f netfilter_test.o
	rm -f nfqnl_test
