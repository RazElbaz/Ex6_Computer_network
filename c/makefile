
#we took this from the tirgul

all: sniffer snifferICMP snifferTCP snifferPassword spoof spoofB SniffAndThenSpoof

clean:
	rm -f *.o sniffer snifferICMP snifferTCP snifferPassword spoof spoofB SniffAndThenSpoof

sniffer:sniffer.c
	gcc -o sniffer sniffer.c -lpcap

snifferICMP:snifferICMP.c
	gcc -o snifferICMP snifferICMP.c -lpcap

snifferTCP:snifferTCP.c
	gcc -o snifferTCP snifferTCP.c -lpcap

snifferPassword:snifferPassword.c
	gcc -o snifferPassword snifferPassword.c -lpcap

spoof:spoof.c
	gcc -o spoof spoof.c

spoofB:spoofB.c
	gcc -o spoofB spoofB.c
SniffAndThenSpoof:SniffAndThenSpoof.c
	gcc -o SniffAndThenSpoof SniffAndThenSpoof.c -lpcap
runs:
	./sniffer
runc:
	./snifferICMP
runt:
	./snifferTCP
rund:
	./snifferPassword
rune:
	./spoof
runf:
	./spoofB
rung:
	./SniffAndThenSpoof

runs-strace:
	strace -f ./sniffer.c
runc-strace:
	strace -f ./snifferICMP.c
runt-strace:
	strace -f ./snifferTCP.c
rund-strace:
	strace -f ./snifferPassword.c
rune-strace:
	strace -f ./spoof.c
runf-strace:
	strace -f ./spoofbB.c
rung-strace:
	strace -f ./SniffAndThenSpoof.c

