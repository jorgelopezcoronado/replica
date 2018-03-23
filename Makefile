CFLAGS=-O3 -lpcap -pthread -lssl -g
BINDIR=/usr/local/bin
CLIENT=repliclient
SERVER=repliserver

all: client server 

client: client.c helpers.c 
	gcc -o ${CLIENT} ${CFLAGS} helpers.c client.c 
	sudo chown root ${CLIENT}
	sudo chmod u+s ${CLIENT}

server: ethernet.h helpers.c helpers.h ip4.h linked_list.c linked_list.h linked_list_node.h server.c packet.h sip.h tcp.h udp.h
	gcc -o ${SERVER} ${CFLAGS} helpers.c linked_list.c server.c 
	sudo chown root ${SERVER} 
	sudo chmod u+s ${SERVER}

clean:
	rm -f ${CLIENT} 
	rm -f ${SERVER}

install: server client
	sudo rsync -aH ${SERVER} ${CLIENT} ${BINDIR}/  
uninstall: 
	sudo rm -f ${BINDIR}/{${SERVER},${CLIENT}}
