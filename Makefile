CFLAGS=-lpcap -pthread -lssl
BINDIR=/usr/local/bin

all: extmon runmonv2

runmon: ethernet.h helpers.c helpers.h ip4.h linked_list.c linked_list.h linked_list_node.h runmon.c runmon.h sip.h tcp.h term.h udp.h
	gcc -o runmon ${CFLAGS} helpers.c linked_list.c runmon.c 
	sudo chown root runmon
	sudo chmod u+s runmon

extmon: extmon.c helpers.c 
	gcc -o extmon ${CFLAGS} helpers.c extmon.c 
	sudo chown root extmon
	sudo chmod u+s extmon

runmonv2: ethernet.h helpers.c helpers.h ip4.h linked_list.c linked_list.h linked_list_node.h runmonv2.c runmon.h sip.h tcp.h term.h udp.h
	gcc -o runmonv2 ${CFLAGS} helpers.c linked_list.c runmonv2.c 
	sudo chown root runmon
	sudo chmod u+s runmon

clean:
	rm -f runmon
	rm -f runmonv2
	rm -f exmon

install: runmon
	sudo rsync -aH runmon ${BINDIR}/  
uninstall: 
	sudo rm -f ${BINDIR}/runmon
