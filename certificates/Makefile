all: trusted_chain.h server.h server_key.h client.h client_key.h

%.h : %.crt
	xxd -i $< > $@

%_key.h : %.key
	xxd -i $< > $@