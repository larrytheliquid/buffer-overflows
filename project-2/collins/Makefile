all:

# set up libraries
local: impacket pcapy

impacket:
	tar xf impacket-0.9.9.9.tar.gz
	cd impacket && python setup.py install --prefix=`readlink -f ..`/local

pcapy:
	tar xf pcapy.tar.gz
	mv pcapy-0.10.8 pcapy
	cd pcapy && python setup.py install --prefix=`readlink -f ..`/local

clean:
	-rm -r impacket
	-rm -r pcapy

really-clean: clean
	-rm -r local
	-rm -r out
