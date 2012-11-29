all: lib

# Setup libraries
.PHONY: lib
lib:
	make -C lib

# Run tests
.PHONY: out
out:
	-rm -r out
	time zsh run-all.txt
	cp -r out "out.`date`"

out.tgz: out
	tar cvzf out.tgz out

really-clean: clean
	-rm -r out
	-rm -r out.tgz

clean:
	make -C lib clean
