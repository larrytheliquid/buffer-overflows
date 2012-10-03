all: badbuf input1.txt

GCC_OPTS = -fno-stack-protector -ggdb
.PHONY: clean test1

badbuf.s: badbuf.c
	gcc -S $(GCC_OPTS) -o $@ $<

badbuf: badbuf.c
	gcc $(GCC_OPTS) -static -o $@ $<

clean:
	-rm badbuf badbuf.s

input1.txt: part1.py
	python part1.py > input1.txt

test1: input1.txt badbuf
	cat input1.txt
	./badbuf < input1.txt
	echo
