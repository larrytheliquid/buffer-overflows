all: badbuf input1.txt

GCC_OPTS = -fno-stack-protector -ggdb
.PHONY: clean

badbuf.s: badbuf.c
	gcc -S $(GCC_OPTS) -o $@ $<

badbuf: badbuf.c
	gcc $(GCC_OPTS) -static -o $@ $<

clean:
	-rm badbuf badbuf.s

input1.txt: part1.py
	python part1.py > input1.txt