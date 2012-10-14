all: badbuf input1.txt

# The -ggdb doesn't seem to affect the stack top address.
GCC_OPTS = -fno-stack-protector -ggdb
.PHONY: clean test1

badbuf.s: badbuf.c
	gcc -S $(GCC_OPTS) -o $@ $<

%: %.c
	gcc $(GCC_OPTS) -static -o $@ $<

clean:
	-rm badbuf badbuf.s

input1.txt: part1.py
	python part1.py > input1.txt

input2.txt: part2.py
	python part2.py > input2.txt

test1: input1.txt badbuf
	cat input1.txt
	./badbuf < input1.txt
	echo

test2: badbuf
	./getfp
	./getfp | ./part2.py | tee input2.txt
	./badbuf < input2.txt
	echo
