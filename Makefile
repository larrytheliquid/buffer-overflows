ALL = badbuf input1.txt getfp input2_robust.txt
all: $(ALL)

# The -ggdb doesn't seem to affect the stack top address.
GCC_OPTS = -fno-stack-protector -ggdb
.PHONY: clean test1 test2

badbuf.s: badbuf.c
	gcc -S $(GCC_OPTS) -o $@ $<

%: %.c
	gcc $(GCC_OPTS) -static -o $@ $<

input1.txt: part1.py
	python part1.py > input1.txt

test1: input1.txt badbuf
	cat input1.txt
	./badbuf < input1.txt
	echo

input2_robust.txt: part2_robust.py
	./part2_robust.py > $@

# NB: the stack top is different in make than it is on the command
# line.
test2: badbuf
	./getfp
	./getfp | ./part2.py | tee input2.txt
	./badbuf < input2.txt
	echo

clean:
	-rm $(ALL) badbuf.s input2.txt badbuf_instrumented foo

