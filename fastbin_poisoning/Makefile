.PHONY: all clean

all: fastbin pointer_protect

clean:
	rm -f fastbin pointer_protect

fastbin: fastbin.c
	gcc -g $^ -o $@ -Wno-stringop-overflow

pointer_protect: pointer_protect.c
	gcc -g $^ -o $@

