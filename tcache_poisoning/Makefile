.PHONY: all clean

all: tcache tcache_arithmetic

clean:
	rm -f tcache tcache arithmetic

tcache: tcache.c
	gcc -g $^ -o $@ -Wno-stringop-overflow

tcache_arithmetic: tcache_arithmetic.c
	gcc -g $^ -o $@

