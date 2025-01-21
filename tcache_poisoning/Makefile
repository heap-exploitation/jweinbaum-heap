.PHONY: all clean

all: tcache tcache_arithmetic

clean:
	rm -f tcache tcache arithmetic

tcache: tcache.c
	gcc -g $^ -o $@ -Wnostringop-overflow

tcache_arithmetic: tcache_arithmetic.c
	gcc -g $^ -o $@

