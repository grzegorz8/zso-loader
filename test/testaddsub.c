#include "loader.h"
#include <stdio.h>

void *getsym_none(void *arg, const char *name) {
	return 0;
}

int main() {
	struct module *mod;
	mod = module_load("addsub.o", getsym_none, 0);
	int res = 0;
	if (!mod) {
		printf("ERROR: Can't load addsub.o\n");
		return 1;
	}
	int (*add)(int, int);
	int (*sub)(int, int);
	add = module_getsym(mod, "add");
	if (!add) {
		printf("ERROR: Can't find add\n");
		return 1;
	}
	sub = module_getsym(mod, "sub");
	if (!sub) {
		printf("ERROR: Can't find sub\n");
		return 1;
	}
	int ok = 1;
	int sum = add(2, 2);
	if (sum != 4) {
		printf("ERROR: 2 + 2 = %d\n", sum);
		return 1;
	}
	int diff = sub(0xc0000000, 0x12345678);
	if (diff != 2915805576) {
		printf("ERROR: sub doesn't work\n");
		return 1;
	}
	printf("OK\n");
	module_unload(mod);
	return 0;
}
