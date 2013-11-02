#include "loader.h"
#include "hello.h"
#include <stdio.h>

const char *gethellostr() {
	return "world";
}

void *getsym_hello(void *arg, const char *name) {
	if (!strcmp(name, "gethellostr"))
		return gethellostr;
	if (!strcmp(name, "printf"))
		return printf;
	return 0;
}
int main() {
	struct module *mod;
	mod = module_load("hello.o", getsym_hello, 0);
	if (!mod) {
		printf("ERROR: Can't load hello.o\n");
		return 1;
	}
	void (*hello)();
	hello = module_getsym(mod, "hello");
	if (!hello) {
		printf("ERROR: Can't find hello\n");
		return 1;
	}
	hello();
	module_unload(mod);
	return 0;
}
