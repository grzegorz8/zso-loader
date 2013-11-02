#include "loader.h"
#include <stdio.h>

int yy = 13;

void *getsym_var(void *arg, const char *name) {
	/* names don't have to match */
	if (!strcmp(name, "y"))
		return &yy;
	return 0;
}

int main() {
	struct module *mod;
	mod = module_load("var.o", getsym_var, 0);
	if (!mod) {
		printf("ERROR: Can't load var.o\n");
		return 1;
	}
	int *px, *pz;
	px = module_getsym(mod, "x");
	if (!px) {
		printf("ERROR: Can't find var x\n");
		return 1;
	}
	pz = module_getsym(mod, "z");
	if (pz) {
		printf("ERROR: Found static var z\n");
		return 1;
	}
	if (*px != 23 || yy != 13) {
		printf("ERROR: variables don't match (1) (%d, %d)\n", *px, yy);
		return 1;
	}
	int lx, ly, lz;
	void (*get)(int *, int *, int *);
	get = module_getsym(mod, "getxyz");
	if (!get) {
		printf("ERROR: Can't find getxyz\n");
		return 1;
	}
	void (*set)(int, int, int);
	set = module_getsym(mod, "setxyz");
	if (!set) {
		printf("ERROR: Can't find setxyz\n");
		return 1;
	}
	get(&lx, &ly, &lz);
	if (lx != 23 || ly != 13 || lz != 5) {
		printf("ERROR: variables don't match (2) (%d, %d, %d)\n", lx, ly, lz);
		return 1;
	}
	*px = 7;
	yy = 6;
	get(&lx, &ly, &lz);
	if (lx != 7 || ly != 6 || lz != 5) {
		printf("ERROR: variables don't match (3) (%d, %d, %d)\n", lx, ly, lz);
		return 1;
	}
	set(1, 2, 3);
	if (*px != 1 || yy != 2) {
		printf("ERROR: variables don't match (4) (%d, %d)\n", *px, yy);
		return 1;
	}
	get(&lx, &ly, &lz);
	if (lx != 1 || ly != 2 || lz != 3) {
		printf("ERROR: variables don't match (3) (%d, %d, %d)\n", lx, ly, lz);
		return 1;
	}
	printf("OK\n");
	module_unload(mod);
	return 0;
}
