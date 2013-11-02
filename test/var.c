int x = 23;
extern int y;
static int z = 5;

void getxyz(int *px, int *py, int *pz) {
	*px = x;
	*py = y;
	*pz = z;
}

void setxyz(int nx, int ny, int nz) {
	x = nx;
	y = ny;
	z = nz;
}
