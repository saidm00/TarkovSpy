

struct retarded
{
	char x; // sizeof(char) = 1
	// Compiler here adds extra 3 bytes
	// To align y on 4 byte boundary
	int y; // sizeof(int) = 4	
};



void foo(void)
{
	int x; // sizeof(int) = 4
	char y; // sizeof(char) = 1
	float z; // sizeof(float) = 4

	return;
}


int main(int argc, char *argv[])
{
	foo();

	int x;
	x = 5;

	int *p = &x;
	*p = 25;

	printf("%d\n", x); // 25

	

	return 0;
}