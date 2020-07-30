#include <Windows.h>
#include <avleak.h>
int main(int argc, char *argv[])
{
	DWORD size;
	char computerName[MAX_COMPUTERNAME_LENGTH];
	GetComputerNameA(computerName, &size);
	leak("ABCDEFGHIJKLMNOPQRSTUVWXYZ012\0", 30);
	return 0;
}