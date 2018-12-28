#include "Rijndael.h"
#include <Windows.h>

void printfBytes(byte *p, int size) {
	for (int i = 0; i < size; i++) {
		printf("%02X ", p[i]);
		if ((i + 1) % 16 == 0) {
			printf("\r\n");
		}
	}
	if (size % 16 == 0) {
		printf("\r\n");
	}
}

Rijndael rijndael;
void multiplyBytes(byte *input, byte *outBuffer, int count, int mul) {
	for (int i = 0; i < (count * mul); i++) {
		outBuffer[i] = input[i % count];
	}
}
byte key[32] = {
	0x13, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0xB4, 0x00, 0x00, 0x00,
	0x1B, 0x00, 0x00, 0x00, 0x0F, 0x00, 0x00, 0x00, 0x33, 0x00, 0x00, 0x00, 0x52, 0x00, 0x00, 0x00
};
void getKeys(byte *iv, byte *outBuffer) {
	byte buffer[0xFFFF] = { 0 };
	Rijndael::Key rkey = Rijndael::CreateKey(key, 32);
	rijndael.setKey(&rkey);
	multiplyBytes(iv, buffer, 4, 4);	
	for (int i = 0; i < (0xffff / 0x10); i++) {
		rijndael.Encrypt(buffer, buffer, 0x10);
		memcpy(outBuffer + i * 0x10, buffer, 0x10);
	}
	rijndael.Encrypt(buffer, buffer, 0x10);
	memcpy(outBuffer + (0xffff - 0x0F), buffer, 0x0F);
}

int main() {
	byte emsIv[] = { 0xb9, 0x7d, 0x63, 0xe9 };
	byte gmsIv[] = { 0x4d, 0x23, 0xc7, 0x2b };
	byte outBuffer[0xFFFF] = { 0 };
	DWORD tBegin = GetTickCount();
	getKeys(emsIv, outBuffer);
	DWORD tEnd = GetTickCount();
	printfBytes(outBuffer, 0xFFFF);
	printf("%dms",(tEnd-tBegin));
	system("pause");
	return 0;
}