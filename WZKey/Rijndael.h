#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef unsigned char byte;

class Rijndael {
public:
    struct Key {
        byte *expandedKey;
        byte expandedKeySize;
    };
    enum Mode {
        CBC,
        CFB,
        CTS,
        ECB,
        OFB
    };

	void Encrypt(byte *input, byte *outBuffer, int size);
	void Decrypt(byte *input, byte *outBuffer, int size);
    
	void setInitVector(int *iv);
	int getInitVector() const;
    
	void setKey(Rijndael::Key *key);
	Rijndael::Key getKey() const;
    
    static Rijndael::Key CreateKey(byte *key, int keySize);
private:
#ifndef RIJNDAEL_NOLOOKUP_TABLE
	static const byte sbox[256];
	static const byte sboxInv[256];
	static const byte Rcon[256];
	static const byte expTable[256];
	static const byte logTable[256];
	static const byte shiftRowTable[16];
	static const byte shiftRowInvTable[16];
	static inline byte getSBoxValue(byte num);
	static inline byte getSBoxInvValue(byte num);
	static inline byte getRconValue(byte num);
	static inline byte getExpTableValue(byte num);
	static inline byte getLogTableValue(byte num);
	static inline byte getShiftRowsValue(byte num);
	static inline byte getShiftRowsInvValue(byte num);
#endif
    
	static void expandKey(byte *key, byte keySize, byte *expandedKey, byte expandedKeySize);
	void addRoundKey(byte *state, byte *roundKey);
	void shiftRows(byte *state);
	void shiftRowsInv(byte *state);
	void subBytes(byte *state);
	void subBytesInv(byte *state);
	void mixColumns(byte *state);
	void mixColumnsInv(byte *state);
	void blockEncrypt(byte *input, byte *outBuffer);
	void blockDecrypt(byte *input, byte *outBuffer);
	byte FFMul(byte a, byte b);
    
	Rijndael::Key m_key;
	int m_initVector[4];
};