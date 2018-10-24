#include "global.h"
#include "dorca30_function.h"
#include "dorca30_api.h"
#include "dorca.h"
#include <string.h>
#include <stdio.h>

#define DelayMS 4
#define DELAY 4
void PrintByte2(unsigned char *pData,int size )
{
	int i = 0;
	for(i = 0; i < size; i++)
	{
			printf("%02x",pData[i]);
	}
	return;	
}

void _EcdsaGenPublicKey(unsigned char *private_key, point *public_key)
{
	unsigned char buffer_ecdsa[256];
	unsigned char buffer_receive[256];
	printf("\r\n ecdsa_test P256");

	buffer_ecdsa[0] = SPI1_WRITE_DATA;
	buffer_ecdsa[1] = 0;
	buffer_ecdsa[2] = SIZE_ECDSA_256;
	buffer_ecdsa[3] = 0;
	buffer_ecdsa[4] = 0;
	SendData(buffer_ecdsa,5);
	delay_ms(DelayMS);	
#ifdef DEBUG_DELAY	
	delay_ms(4000);
#endif	
	buffer_ecdsa[0] = SPI1_WRITE_DATA;
	buffer_ecdsa[1] = 0;
	buffer_ecdsa[2] = Set_ECDSA_PrivateKey;
	buffer_ecdsa[3] = 0;
	buffer_ecdsa[4] = 32;
	memcpy(&buffer_ecdsa[5],private_key,32);
	SendData(buffer_ecdsa,37);
	delay_ms(DelayMS);
//	printf("\r\n private key in api");
//	PrintByte(private_key,32);
	
	buffer_ecdsa[0] = SPI1_WRITE_DATA;
	buffer_ecdsa[1] = 0;
	buffer_ecdsa[2] = Create_ECDSA_Public_Key;
	buffer_ecdsa[3] = 0;
	buffer_ecdsa[4] = 0;
	SendData(buffer_ecdsa,5);
	printf("\r\n Create_ECDSA_Public_Key");
#ifdef DEBUG_DELAY	
	delay_ms(4000);
#endif
	delay_ms(1000);
    buffer_ecdsa[0] = SPI1_READ_DATA;
	buffer_ecdsa[1] = 0;
	buffer_ecdsa[2] = Get_ECDSA_Public_Key_Yq;
	buffer_ecdsa[3] = 0;
	buffer_ecdsa[4] = 32;
	ReadData(buffer_ecdsa,public_key->y,32);

	         
	delay_ms(DelayMS);	
#ifdef DEBUG_DELAY	
	delay_ms(4000);
#endif

    buffer_ecdsa[0] = SPI1_READ_DATA;
	buffer_ecdsa[1] = 0;
	buffer_ecdsa[2] = Get_ECDSA_Public_Key_Xq;
	buffer_ecdsa[3] = 0;
	buffer_ecdsa[4] = 32;
	ReadData(buffer_ecdsa,public_key->x,32);
	delay_ms(DelayMS);	
	return;
}
void _EcdsaGenSignature(unsigned char  *d, unsigned char  *k, unsigned char  *h, unsigned char  *r, unsigned char  *s)
{
		unsigned char buffer_ecdsa[256];
		unsigned char buffer_receive[256];
	
		buffer_ecdsa[0] = SPI1_WRITE_DATA;
		buffer_ecdsa[1] = 0;
		buffer_ecdsa[2] = SIZE_ECDSA_256;
		buffer_ecdsa[3] = 0;
		buffer_ecdsa[4] = 0;
		SendData(buffer_ecdsa,5);
		delay_ms(DelayMS);	
#ifdef DEBUG_DELAY	
		delay_ms(4000);
#endif	
		buffer_ecdsa[0] = SPI1_WRITE_DATA;
		buffer_ecdsa[1] = 0;
		buffer_ecdsa[2] = Set_ECDSA_PrivateKey;
		buffer_ecdsa[3] = 0;
		buffer_ecdsa[4] = 32;
		//Hexstr2Bytes("00d007e1b9afcc312eec9cecffa0280752bbd1953182edef12f3fc366e8f4356",&buffer_ecdsa[5]);
		memcpy(&buffer_ecdsa[5],d,32);
		SendData(buffer_ecdsa,37);
		delay_ms(DelayMS);	
	
		//return;
 #ifdef DEBUG_DELAY
		delay_ms(4000);
#endif	
		buffer_ecdsa[0] = SPI1_WRITE_DATA;
		buffer_ecdsa[1] = 0;
		buffer_ecdsa[2] = Set_ECDSA_K_RND;
		buffer_ecdsa[3] = 0;
		buffer_ecdsa[4] = 32;
		//Hexstr2Bytes("00c03c3b8b1e40cb328a61d51783356935625884399e26a5828f387c2bde6ebc",&buffer_ecdsa[5]);
		memcpy(&buffer_ecdsa[5],k,32);		
		SendData(buffer_ecdsa,37);
		delay_ms(DelayMS);	
	
		buffer_ecdsa[0] = SPI1_WRITE_DATA;
		buffer_ecdsa[1] = 0;
		buffer_ecdsa[2] = Set_ECDSA_h;
		buffer_ecdsa[3] = 0;
		buffer_ecdsa[4] = 32;
//		Hexstr2Bytes("0000000000000000000000000f7b55549fab573c0361b832ad0be8cdeef91b56",&buffer_ecdsa[5]);
		memcpy(&buffer_ecdsa[5],h,32);		
		SendData(buffer_ecdsa,37);		 
		delay_ms(DelayMS);	
	
		
		buffer_ecdsa[0] = SPI1_WRITE_DATA;
		buffer_ecdsa[1] = 0;
		buffer_ecdsa[2] = Create_ECDSA_Sign;
		buffer_ecdsa[3] = 0;
		buffer_ecdsa[4] = 0;
		SendData(buffer_ecdsa,5); 
        delay_ms(400);
#ifdef DEBUG_DELAY	
		delay_ms(4000);
#endif
	
			buffer_ecdsa[0] = SPI1_READ_DATA;
		buffer_ecdsa[1] = 0;
		buffer_ecdsa[2] = Get_ECDSA_r;
		buffer_ecdsa[3] = 0;
		buffer_ecdsa[4] = 32;
		ReadData(buffer_ecdsa,r,32);
		
		delay_ms(DelayMS);	
#ifdef DEBUG_DELAY	
		delay_ms(4000);
#endif
	
		buffer_ecdsa[0] = SPI1_READ_DATA;
		buffer_ecdsa[1] = 0;
		buffer_ecdsa[2] = Get_ECDSA_s;
		buffer_ecdsa[3] = 0;
		buffer_ecdsa[4] = 32;
		ReadData(buffer_ecdsa,s,32);
		
		delay_ms(DelayMS);	
		return;
}


//#define LOG_ON
//#define LOG_ON
int _EcdsaVerifySignature(point *public_key, unsigned char  *r,unsigned char  *s,unsigned char  *h )
{
	unsigned char buffer_ecdsa[256];
	unsigned char buffer_receive[256];


	buffer_ecdsa[0] = SPI1_WRITE_DATA;
	buffer_ecdsa[1] = 0;
	buffer_ecdsa[2] = SIZE_ECDSA_256;
	buffer_ecdsa[3] = 0;
	buffer_ecdsa[4] = 0;

	SendData(buffer_ecdsa,5);
	delay_ms(DELAY);	
	buffer_ecdsa[0] = SPI1_WRITE_DATA;
	buffer_ecdsa[1] = 0;
	buffer_ecdsa[2] = Set_ECDSA_r;
	buffer_ecdsa[3] = 0;
	buffer_ecdsa[4] = 32;
	memcpy(&buffer_ecdsa[5],r,32);
#ifdef LOG_ON	
	printf("\r\n Sign r");
	PrintByte(r,32);
#endif	
	SendData(buffer_ecdsa,37);
	delay_ms(DELAY);	


	buffer_ecdsa[0] = SPI1_WRITE_DATA;
	buffer_ecdsa[1] = 0;
	buffer_ecdsa[2] = Set_ECDSA_s;
	buffer_ecdsa[3] = 0;
	buffer_ecdsa[4] = 32;
	memcpy(&buffer_ecdsa[5],s,32);
#ifdef LOG_ON	
	printf("\r\n Sign s");
	PrintByte(s,32);
#endif	
	SendData(buffer_ecdsa,37);
	delay_ms(DELAY);		


	#ifdef DEBUG_DELAY
    delay_ms(4000);
#endif	
	buffer_ecdsa[0] = SPI1_WRITE_DATA;
	buffer_ecdsa[1] = 0;
	buffer_ecdsa[2] = Set_ECDSA_Public_Key_Xq;
	buffer_ecdsa[3] = 0;
	buffer_ecdsa[4] = 32;
	memcpy(&buffer_ecdsa[5],public_key->x,32);
#ifdef LOG_ON	
	printf("\r\n public_key->x");
	PrintByte(public_key->x,32);
#endif
	
	SendData(buffer_ecdsa,37);
	delay_ms(DELAY);	
#ifdef DEBUG_DELAY
	delay_ms(4000);
#endif	
	buffer_ecdsa[0] = SPI1_WRITE_DATA;
	buffer_ecdsa[1] = 0;
	buffer_ecdsa[2] = Set_ECDSA_Public_Key_Yq;
	buffer_ecdsa[3] = 0;
	buffer_ecdsa[4] = 32;
	memcpy(&buffer_ecdsa[5],public_key->y,32);
#ifdef LOG_ON		
	printf("\r\n public_key->y");
	PrintByte(public_key->y,32);	
#endif	
	SendData(buffer_ecdsa,37);
	PrintByte2(buffer_ecdsa + 5, 32);
	delay_ms(DELAY);	


	buffer_ecdsa[0] = SPI1_WRITE_DATA;
	buffer_ecdsa[1] = 0;
	buffer_ecdsa[2] = Set_ECDSA_h;
	buffer_ecdsa[3] = 0;
	buffer_ecdsa[4] = 32;
//		Hexstr2Bytes("0000000000000000000000000f7b55549fab573c0361b832ad0be8cdeef91b56",&buffer_ecdsa[5]);
	memcpy(&buffer_ecdsa[5],h,32);		
#ifdef LOG_ON	
	printf("\r\n h");
	PrintByte(h,32);
#endif
	SendData(buffer_ecdsa,37);		 
	delay_ms(DELAY);	

	buffer_ecdsa[0] = SPI1_WRITE_DATA;
	buffer_ecdsa[1] = 0;
	buffer_ecdsa[2] = Do_ECDSA_Verify;
	buffer_ecdsa[3] = 0;
	buffer_ecdsa[4] = 0;
	SendData(buffer_ecdsa,5);
#ifdef DEBUG_DELAY	
	delay_ms(4000);
#endif
	delay_ms(500);


    buffer_ecdsa[0] = SPI1_READ_DATA;
	buffer_ecdsa[1] = 0;
	buffer_ecdsa[2] = Get_ECDSA_Result;
	buffer_ecdsa[3] = 0;
	buffer_ecdsa[4] = 1;
	ReadData(buffer_ecdsa,buffer_receive,1);

	printf("\r\n Get_ECDSA_Result %d",buffer_receive[0]);
   return buffer_receive[0]; 

	

}


int _EcdhGenPubKey(unsigned char * sk,point *p1)
{

	unsigned char buffer_ecdh[256];
	unsigned char buffer_receive[256];

	int i = 0;	

	for(i = 0; i < 256; i++)
		buffer_ecdh[i] = i;

	buffer_ecdh[0] = SPI1_WRITE_DATA;
	buffer_ecdh[1] = 0;
	buffer_ecdh[2] = SIZE_ECDH_256;
	buffer_ecdh[3] = 0;
	buffer_ecdh[4] = 0;

	SendData(buffer_ecdh,5);


	//printf("\r\n read write test");
	delay_ms(DelayMS);
#ifdef DEBUG_DELAY	
	delay_ms(4000);
#endif	
	buffer_ecdh[0] = SPI1_WRITE_DATA;
	buffer_ecdh[1] = 0;
	buffer_ecdh[2] = Set_ECDH_PrivateKey;
	buffer_ecdh[3] = 0;
	buffer_ecdh[4] = 32;
	memcpy(&buffer_ecdh[5],sk,32);

	SendData(buffer_ecdh,37);

	//	write_spi_data(buffer_ecdh,37);


	delay_ms(DelayMS);
#ifdef DEBUG_DELAY
	delay_ms(4000);
#endif

	buffer_ecdh[0] = SPI1_WRITE_DATA;
	buffer_ecdh[1] = 0;
	buffer_ecdh[2] = Create_ECHD_PublicKey;
	buffer_ecdh[3] = 0;
	buffer_ecdh[4] = 0;

	SendData(buffer_ecdh,5);


	delay_ms(200);
#ifdef DEBUG_DELAY	
	delay_ms(4000);
#endif
	buffer_ecdh[0] = SPI1_READ_DATA;
	buffer_ecdh[1] = 0;
	buffer_ecdh[2] = Get_ECDH_PublicKey_X;
	buffer_ecdh[3] = 0;
	buffer_ecdh[4] = 32;

	ReadData(buffer_ecdh,buffer_receive,32);

	memcpy(p1->x,buffer_receive,32);

	delay_ms(DelayMS);
#ifdef DEBUG_DELAY	
	delay_ms(4000);
#endif	
	buffer_ecdh[0] = SPI1_READ_DATA;
	buffer_ecdh[1] = 0;
	buffer_ecdh[2] = Get_ECDH_PublicKey_Y;
	buffer_ecdh[3] = 0;
	buffer_ecdh[4] = 32;
	ReadData(buffer_ecdh,buffer_receive,32);

	memcpy(p1->y,buffer_receive,32);

	return 0;


}
int _EcdhGenPubKeyPuf(point *p1)
{

	unsigned char buffer_ecdh[256];
	unsigned char buffer_receive[256];

	int i = 0;	

	for(i = 0; i < 256; i++)
		buffer_ecdh[i] = i;
	buffer_ecdh[0] = SPI1_WRITE_DATA;
	buffer_ecdh[1] = 0;
	buffer_ecdh[2] = SIZE_ECDH_256;
	buffer_ecdh[3] = 0;
	buffer_ecdh[4] = 0;

	SendData(buffer_ecdh,5);


	//printf("\r\n read write test");
	delay_ms(DelayMS);
#ifdef DEBUG_DELAY	
	delay_ms(4000);
#endif	
	buffer_ecdh[0] = SPI1_WRITE_DATA;
	buffer_ecdh[1] = 0;
	buffer_ecdh[2] = Set_ECDH_PrivateKey_PUF;
	buffer_ecdh[3] = 0;
	buffer_ecdh[4] = 0;
	SendData(buffer_ecdh,5);


	delay_ms(200);
	delay_ms(DelayMS);
#ifdef DEBUG_DELAY
	delay_ms(4000);
#endif

	buffer_ecdh[0] = SPI1_WRITE_DATA;
	buffer_ecdh[1] = 0;
	buffer_ecdh[2] = Create_ECHD_PublicKey;
	buffer_ecdh[3] = 0;
	buffer_ecdh[4] = 0;
	SendData(buffer_ecdh,5);

	delay_ms(200);
#ifdef DEBUG_DELAY	
	delay_ms(4000);
#endif
	buffer_ecdh[0] = SPI1_READ_DATA;
	buffer_ecdh[1] = 0;
	buffer_ecdh[2] = Get_ECDH_PublicKey_X;
	buffer_ecdh[3] = 0;
	buffer_ecdh[4] = 32;

	ReadData(buffer_ecdh,buffer_receive,32);

	memcpy(p1->x,buffer_receive,32);

	delay_ms(DelayMS);
#ifdef DEBUG_DELAY	
	delay_ms(4000);
#endif	
	buffer_ecdh[0] = SPI1_READ_DATA;
	buffer_ecdh[1] = 0;
	buffer_ecdh[2] = Get_ECDH_PublicKey_Y;
	buffer_ecdh[3] = 0;
	buffer_ecdh[4] = 32;

	ReadData(buffer_ecdh,buffer_receive,32);
	memcpy(p1->y,buffer_receive,32);

	return 0;


}

#define ECDH_SESSION_KEY_GEN_PRINT
int _EcdhGenSessionKeyPuf(point *p1, unsigned char  *key,size_t* key_length)
{
	unsigned char buffer_ecdh[256];
	unsigned char buffer_receive[256];
	unsigned char XofKey[32];
	int i = 0;	

	buffer_ecdh[0] = SPI1_WRITE_DATA;
	buffer_ecdh[1] = 0;
	buffer_ecdh[2] = SIZE_ECDH_256;
	buffer_ecdh[3] = 0;
	buffer_ecdh[4] = 0;
	SendData(buffer_ecdh,5);
	delay_ms(DelayMS);
#ifdef DEBUG_DELAY	
	delay_ms(4000);
#endif	

	delay_ms(DelayMS);
	buffer_ecdh[0] = SPI1_WRITE_DATA;
	buffer_ecdh[1] = 0;
	buffer_ecdh[2] = Set_ECDH_PublicKey_X;
	buffer_ecdh[3] = 0;
	buffer_ecdh[4] = 32;
	memcpy(&buffer_ecdh[5],p1->x,32);
	SendData(buffer_ecdh,37);
	delay_ms(DelayMS);
#ifdef DEBUG_DELAY	
	delay_ms(4000);
#endif

	buffer_ecdh[0] = SPI1_WRITE_DATA;
	buffer_ecdh[1] = 0;
	buffer_ecdh[2] = Set_ECDH_PublicKey_Y;
	buffer_ecdh[3] = 0;
	buffer_ecdh[4] = 32;
	memcpy(&buffer_ecdh[5],p1->y,32);
	SendData(buffer_ecdh,37);

	delay_ms(DelayMS);
#ifdef DEBUG_DELAY	
	delay_ms(4000);
#endif	

	buffer_ecdh[0] = SPI1_WRITE_DATA;
	buffer_ecdh[1] = 0;
	buffer_ecdh[2] = Create_ECHD_KEY;
	buffer_ecdh[3] = 0;
	buffer_ecdh[4] = 0;
	SendData(buffer_ecdh,5);
	delay_ms(200);
#ifdef DEBUG_DELAY	
	delay_ms(4000);
#endif	



#ifdef DEBUG_DELAY	
	delay_ms(4000);
#endif	



	buffer_ecdh[0] = SPI1_WRITE_DATA;
	buffer_ecdh[1] = 0;
	buffer_ecdh[2] = SET_EEPROM_BY_KEY;
	buffer_ecdh[3] = 0;
	buffer_ecdh[4] = 0;	

	SendData(buffer_ecdh,5);
	delay_ms(DelayMS);
	return 0;
}

int _EcdhGenSessionKey(unsigned char * sk,point *p1, unsigned char  *key,size_t* key_length)
{
	return 0;
}




int _RsaPubEnc2048(unsigned char * pub_key_n,unsigned char * pub_key_e,unsigned char * out, unsigned char *in, size_t len,int padding)
{

	unsigned char buffer[512];
	unsigned char buffer_receive[256];

	buffer[0] = SPI1_WRITE_DATA;
	buffer[1] = 0;
	buffer[2] = SIZE_RSA_2048;
	buffer[3] = 0;
	buffer[4] = 0;
	SendData(buffer,5);
	delay_ms(DelayMS);

	memcpy(buffer+5,in,256);	
	buffer[0] = SPI1_WRITE_DATA;
	buffer[1] = 0;
	buffer[2] = Set_RSA_PlainText_M;
	buffer[3] = 0x01;
	buffer[4] = 00;
	SendData(buffer,256+5);
	delay_ms(DelayMS);

	memcpy(buffer+5,pub_key_n,256);	
	buffer[0] = SPI1_WRITE_DATA;
	buffer[1] = 0;
	buffer[2] = Set_RSA_Modulus_n;
	buffer[3] = 0x01;
	buffer[4] = 00;
	SendData(buffer,256+5);
	delay_ms(DelayMS);

	memcpy(buffer+5,pub_key_e,256);	
	buffer[0] = SPI1_WRITE_DATA;
	buffer[1] = 0;
	buffer[2] = Set_RSA_PublicExpo;
	buffer[3] = 0x01;
	buffer[4] = 00;
	SendData(buffer,256+5);
	delay_ms(DelayMS);

	buffer[0] = SPI1_WRITE_DATA;
	buffer[1] = 0;
	buffer[2] = Encrypt_RSA;
	buffer[3] = 0;
	buffer[4] = 0;
	SendData(buffer,5);
	delay_ms(64);
	delay_ms(64);

	buffer[0] = SPI1_READ_DATA;
	buffer[1] = 0;
	buffer[2] = Get_RSA_CipherText_C;
	buffer[3] = 0x01;
	buffer[4] = 0;
	ReadData(buffer,buffer_receive,256);
	
	memcpy(out,buffer_receive,256);	
	return 0;
}

int _RsaPubDec2048(unsigned char * priv_key,unsigned char * pub_key_n,unsigned char * out, unsigned char *in, size_t len,int padding)
{

	unsigned char buffer[512];
	unsigned char buffer_receive[256];

	buffer[0] = SPI1_WRITE_DATA;
	buffer[1] = 0;
	buffer[2] = SIZE_RSA_2048;
	buffer[3] = 0;
	buffer[4] = 0;
	SendData(buffer,5);
	delay_ms(DelayMS);

	memcpy(buffer+5,in,256);	
	buffer[0] = SPI1_WRITE_DATA;
	buffer[1] = 0;
	buffer[2] = Set_RSA_CipherText_C;
	buffer[3] = 0x01;
	buffer[4] = 00;
	SendData(buffer,256+5);
	delay_ms(DelayMS);

	memcpy(buffer+5,pub_key_n,256);	
	buffer[0] = SPI1_WRITE_DATA;
	buffer[1] = 0;
	buffer[2] = Set_RSA_Modulus_n;
	buffer[3] = 0x01;
	buffer[4] = 00;
	SendData(buffer,256+5);
	delay_ms(DelayMS);

	memcpy(buffer+5,priv_key,256);	
	buffer[0] = SPI1_WRITE_DATA;
	buffer[1] = 0;
	buffer[2] = Set_RSA_PrivateKey_d;
	buffer[3] = 0x01;
	buffer[4] = 00;
	SendData(buffer,256+5);
	delay_ms(DelayMS);

	buffer[0] = SPI1_WRITE_DATA;
	buffer[1] = 0;
	buffer[2] = Decrypt_RSA;
	buffer[3] = 0;
	buffer[4] = 0;
	SendData(buffer,5);
	delay_ms(5500);

	buffer[0] = SPI1_READ_DATA;
	buffer[1] = 0;
	buffer[2] = Get_RSA_PlainText_M;
	buffer[3] = 0x01;
	buffer[4] = 0;
	ReadData(buffer,buffer_receive,256);
	
	memcpy(out,buffer_receive,256);	
	return 0;
}


