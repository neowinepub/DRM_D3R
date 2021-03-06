#ifndef _DORCA30_FUNCTION_H
#define _DORCA30_FUNCTION_H 

#define SPI1_WRITE_DATA 0x61
#define SPI1_READ_DATA  0x71
#define	SET_ECC_Q	0x01
#define	SET_ECC_A	0x02
#define	SET_ECC_B	0x03
#define	SET_ECC_xG	0x04
#define	SET_ECC_yG	0x05
#define	SET_ECC_n	0x06
#define	SET_Curve	0x07
#define   SLEEP           0x08
#define DEEP_SLEEP 0x09

#define	Set_ECDH_PrivateKey	0x11
#define	Set_ECDH_PrivateKey_PUF	0x12
#define	Create_ECHD_PublicKey	0x13
#define	Set_ECDH_PublicKey_X 	0x14
#define	Set_ECDH_PublicKey_Y 	0x15
#define	Get_ECDH_PublicKey_X 	0x16
#define	Get_ECDH_PublicKey_Y 	0x17
#define	Create_ECHD_KEY 	0x18

#define SET_EEPROM_BY_KEY 0x1a
#define	Get_ECDH_KEY_Y 	0x20
#define Get_ECDH_Result 0x23;


#define Set_ECDSA_PrivateKey 0x41
#define Set_ECDSA_PrivateKey_PUF  0x42
#define Set_ECDSA_K_RND 0x43
#define Set_ECDSA_K_RND_PUF 0x44
#define Set_ECDSA_Public_Key_Xq 0x45
#define Set_ECDSA_Public_Key_Yq 0x46
#define Create_ECDSA_Public_Key 0x47
#define Get_ECDSA_Public_Key_Xq 0x48
#define Get_ECDSA_Public_Key_Yq 0x49
#define Set_ECDSA_r 0x50
#define Set_ECDSA_s 0x51
#define Get_ECDSA_r 0x52
#define Get_ECDSA_s 0x53
#define Create_ECDSA_Sign 0x54
#define Set_ECDSA_h 0x55
#define Get_ECDSA_h 0x56
#define Get_ECDSA_Result 0x57
#define Do_ECDSA_Verify 0x58
		
#define	Set_RSA_Prime_q	0x81
#define	Set_RSA_Prime_p	0x82
#define	Set_RSA_PublicExpo	0x83
#define	Set_RSA_PrivateKey_d	0x84
#define	Set_RSA_PlainText_M	0x85
#define	Set_RSA_CipherText_C	0x86
#define	Get_RSA_CipherText_C	0x87
#define	Set_RSA_Modulus_n	0x88
#define	Get_RSA_PlainText_M	0x89
#define	Get_RSA_PublicExpo	0x90
#define	Get_RSA_PrivateKed_d	


#define	Get_RSA_Modulus_n	0x92
#define	Create_RSA_Key	0x93
#define	Encrypt_RSA	0x94
#define	Decrypt_RSA	0x95
#define SIZE_ECDH_256   0xA0
#define SIZE_ECDH_521   0xA1
#define SIZE_ECDSA_256  0xA2
#define SIZE_ECDSA_521  0xA3
#define SIZE_RSA_2048   0xA4
#define SAVE_KEY 0xA6
#define MAKE_RAND 0xA7
#define Get_RAND 0xA8
#define KEY_INDEX 1



typedef enum {
		BKUP_EE_SUPER_PASS = 0,
		BKUP_EE_DETOUR_PASS,
		BKUP_EE_DESTORY0_PASS,
		BKUP_EE_DESTORY1_PASS,
		BKUP_EE_EEPROM_PASS,
		BKUP_EE_UID_PASS,
		BKUP_EE_SUPER_PASS_CNT,
		BKUP_EE_DETOUR_PASS_CNT,
		BKUP_EE_DESTORY0_PASS_CNT,
		BKUP_EE_DESTORY1_PASS_CNT,
		BKUP_EE_EEPROM_PASS_CNT,
		BKUP_EE_UID_PASS_CNT
}BKUP_TYPE;

typedef enum {
	TYPE_TX = 0,
	TYPE_RX
}TRANS_TYPE;
typedef enum {
	RG_PERM_SUPER_PASS = 5,
	RG_PERM_DETOUR_PASS = 4,
	RG_PERM_DESTORY0_PASS = 3,
	RG_PERM_DESTORY1_PASS= 2,
	RG_PERM_EEPROM_PASS= 1,
	RG_PERM_UID_PASS = 0
}PERM_TYPE;

typedef enum {
	A_EE_CONFIG_NW =0,
	A_EE_CONFIG_FAC,
	A_EE_CONFIG_UID,
	A_EE_SEED_KEY,
	A_EE_CONFIG_USER,
	A_EE_CONFIG_LOCK,
	A_EE_MEM_TEST,
	A_EE_MIDR
}CONFIG_TYPE;	

typedef enum {
F_EE_MEM_BKUP_RSFLAG =0,
F_EE_MEM_BKUP_NOTUSE 
}BKUP_FLAG;

#endif //_DORCA30_FUNCTION_H