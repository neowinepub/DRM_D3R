#ifndef GLOBAL_H
#define GLOBAL_H 
#include <stdint.h>
#if 1
#define PRINTLOG(...) printf(__VA_ARGS__)
#else
#define PRINTLOG(...) (void)0
#endif
extern int cs;
extern unsigned char gAES_KEY_X3[32];
extern unsigned char gAES_KEY_X2[32];
extern unsigned char gAES_KEY_X1[32];
extern unsigned char gAES_KEY_X0[32];
extern unsigned char gAES_KEY_SEED[32];
extern unsigned char gUID_PW_PT[16];
extern unsigned char ADDR_NOR_W;
extern unsigned char ADDR_NOR_R;
extern unsigned char COMM_NOR_W;
extern unsigned char COMM_NOR_R;
extern unsigned char MIDR_INCDEC[2];
extern unsigned char MIDR_CNT0[2];
extern unsigned char MIDR_CNT1[2];
extern unsigned char ADDR_SUPER_PW[2];
extern unsigned char ADDR_DETOUR_PW[2];
extern unsigned char ADDR_DESTORY0_PW[2];
extern unsigned char ADDR_DESTORY1_PW[2];
extern unsigned char ADDR_EEPROM_PW[2];
extern unsigned char ADDR_UID_PW[2];
#define R402
#ifdef R402
extern unsigned char ADDR_SUPER_PW_CNT[2];
extern unsigned char ADDR_DETOUR_PW_CNT[2];
extern unsigned char ADDR_DESTORY0_PW_CNT[2];
extern unsigned char ADDR_DESTORY1_PW_CNT[2];
extern unsigned char ADDR_EEPROM_PW_CNT[2];
extern unsigned char ADDR_UID_PW_CNT[2];
#else
unsigned char ADDR_SUPER_PW_CNT[2] = {0xED,0x90};
unsigned char ADDR_DETOUR_PW_CNT[2] = {0xED,0xD0};
unsigned char ADDR_DESTORY0_PW_CNT[2] = {0xEE,0x10};
unsigned char ADDR_DESTORY1_PW_CNT[2] = {0xEE,0x50};
unsigned char ADDR_EEPROM_PW_CNT[2] = {0xEE,0x90};
unsigned char ADDR_UID_PW_CNT[2] = {0xEE,0x90};

#endif

extern unsigned char ADDR_SUPER_PW_CNT_PAGE[2];
extern unsigned char ADDR_DETOUR_PW_CNT_PAGE[2];
extern unsigned char ADDR_DESTORY0_PW_CNT_PAGE[2];
extern unsigned char ADDR_DESTORY1_PW_CNT_PAGE[2];
extern unsigned char ADDR_EEPROM_PW_CNT_PAGE[2];
extern unsigned char ADDR_UID_PW_CNT_PAGE[2];
extern unsigned char ADDR_EE_KEY_AES_x0[2];
extern unsigned char ADDR_EE_KEY_AES_x1[2];
extern unsigned char ADDR_EE_KEY_AES_x2[2];
extern unsigned char ADDR_EE_KEY_AES_x3[2];
extern unsigned char ADDR_EE_KEY_RS_x3[2]; 
extern unsigned char ADDR_EE_MEM_BKUP[2];
extern unsigned char ADDR_EE_SEED_KEY[2];
extern unsigned char EE_MEM_BKUP_RSFLAG[2];
//**************************************************************************
//* Instruction End
//**************************************************************************


//**************************************************************************
//* Register Address
//**************************************************************************

extern unsigned char RG_BT_LOGIC_SEL[2];

extern unsigned char RG_ST0_OPMODE[2] ;
extern unsigned char RG_EET_CTRL[2];
extern unsigned char RG_EET_OPMODE[2];
extern unsigned char RG_EET_BYOB_LEN[2];
extern unsigned char RG_EET_BYOB_ADDR_LSB[2];
extern unsigned char RG_ST1_RND_OPMODE[2];
extern unsigned char RG_AES_CTRL[2];
extern unsigned char RG_OKA_CTRL[2];
extern unsigned char RG_ST1_MIDR_OPMODE[2];
extern unsigned char RG_RNDGEN_USER[2];
extern unsigned char RG_SUPER_WIRE_PW0[2];
extern unsigned char RG_EE_KEY_AES_CTRL [2];
extern unsigned char RG_PERM_GET_CTRL [2];
extern unsigned char RG_ST2_SYMCIP_OPMODE  [2];
extern unsigned char RG_PERM_GET_CTRL1   [2];
extern unsigned char RG_PERM_RELEASE   [2];
extern unsigned char RG_ST1_OKA_OPMODE[2];
extern unsigned char RG_ST1_SYMCIP_OPMODE[2];
extern unsigned char RG_ST3_SYMCIP_RSCREATE_OPMODE[2];
extern unsigned char RG_ST3_SYMCIP_KEYLOAD_OPMODE[2];
extern unsigned char RG_FFFF[2];
extern unsigned char RG_EE_USER_ZONE_SEL[2];
extern unsigned char RG_PERM_GET_EE_RD_PRE_SP[2];
extern unsigned char RG_EE_CFG_RD_RG_EEBUF_ST[2];
extern unsigned char RG_MCUAuthResult [2];
extern unsigned char RG_ST2_SYMCIP_SHAAuth_CMP_DP [2];
extern unsigned char RG_EETEST_BYOB_ADDR_LSB[2];

extern unsigned char RG_SHA_CTRL[2];
extern unsigned char RG_ST1_STDSPI_OPMODE [2];


extern unsigned char RG_EEBUF100[2] ;
extern unsigned char RG_EEBUF300[2] ;
extern unsigned char RG_EEBUF310[2] ;
extern unsigned char RG_EEBUF320[2] ;
extern unsigned char RG_EEBUF330[2] ;
extern unsigned char RG_EEBUF400[2] ;
extern unsigned char RG_EEBUF410[2] ;
extern unsigned char RG_EEBUF420[2] ;
extern unsigned char RG_EEBUF430[2] ;
extern unsigned char RG_EEBUF500[2] ;
extern unsigned char RG_EEBUF510[2] ;

extern unsigned char	RG_ACCESS[2] ;
extern unsigned char RG_SLEEP_TIMER_MSB[2];
extern unsigned char RG_SLEEP_TIMER_LSB[2];
extern unsigned char RG_KL_CTRL[2];
extern unsigned char RG_RSCREATE_CTRL[2];
extern unsigned char RG_MEM_TEST_OPMODE[2];
extern unsigned char RG_ST1_MEM_TEST_OPMODE[2];
extern unsigned char A_MIDR[2];
extern unsigned char A_EE_MEM_BKUP_RSFLAG[2];
extern unsigned char A_EE_MEM_BKUP_CTRL[2];
extern unsigned char RG_BIST_MODE[2];
extern unsigned char RG_EE_BI_NO[2];
extern unsigned char RG_MB_ERROR_BIT[2];
extern unsigned char RG_SRAM_BIST_RESULT[2];
extern unsigned char RG_SHAAUTH_CTRL[2];
extern unsigned char RG_SOFT_RESET[2];				
/////////////////////////////////////DEBUG REGISTER/////////////////////////////////////////////////////
extern unsigned char RG_ST0_CUR[2]                      ;
extern unsigned char RG_CHK_RSFLAG[2]                   ;
extern unsigned char RG_ST1_CHK_RSFLAG_CUR[2]           ;
extern unsigned char RG_ST1_PON_READ_CUR[2]             ;
extern unsigned char RG_STCM0_CUR[2]                    ;
extern unsigned char RG_ST1_STDSPI_CUR[2]               ;
extern unsigned char RG_ST1_EE_CFG_CUR[2]               ;
extern unsigned char RG_ST1_RND_CUR[2]                  ;
extern unsigned char RG_ST1_SYMCIP_CUR[2]               ;
extern unsigned char RG_ST1_OKA_CUR[2]                  ;
extern unsigned char RG_ST1_MIDR_CUR[2]                 ;
extern unsigned char RG_ST1_PERM_GET_CUR[2]             ;
extern unsigned char RG_ST1_EEP_OW_CTRL_CUR[2]          ;
extern unsigned char RG_ST1_MEM_TEST_CUR[2]             ;
extern unsigned char RG_ST2_EEP_OW_CTRL_CUR[2]          ;
extern unsigned char RG_ST2_SYMCIP_OPMODE_AES_CUR[2]    ;
extern unsigned char RG_ST2_OKA_OKA2_CUR[2]             ;
extern unsigned char RG_ST2_STDSPI_SHA_CUR[2]           ;
extern unsigned char RG_ST2_SYMCIP_SHAAuth_CUR[2]       ;
extern unsigned char RG_ST2_RND_CUR[2]                  ;
extern unsigned char RG_ST3_RND_CUR[2]                  ;
extern unsigned char RG_ST3_SYMCIP_AES_CUR[2]           ;
extern unsigned char RG_ST3_SYMCIP_KEYLOAD_CUR[2]       ;
extern unsigned char RG_ST3_SYMCIP_RSCREATE_CUR[2]      ;

//**************************************************************************
//* Register Address End
//**************************************************************************

//**************************************************************************
//* RG_EET_OPMODE Register Value
//**************************************************************************
extern unsigned int STEM_WRITE_MAIN_AUTO;
extern unsigned int STEM_READ_MAIN;
//**************************************************************************
//* RG_EET_OPMODE Register Value End
//**************************************************************************

//**************************************************************************
//* RG_MEM_TEST_OPMODE Register Value
//**************************************************************************
extern unsigned int ST1_MEM_TEST_RG_EEBUF_WR;
extern unsigned int ST1_MEM_TEST_EE_WRRD_EN;
extern unsigned int ST1_MEM_TEST_EE_WR_EN;
extern unsigned int ST1_MEM_TEST_STANDBY;
extern unsigned int ST1_MEM_TEST_EE_BIST;
extern unsigned char A_EEPROM[2];
extern unsigned char A_EEPROM_FFC0[2];
//**************************************************************************
//* RG_MEM_TEST_OPMODE Register Value End
//**************************************************************************

unsigned char tspi_interface(unsigned int cs, unsigned char inst, unsigned char *addr,unsigned char count, unsigned char opcode,unsigned char param0, unsigned char param1, unsigned char *tx_data, unsigned char *rx_data, int Byte_num);
void reversebuffer(unsigned char *dest,unsigned char *org,int count);
void delay_us(unsigned int us);
void Delay_us(unsigned int us);
void Delay_ms(unsigned int us);
void delay_ms(unsigned int i);
void Hexstr2Bytes( char * str, unsigned char  * result);
void PrintByte(unsigned char *pData,int size );
void PrintByte2(unsigned char *pData,int size );
void printbyte(unsigned char *pData,int size );
 void SetSPI0();
unsigned char SET_SPI1();
char get_char();
char _uart_get_char();
unsigned char SpiSpeedSet(void);
void API_TEST_MAIN();
void GenINT0();
void Reset();
void EndOperation(void);
int KeyLoadIDX(int KeyAseCtrl,int TextSel,int KeySel, int KeySaveSel, unsigned char *LoadKEY ,int mode, unsigned char *pPrevKey);
void KeySetup(unsigned char *KEY);
void ClearSleepTimer();
int start_main(void);
#define SPI_0 0
#define SPI_1 1
void SetSPIMode(int SPI_MODE);
#endif //GLOBAL_H