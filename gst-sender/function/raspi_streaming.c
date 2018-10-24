/*
 * text-color-example.c
 *
 * Builds a pipeline with [videotestsrc ! textoverlay ! ximagesink] and
 * moves text
 *
 * Needs gst-plugins-base installed.
 */
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <gst/gst.h>
#include <glib.h>
#include <stdio.h>
#include <string.h> 
#include <stdlib.h>
 #include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#include <gst/controller/gstinterpolationcontrolsource.h>
#include <gst/controller/gstlfocontrolsource.h>
#include <gst/controller/gstargbcontrolbinding.h>
#include <gst/controller/gstdirectcontrolbinding.h>
#include <openssl/aes.h>
#include "dorca30_api.h"
#include "dorca30_api_inside.h"
#include "dorca30_function.h"
#include "./include/aes.h"
#include "global.h"
#include "dorca.h"

#define BUFF_SIZE 1024
extern void Hexstr2Bytes(char * str, unsigned char * result);

static gboolean
bus_call (GstBus     *bus,
          GstMessage *msg,
          gpointer    data)
{
  	GMainLoop *loop = (GMainLoop *) data;

  	switch (GST_MESSAGE_TYPE (msg)) 
  	{

    	case GST_MESSAGE_EOS:
      		g_print ("End of stream\n");
      		g_main_loop_quit (loop);
      		break;

    	case GST_MESSAGE_ERROR: 
    	{
      		gchar  *debug;
      		GError *error;

      		gst_message_parse_error (msg, &error, &debug);
      		g_free (debug);

      		g_printerr ("Error: %s\n", error->message);
      		g_error_free (error);

      		g_main_loop_quit (loop);
      		break;
    	}
    
    	default:
      		break;
  	}

  	return TRUE;
}

int first = 1;		  
AES_KEY encKey;		  
static GstPadProbeReturn
cb_have_data (GstPad			*pad,
			  GstPadProbeInfo *info,
			  gpointer		 user_data)
 {
	gint x, y , i;
	GstMapInfo map;
	guint16 *ptr, t;
	GstBuffer *buffer;
    int size = 0;
  	int j = 0;
	unsigned char CT[16];
	unsigned char KEY1[32];
	unsigned char iv[32];
	buffer = GST_PAD_PROBE_INFO_BUFFER (info);
	buffer = gst_buffer_make_writable (buffer);
    memset(iv,0,32);
	 
	if (buffer == NULL)
	  	return GST_PAD_PROBE_OK;
  
	/* Mapping a buffer can fail (non-writable) */
	if (gst_buffer_map (buffer, &map, GST_MAP_WRITE)) 
	{
		
	#if 1
	
       	Dorca3CipherDecipherGivenIdx(-1,RG_ENC,1 /*AES*/,0,32,0,KEY1,map.data,16,MODE_ECB,0);		
       	Dorca3CipherDecipherGivenIdx(-1,RG_ENC,1 /*AES*/,0,32,0,KEY1+16,map.data+16,16,MODE_ECB,0);		


  			if (AES_set_encrypt_key(KEY1, 256, &encKey) < 0)
     			printf("\r\n error making key OSSL");

  
			for (i = 260 ; i < (map.size/16)*16; i += 16)	
				{
					AES_cbc_encrypt(&map.data[i],  CT, 16, &encKey, iv, AES_ENCRYPT);
		
	  				memcpy(&map.data[i],CT,16);
				}
	#endif	
	  	gst_buffer_unmap (buffer, &map);
	}

	GST_PAD_PROBE_INFO_DATA (info) = buffer;
  
	return GST_PAD_PROBE_OK;
}
 //#define SK
void HandShake(unsigned char *key) 
{

	unsigned char  sk[32];
	unsigned char  common_key[32];	
	unsigned char  temp_buffer[32];
	size_t  key_length;
	point p1,p2;		
	
	int   server_socket;
	int   client_socket;
	int   client_addr_size;
	
	struct sockaddr_in	 server_addr;
	struct sockaddr_in	 client_addr;
	
	char   buff_rcv[BUFF_SIZE+5];
	char   buff_snd[BUFF_SIZE+5];
	int 	 option;
	int i = 0;
	
	server_socket  = socket( PF_INET, SOCK_STREAM, 0);
	if( -1 == server_socket)
	{
	   	printf( "server socket ?앹꽦 ?ㅽ뙣\n");
	   	exit( 1);
	}
	
	option = 1;          // SO_REUSEADDR ???듭뀡 媛믪쓣 TRUE 濡?
	setsockopt( server_socket, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option) );
	memset( &server_addr, 0, sizeof( server_addr));
	server_addr.sin_family	   = AF_INET;
	server_addr.sin_port	   = htons( 4100);
	server_addr.sin_addr.s_addr= htonl( INADDR_ANY);
	
	if( -1 == bind( server_socket, (struct sockaddr*)&server_addr, sizeof( server_addr) ) )
	{
	   	printf( "bind() ?ㅽ뻾 ?먮윭\n");
	   	exit( 1);
	}
	
	if( -1 == listen(server_socket, 5))
	{
	   	printf( "listen() ?ㅽ뻾 ?ㅽ뙣\n");
	   	exit( 1);
	}

		printf("server waiting\n");
	    
		printf("\r\n TEST EcdhGenPubKey");
	
		SetSPIMode(SPI_0);
		GetRandomNumber(sk);
		GetRandomNumber(&sk[16]);	
		SetSPIMode(SPI_1);	

	#ifdef SK
		EcdhGenPubKey(sk,&p1);
	#else
		EcdhGenPubKeyPuf(&p1);
	#endif
		printf("\r\nGet_ECDH_PublicKey_X\r\n");
		PrintByte(p1.x,32);

		printf("\r\n Expected ECDH_PublicKey_X\r\n");
		printf("\r\nefb50f68f26558c1d42847e82dc552607965049cc6f65d7ed8b8d02a1d8825f9");
		Hexstr2Bytes("efb50f68f26558c1d42847e82dc552607965049cc6f65d7ed8b8d02a1d8825f9",temp_buffer);
		if(memcmp(p1.x,temp_buffer,32) == 0)
			printf("\r\n PASS");
		else
			printf("\r\n FAIL");
	
		client_addr_size  = sizeof( client_addr);
		client_socket	  = accept( server_socket, (struct sockaddr*)&client_addr, &client_addr_size);
	
		if ( -1 == client_socket)
		{
	   		printf( "?대씪?댁뼵???곌껐 ?섎씫 ?ㅽ뙣\n");
	   		exit( 1);
		}

		printf("\r\n TEST accept");
		read(client_socket, p2.x, 32);
		read(client_socket, p2.y, 32);	

	
		write(client_socket, p1.x, 32);
		write(client_socket, p1.y, 32);	
		close(client_socket);	
		close(server_socket);
		printf("\r\n TEST _EcdhGenSessionKey");

		key_length = 32;
	
	#ifdef SK
		EcdhGenSessionKey(sk,&p2,common_key,&key_length);
	#else
		EcdhGenSessionKeyPuf(&p2,NULL,&key_length);
	#endif

	}

int main (int argc, char ** argv)
{
  	gint res = 1;
 	GstElement *rpicamsrc, *h264parse, *rtph264pay, *udpsink, *gdppay, *tcpserversink ;
  	GstElement *bin;
 	GstCaps *caps;
  	GstCaps *caps_rpicamsrc;
  	GstBus *bus;
 	GstPad *pad;

	GstControlSource *cs;
	GstClock *clock;
  	GstClockID clock_id;
  	GstClockReturn wait_ret;
 	guint bus_watch_id;

 	GMainLoop *loop;
  	start_main();
  	unsigned char AES128KEY[16];
  	unsigned char AES256PT[16];
  	unsigned char AES256CT[16];  

 	memset(AES256PT,0,16);	
  	memset(AES256CT,0,16);
  	HandShake(AES128KEY);
  	SetSPIMode(SPI_0);
  	KeyFromEcdh();

  	Dorca3CipherDecipherGivenIdx(0,RG_ENC,1 /*AES*/,0,32,0,AES256CT,AES256PT,16,MODE_ECB,LAST);	
 	printf("\r\n AES 256 result");
  	printbyte(AES256CT,16);
  	Dorca3CipherDecipherGivenIdx(0,RG_ENC,1 /*AES*/,0,32,0,AES256CT,AES256PT,16,MODE_ECB,0);	
	
  	printf("\ncaps_rpicamsrc %d",__LINE__);
  	gst_init (&argc, &argv);
  	printf("\ncaps_rpicamsrc %d",__LINE__);

  	loop = g_main_loop_new (NULL, FALSE);

  	/* build pipeline */
  	bin = gst_pipeline_new ("audio-player");
   	printf("\ncaps_rpicamsrc %d",__LINE__);

    printf("\ncaps_rpicamsrc %d",__LINE__);
   	h264parse = gst_element_factory_make ("h264parse", "h264parse_inst");
  	
  	if (!h264parse) {
    	GST_WARNING ("need h264parse from gst-plugins-base");
    	printf ("need h264parse from gst-plugins-base");		
    	goto Error;
  	}   
  	rtph264pay = gst_element_factory_make ("rtph264pay", "rtph264pay_inst");
		
	if (!rtph264pay) 
	{
    	GST_WARNING ("need rtph264pay from gst-plugins-base");
    	printf ("need rtph264pay from gst-plugins-base"	);
    	goto Error;
  	}
    	
    rpicamsrc = gst_element_factory_make ("rpicamsrc", "rpicamsrc_inst");
  		
  	if (!rpicamsrc) 
  	{
    	GST_WARNING ("need rpicamsrc from gst-plugins-base");
    	printf ("need rpicamsrc from gst-plugins-base");	
    	goto Error;
  	} 
    
    gdppay = gst_element_factory_make ("gdppay", "gdppay_inst");
  	
  	if (!gdppay) 
  	{
    	GST_WARNING ("need gdppay from gst-plugins-base");
    	printf ("need gdppay from gst-plugins-base");	
    	goto Error;
  	}  

    tcpserversink = gst_element_factory_make ("tcpserversink", "tcpserversink_inst");
  
  	if (!tcpserversink) 
  	{
    	GST_WARNING ("need tcpserversink from gst-plugins-base");
    	printf ("need tcpserversink from gst-plugins-base");	
    	goto Error;
  	}  

	printf("\ncaps_rpicamsrc");
   	caps_rpicamsrc = gst_caps_new_simple ("video/x-h264",
          								  "width", G_TYPE_INT, 1280,
         								  "height", G_TYPE_INT, 720,
          								  "profile", G_TYPE_STRING, "baseline",
          								  NULL);	
  	g_object_set (rpicamsrc,
      			  "bitrate", 2097152 ,
      			  "preview", 1,
      			  "rotation", 180,
      			  "sensor-mode",0,
      			  NULL);

 	g_object_set (gdppay,
      			  "crc-header", 0 ,
      			  "crc-payload", 0 ,
      			  NULL);
	  
	g_object_set(rtph264pay,
	 	  		 "config-interval",1  ,
		  		 "pt", 96,
		  		 NULL);
	 
	g_object_set (tcpserversink ,
		  		  "host","192.168.0.25"  ,
		  		  "port", 5000,
		  		  NULL);

    bus = gst_pipeline_get_bus (GST_PIPELINE (bin));
  	bus_watch_id = gst_bus_add_watch (bus, bus_call, loop);
  	gst_object_unref (bus);

 	gst_bin_add_many (GST_BIN (bin), rpicamsrc, h264parse, rtph264pay, gdppay, tcpserversink, NULL);
  
   	pad = gst_element_get_static_pad (gdppay , "sink");
	gst_pad_add_probe (pad, GST_PAD_PROBE_TYPE_BUFFER, (GstPadProbeCallback) cb_have_data, NULL, NULL);
	gst_object_unref (pad);

   	gst_element_link_filtered (rpicamsrc, h264parse, caps_rpicamsrc);
   	gst_caps_unref (caps_rpicamsrc);
 	gst_element_link(rpicamsrc,h264parse);
   	gst_element_link(h264parse,rtph264pay);
   	gst_element_link(rtph264pay,gdppay);  
    gst_element_link(gdppay,tcpserversink);  

  	/* Iterate */
  	gst_element_set_state (bin, GST_STATE_PLAYING);
  	g_print ("Running...\n");
  	g_main_loop_run (loop);


  	/* Out of the main loop, clean up nicely */
  	g_print ("Returned, stopping playback\n");
  	gst_element_set_state (bin, GST_STATE_NULL);

  	g_print ("Deleting pipeline\n");
  	gst_object_unref (GST_OBJECT (bin));
  	g_source_remove (bus_watch_id);
  	g_main_loop_unref (loop);

  	return 0;
  	
Error:
  	return (res);
}
