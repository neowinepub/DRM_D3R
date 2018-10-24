
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
#include <wiringPi.h>

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
/*
 * text-color-example.c
 *
 * Builds a pipeline with [videotestsrc ! textoverlay ! ximagesink] and
 * moves text
 *
 * Needs gst-plugins-base installed.
 */
	static gboolean
	bus_call (GstBus	 *bus,
			  GstMessage *msg,
			  gpointer	  data)
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
	
	
	static void
	on_pad_added (GstElement *element,
				  GstPad	 *pad,
				  gpointer	  data)
	{
	  	GstPad *sinkpad;
	  	GstElement *decoder = (GstElement *) data;
	
	  	/* We can now link this pad with the vorbis-decoder sink pad */
	 	g_print ("Dynamic pad created, linking demuxer/decoder\n");
	
	 	sinkpad = gst_element_get_static_pad (decoder, "sink");
	
	 	gst_pad_link (pad, sinkpad);
	
	 	gst_object_unref (sinkpad);
	}

				  
	int first = 1;	  
	AES_KEY encKey;				  
	static GstPadProbeReturn
	cb_have_data (GstPad			*pad,
			  	  GstPadProbeInfo   *info,
			  	  gpointer		     user_data)
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
		memset(iv,0,32);
		buffer = GST_PAD_PROBE_INFO_BUFFER (info);
		buffer = gst_buffer_make_writable (buffer);
		
		wiringPiSetupPhys();	  
	  
		   
		if (buffer == NULL)
			return GST_PAD_PROBE_OK;
		
		/* Mapping a buffer can fail (non-writable) */
		if (gst_buffer_map (buffer, &map, GST_MAP_WRITE)) 
		{
       		Dorca3CipherDecipherGivenIdx(-1,RG_ENC,1 /*AES*/,0,32,0,KEY1,map.data,16,MODE_ECB,0);		
       		Dorca3CipherDecipherGivenIdx(-1,RG_ENC,1 /*AES*/,0,32,0,KEY1+16,map.data+16,16,MODE_ECB,0);		
	 
	 		if (AES_set_decrypt_key(KEY1, 256, &encKey) < 0)
     			printf("\r\n error making key OSSL");		
	
			/*Turn Dorca on when switch is activated at port 11*/
			if(digitalRead(11)==1)
			{
				for (i = 260 ; i < (map.size/16)*16; i += 16)	
				{
		   		AES_cbc_encrypt(&map.data[i], CT,16, &encKey, iv, AES_DECRYPT);

	  			memcpy(&map.data[i],CT,16);
				}
			}
		
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
		size_t	key_length;
		point p1;
		int   client_socket;
		int i  = 0;
		struct sockaddr_in	 server_addr;
	
		char   buff[BUFF_SIZE+5];

		client_socket  = socket( PF_INET, SOCK_STREAM, 0);

		if( -1 == client_socket)
		{
		   printf( "socket ?앹꽦 ?ㅽ뙣\n");
		   exit( 1);
		}
	
		memset( &server_addr, 0, sizeof( server_addr));
		server_addr.sin_family	   = AF_INET;
		server_addr.sin_port	   = htons( 4100);
		server_addr.sin_addr.s_addr= inet_addr( "192.168.0.25");
	
		if( -1 == connect( client_socket, (struct sockaddr*)&server_addr, sizeof( server_addr) ) )
		{
	  		printf( "?묒냽 ?ㅽ뙣\n");
	   		exit(1);
		}

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
	
		write(client_socket, p1.x, 32);
		write(client_socket, p1.y, 32); 

		read(client_socket, p1.x, 32);
		read(client_socket, p1.y, 32);	
		close(client_socket);
		printf("\r\n TEST _EcdhGenSessionKey");
	
		key_length = 32;

	#ifdef SK	
		EcdhGenSessionKey(sk,&p1,common_key,&key_length);
	#else
		EcdhGenSessionKeyPuf(&p1,NULL,&key_length);	
	#endif
		
	}

	#define LOGGING() ;//(void 0);

	int main (int	argc,
		 	  char *argv[])
	{
	  	GMainLoop *loop;
	  	GstCaps *caps_rtph264depay_sink;
	 	GstCaps *caps_rtph264depay_source;	  
	  	GstElement *pipeline, *tcpclientsrc  ,*gdpdepay, *omxh264dec , *h264parse , *autovideoconvert , *glimagesink, *rtph264depay ;
	  	GstBus *bus;
	 	guint bus_watch_id;
     	GstPad *pad;
	 	/* Initialization */
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
	  	gst_init (&argc, &argv);
	  	loop = g_main_loop_new (NULL, FALSE);


	  	printf("\nCreate gstreamer elements");
	  	/* Create gstreamer elements */
	  	pipeline = gst_pipeline_new ("audio-player");
	  	LOGGING();
	  	tcpclientsrc     = gst_element_factory_make ("tcpclientsrc",		"tcpclientsrc-inst");
	  	LOGGING();	  
	  	omxh264dec   = gst_element_factory_make ("omxh264dec",		"omxh264dec-inst");
	  	LOGGING();	  
	  	h264parse   = gst_element_factory_make ("h264parse", 	"h264parse-inst");
	  	LOGGING();	  
	  	autovideoconvert 	   = gst_element_factory_make ("autovideoconvert",	"autovideoconvert-inst");
	  	LOGGING();	  
	  	glimagesink	   = gst_element_factory_make ("glimagesink", "glimagesink-inst");
	  	LOGGING();	  
	  	rtph264depay	   = gst_element_factory_make ("rtph264depay", "rtph264depay-inst");	  
	  	LOGGING();	  
	  	gdpdepay	   = gst_element_factory_make ("gdpdepay", "gdpdepay-inst");	  	  
	  	LOGGING();
	  	if (!pipeline || !tcpclientsrc || !omxh264dec || !gdpdepay|| !h264parse || !autovideoconvert || !glimagesink || !rtph264depay) {
			g_printerr ("One element could not be created. Exiting.\n");
		return -1;
	}

	  	/* Set up the pipeline */
		LOGGING();
	  	/* we set the input filename to the source element */
	  	g_object_set (tcpclientsrc,
	  	"host","192.168.0.25",
      	"port", 5000 ,
      	NULL);
      
	  	LOGGING();


   	  	printf("\n rtph264depay source");
 	    caps_rtph264depay_source = gst_caps_new_simple ("video/x-h264",
       	"stream-format", G_TYPE_STRING, "byte-stream",
       	"alignment", G_TYPE_STRING, "nal",
        NULL);	
   	  	LOGGING();

	  	g_object_set (glimagesink,
	  	"sync", 0,   
      	NULL);

		LOGGING();
	  	/* we add a message handler */
	  	bus = gst_pipeline_get_bus (GST_PIPELINE (pipeline));
	  	bus_watch_id = gst_bus_add_watch (bus, bus_call, loop);
	  	gst_object_unref (bus);
		LOGGING();
	  	/* we add all elements into the pipeline */
	  	/* file-source | ogg-demuxer | vorbis-decoder | converter | alsa-output */
	  	gst_bin_add_many (GST_BIN (pipeline),
							gdpdepay,
							tcpclientsrc, 
							omxh264dec, 
							h264parse, 
							autovideoconvert, 
							glimagesink,
							rtph264depay, 
							NULL);
	  	LOGGING();

		printf("\r\n gst_element_get_static_pad \r\n");
		pad = gst_element_get_static_pad (gdpdepay, "src");
		gst_pad_add_probe (pad, GST_PAD_PROBE_TYPE_BUFFER,
		(GstPadProbeCallback) cb_have_data, NULL, NULL);
		gst_object_unref (pad);
	 	/* we link the elements together */
	  	/* file-source -> ogg-demuxer ~> vorbis-decoder -> converter -> alsa-output */
   		//gst_element_link_filtered (udpsrc, rtph264depay, caps_rtph264depay_sink);
   		//gst_caps_unref (caps_rtph264depay_sink);
   	  	gst_element_link(tcpclientsrc, gdpdepay);
	  	gst_element_link(gdpdepay, rtph264depay);
  
  		// gst_element_link(capsfilter,text); 
   		gst_element_link_filtered (rtph264depay, h264parse , caps_rtph264depay_source);
   		gst_caps_unref (caps_rtph264depay_source);  
   
  		gst_element_link(h264parse,omxh264dec  );
   		gst_element_link(omxh264dec ,autovideoconvert );
   		gst_element_link(autovideoconvert,glimagesink);  
	
	  	/* note that the demuxer will be linked to the decoder dynamically.
		The reason is that Ogg may contain various streams (for example
		audio and video). The source pad(s) will be created at run time,
		by the demuxer when it detects the amount and nature of streams.
		Therefore we connect a callback function which will be executed
		when the "pad-added" is emitted.*/
		
	  	/* Set the pipeline to "playing" state*/
	  	g_print ("Now playing: ");
	  	gst_element_set_state (pipeline, GST_STATE_PLAYING);
	
	  	/* Iterate */
	  	g_print ("Running...\n");
	  	g_main_loop_run (loop);
	
	  	/* Out of the main loop, clean up nicely */
	  	g_print ("Returned, stopping playback\n");
	  	gst_element_set_state (pipeline, GST_STATE_NULL);
	
	  	g_print ("Deleting pipeline\n");
	  	gst_object_unref (GST_OBJECT (pipeline));
	  	g_source_remove (bus_watch_id);
	  	g_main_loop_unref (loop);
	
	  	return 0;
	}

