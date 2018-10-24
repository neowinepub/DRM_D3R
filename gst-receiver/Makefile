SRCS =    ./function/core_funtion.c ./function/api_fuction.c ./function/test_main.c \
	./function/aes_core.c ./function/dorca.c ./function/raspi_streaming_player.c ./function/aes_ecb.c ./function/aes_misc.c ./function/cipher_memory.c ./function/register.c\
	./function/rsa_ecc_rand.c ./function/sha.c ./function/rootSerial.c ./function/permission.c ./function/mrshs256.c ./function/mrshs256.c ./function/sha_auth.c Entry.c 
OBJS = $(SRCS:.c=.o)
CFLAGS = `pkg-config --cflags gstreamer-1.0`
LIBS= `pkg-config --libs gstreamer-1.0`
INC = -I/usr/include/gstreamer-1.0 -I/usr/include/glib-2.0 -I/usr/lib/arm-linux-gnueabihf/glib-2.0/include -I/usr/local/include -L/usr/local/lib

all: test
test: $(OBJS)
	$(CC) $(LIBS) $(CFLAGS) $(LDFLAGS) -o $@ $^ -lbcm2835 -lcrypto -lssl -lwiringPi
	
.c.o: 
	@echo [Compile C] $< $(INC) 
	@$(CC) $(LIBS) $(CFLAGS) -c -o $@ $< $(INC) 
clean:
	rm -rf *.o test
	cd function && rm -rf *.o 
