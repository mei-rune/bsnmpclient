# TODO: read values from CMakeLists.txt somehow instead of hard coding them here
CC=gcc


OBJECTS=build/agent.o         \
        build/asn1.o          \
        build/snmp.o          \
        build/client.o        \
        build/crypto.o        \
        build/support.o       
        
APPS_OBJECTS=build/apps/bsnmpimport.o   \
        build/apps/bsnmpmap.o           \
        build/apps/bsnmptc.o            \
        build/apps/bsnmptools.o         \
        build/apps/getopt.o             \
        build/apps/getopt1.o       	    \
        build/apps/util.o       	    \
        build/apps/main.o       
        
        
OPENSSL_OBJECTS=build/ssl/openssl_aes_cfb.o   \
                build/ssl/openssl_aes_core.o  \
                build/ssl/openssl_cbc_enc.o   \
                build/ssl/openssl_cfb128.o    \
                build/ssl/openssl_des_enc.o   \
                build/ssl/openssl_evp.o       \
                build/ssl/openssl_evp_aes.o   \
                build/ssl/openssl_evp_des.o   \
                build/ssl/openssl_evp_sha.o   \
                build/ssl/openssl_md5.o       \
                build/ssl/openssl_rand.o      \
                build/ssl/openssl_set_key.o   \
                build/ssl/openssl_sha1.o

all: build/libsnmpclient.a build/bsnmptools.exe


clean: 
	rm -fr build

build:
	mkdir -p build
	
build_ssl: build
	mkdir -p build/ssl
	
build_apps: build
	mkdir -p build/apps

build/libsnmpclient.a: ${OBJECTS} ${OPENSSL_OBJECTS}
	ar rcs build/libsnmpclient.a ${OBJECTS} ${OPENSSL_OBJECTS}

build/bsnmptools.exe: ${APPS_OBJECTS} 
	$(CC) -g -Wall -o build/bsnmptools.exe ${APPS_OBJECTS} build/libsnmpclient.a -lWs2_32  -lwsock32


build/%.o: src/%.c build
	$(CC) -g -Wall -c $< -o $@ -I include
	
	
build/apps/%.o: apps/%.c build_apps
	$(CC) -g -Wall -c $< -o $@ -I include
	
	
build/ssl/%.o: src/openssl/%.c build_ssl
	$(CC) -g -Wall -c $< -o $@ -I include

