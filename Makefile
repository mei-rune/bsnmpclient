# TODO: read values from CMakeLists.txt somehow instead of hard coding them here
CC=gcc

ifeq ($(OS),Windows_NT)
    GCC_OS=WIN32
    ifeq ($(PROCESSOR_ARCHITECTURE),AMD64)
        GCC_ARCH=AMD64
    endif
    ifeq ($(PROCESSOR_ARCHITECTURE),x86)
        GCC_ARCH=IA32
    endif
else
    UNAME_S := $(shell uname -s)
    ifeq ($(UNAME_S),Linux)
        GCC_OS=LINUX
    endif
    ifeq ($(UNAME_S),Darwin)
        GCC_OS=OSX
    endif
    UNAME_P := $(shell uname -p)
    ifeq ($(UNAME_P),x86_64)
        GCC_ARCH=AMD64
    endif
    ifneq ($(filter %86,$(UNAME_P)),)
        GCC_ARCH=IA32
    endif
    ifneq ($(filter arm%,$(UNAME_P)),)
        GCC_ARCH=ARM
    endif
endif

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

ifeq ($(GCC_OS),WIN32)
all: build/libsnmpclient.a build/bsnmptools.exe
else
all: build/libsnmpclient.a build/bsnmptools
endif

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


build/bsnmptools: ${APPS_OBJECTS} 
	$(CC) -g -Wall -o build/bsnmptools ${APPS_OBJECTS} build/libsnmpclient.a

build/%.o: src/%.c build
	$(CC) -g -Wall -c $< -o $@ -I include
	
	
build/apps/%.o: apps/%.c build_apps
	$(CC) -g -Wall -c $< -o $@ -I include
	
	
build/ssl/%.o: src/openssl/%.c build_ssl
	$(CC) -g -Wall -c $< -o $@ -I include

