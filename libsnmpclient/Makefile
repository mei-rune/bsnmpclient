# TODO: read values from CMakeLists.txt somehow instead of hard coding them here

OBJECTS=build/agent.o         \
        build/asn1.o          \
        build/snmp.o          \
        build/client.o        \
        build/crypto.o        \
        build/support.o       

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

all: build/libsnmpclient.a


clean: 
	rm -fr build

build:
	mkdir -p build
build_ssl: build
	mkdir -p build/ssl

build/libsnmpclient.a: ${OBJECTS} ${OPENSSL_OBJECTS}
	ar rcs build/libsnmpclient.a ${OBJECTS} ${OPENSSL_OBJECTS}

build/%.o: %.c build
	$(CC) -g -Wall -c $< -o $@ -I include
	
	
build/ssl/%.o: openssl/%.c build_ssl
	$(CC) -g -Wall -c $< -o $@ -I include

