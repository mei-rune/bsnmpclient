# TODO: read values from CMakeLists.txt somehow instead of hard coding them here

OBJECTS=build/bsnmpimport.o   \
        build/bsnmpmap.o      \
        build/bsnmptc.o       \
        build/bsnmptools.o    \
        build/getopt.o        \
        build/getopt1.o       \
        build/util.o       \
        build/main.o       



all: snmpclient build/bsnmptools.exe

snmpclient:
	cd libsnmpclient && $(MAKE) all && cd ..
   
clean: 
	rm -fr build
	rm -fr libsnmpclient/build

build:
	mkdir -p build
build_ssl: build
	mkdir -p build/ssl

build/bsnmptools.exe: ${OBJECTS} 
	$(CC) -g -Wall -o build/bsnmptools.exe ${OBJECTS} ./libsnmpclient/build/libsnmpclient.a -lWs2_32  -lwsock32

build/%.o: src/%.c build
	$(CC) -g -Wall -c $< -o $@ -I ./libsnmpclient/include
	


