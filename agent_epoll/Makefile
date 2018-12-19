CXX = g++
#CP = cp
CXXFLAGS = -I/usr/local/include/openssl -lpthread -lcrypto -lssl -lxml2 -lm
TARGET = agent_main
OBJS = main.o threadpool.o req_conn.o cryptdatafunc.o 
CFLAGS = -g -c
#LKFLAGS =
#INSTALLDIR = /mnt/
#install:
#	$(CP) $(TARGET) $(INSTALLDIR)

all:$(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $^ -o $@ $(CXXFLAGS)

main.o: main.cpp threadpool.cpp req_conn.cpp
	$(CXX) $(CFLAGS) $^
threadpool.o: threadpool.cpp req_conn.cpp cryptdatafunc.cpp
	$(CXX) $(CFLAGS) $^
req_conn.o: req_conn.cpp threadpool.cpp
	$(CXX) $(CFLAGS) $^
cryptdatafunc.o: cryptdatafunc.cpp
	$(CXX) $(CFLAGS) $^
clean:
	@echo "cleaning project"
	-rm main*.o threadpool*.o req_conn*.o cryptdatafunc*.o 
	@echo "clean completed"
.PHONY: clean
