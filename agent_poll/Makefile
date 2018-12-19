CXX = g++
#CP = cp
CXXFLAGS = -L. -Iinclude -lpthread -lm
#-lcrypto -lssl -lxml2 -lm
TARGET = agent_main
OBJS = main.o req_conn.o agent_main.o cryptdatafunc.o 
CFLAGS = -g -c
STATICLIB = libssl.a libcrypto.a libxml2.a
#LKFLAGS =
#INSTALLDIR = /mnt/
#install:
#	$(CP) $(TARGET) $(INSTALLDIR)

all:$(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $^ -o $@ $(CXXFLAGS) $(STATICLIB)

main.o: main.cpp agent_main.cpp
	$(CXX) $(CFLAGS) $^ $(STATICLIB)
req_conn.o: req_conn.cpp cryptdatafunc.cpp
	$(CXX) $(CFLAGS) $^ $(STATICLIB)
agent_main.o: agent_main.cpp req_conn.cpp  
	$(CXX) $(CFLAGS) $^ $(STATICLIB)
cryptdatafunc.o: cryptdatafunc.cpp
	$(CXX) $(CFLAGS) $^ $(STATICLIB)
clean:
	@echo "cleaning project"
	-rm main*.o agent_main*.o thread_pool*.o req_conn*.o cryptdatafunc*.o
	@echo "clean completed"
.PHONY: clean
