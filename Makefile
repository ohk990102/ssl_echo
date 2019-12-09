CXXFLAGS = -L/usr/lib
LDLIBS = -lpthread -lssl -lcrypto

all: ssl_echo_server ssl_echo_client

debug: CXXFLAGS += -DDEBUG -g
debug: ssl_echo_server ssl_echo_client

ssl_echo_server: ssl_echo_server.cpp
	$(CXX) -o $@ $^ $(CXXFLAGS)	$(LDLIBS)

ssl_echo_client: ssl_echo_client.cpp
	$(CXX) -o $@ $^ $(CXXFLAGS)	$(LDLIBS)

clean:
	rm -rf ssl_echo_server ssl_echo_client

.PHONY: all clean