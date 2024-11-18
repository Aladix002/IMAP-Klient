CXX = g++
CXXFLAGS = -std=gnu++17 -Wall -Wextra

LIBS = -L/usr/lib -lcrypto -lssl

TARGET = imapcl

SRCS = imapcl.cc config_parser.cpp error_handling.cpp
HEADERS = imapcl.h config_parser.h error_handling.h

OBJS = $(SRCS:.cc=.o)

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(OBJS) $(LIBS)

%.o: %.cc $(HEADERS)
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f *.o $(TARGET) xbotlo01.tar

tar:
	tar -cf xbotlo01.tar Makefile $(SRCS) $(HEADERS) README manual.pdf
