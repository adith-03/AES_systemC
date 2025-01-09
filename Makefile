CPP = g++
CPPFLAGS = -g -Wall -Werror
GTK = gtkwave

SYSTEMC_INC = -I$(SYSTEMC_HOME)/include
SYSTEMC_LIB = -L$(SYSTEMC_HOME)/lib-linux64

SYSTEMC_LIBS = -lsystemc -lm

TARGET = aes_128
TRACE_FILE = aes_trace.vcd

SRCS = src/test_AES.cpp src/AES_encryption.cpp src/AES_decryption.cpp
OBJS = $(SRCS:.cpp=.o)

$(TARGET) : $(OBJS)
	$(CPP) $(CPPFLAGS) -I. $(SYSTEMC_INC) $(SYSTEMC_LIB) $(SYSTEMC_LIBS) $(OBJS) -o $(TARGET)

%.o : %.cpp
	$(CPP) $(CPPFLAGS) -I. $(SYSTEMC_INC) -c $< -o $@ 

run : $(TARGET)
	./$(TARGET) 

trace : $(TARGET)
	./$(TARGET)
	$(GTK) $(TRACE_FILE)

clean :
	rm -f $(TARGET) $(OBJS) $(TRACE_FILE)
