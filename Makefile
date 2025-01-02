CPP = g++
CPPFLAGS = -g -Wall -Werror

SYSTEMC_INC = -I$(SYSTEMC_HOME)/include
SYSTEMC_LIB = -L$(SYSTEMC_HOME)/lib-linux64

SYSTEMC_LIBS = -lsystemc -lm

TARGET = aes_128

SRCS = src/test_AES.cpp src/AES_encryption.cpp 
OBJS = $(SRCS:.cpp=.o)

$(TARGET) : $(OBJS)
	$(CPP) $(CPPFLAGS) -I. $(SYSTEMC_INC) $(SYSTEMC_LIB) $(SYSTEMC_LIBS) $(OBJS) -o $(TARGET)

%.o : %.cpp
	$(CPP) $(CPPFLAGS) -I. $(SYSTEMC_INC) -c $< -o $@ 

run : $(TARGET)
	./$(TARGET) 

clean :
	rm -f $(TARGET) $(OBJS)
