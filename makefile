CC = gcc
CFLAGS = `libgcrypt-config --cflags` -Wall -g -std=gnu99
LIBS = `libgcrypt-config --libs`
OBJS = suncrypt sundec method.o suncrypt.o sundec.o

all: $(OBJS)
method.o: .c
	$(CC) -c -o method.o method.c $(CFLAGS) 

suncrypt.o: suncrypt.c
	$(CC) -c -o suncrypt.o suncrypt.c $(CFLAGS) 

suncrypt: suncrypt.o method.o
	$(CC) -o suncrypt suncrypt.o method.o $(CFLAGS) $(LIBS)
sundec.o: sundec.c
	$(CC) -c -o sundec.o sundec.c $(CFLAGS)
sundec: sundec.o method.o
	$(CC) -o sundec sundec.o method.o $(CFLAGS) $(LIBS)

clean:
	rm $(OBJS)
