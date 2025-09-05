all: fixxss

fixxss: fixxss.c mongoose.c mongoose.h
	$(CC) -g -o $@ $^

clean:
	rm -f fixxss
