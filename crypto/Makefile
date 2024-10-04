CC = gcc
CFLAGS = -Wall -Wextra -Werror -pedantic -std=gnu89
AR = ar rcs
TARGET = libhblk_crypto.a
SRC = $(wildcard *.c)
OBJ = $(SRC:.c=.o)

# Default target
all: $(TARGET)

# Rule to create the static library
$(TARGET): $(OBJ)
	$(AR) $@ $^

# Compile .c files to .o object files
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) $(TARGET)

rebuild: clean all

.PHONY: all clean rebuild
