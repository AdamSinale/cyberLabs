# Define variables for the compiler, flags, and output files
CC = gcc
CFLAGS = -Wall -g
TARGET1 = attack
TARGET2 = monitor
OBJ1 = Attack.o
OBJ2 = monitor.o

# The 'all' target builds both programs
all: $(TARGET1) $(TARGET2)

# Rule for the first target (attack program)
$(TARGET1): $(OBJ1)
	$(CC) $(CFLAGS) -o $(TARGET1) $(OBJ1)

# Rule for the second target (monitor program)
$(TARGET2): $(OBJ2)
	$(CC) $(CFLAGS) -o $(TARGET2) $(OBJ2)

# Rule for building the object files
%.o: %.c
	$(CC) $(CFLAGS) -c $<

# Clean rule to remove built files
clean:
	rm -f $(OBJ1) $(OBJ2) $(TARGET1) $(TARGET2)

# PHONY to avoid file conflicts with clean and all
.PHONY: clean all
