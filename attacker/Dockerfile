# Base image: Ubuntu latest version
FROM ubuntu:latest

# Install necessary tools like GCC and Make for compiling C code
RUN apt-get update && apt-get install -y gcc make

# Copy the C attack code from the host machine to the container
COPY . /attacker

# Set the working directory inside the container
WORKDIR /attacker

# Compile the C attack code (using the correct file name Attack.c)
RUN gcc -o attack Attack.c

# Command to run the attack once the container starts
CMD ["./attack"]
