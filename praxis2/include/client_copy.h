#ifndef CLIENT_H
#define CLIENT_H

#include "packet.h"
#include "util.h"

#include <netdb.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

// client copy is a copy of all functions except main of "src/client.c".

unsigned char *read_stdin(size_t *len);
int connect_socket(char *hostname, char *port);

#endif
