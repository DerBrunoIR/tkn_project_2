#include "client_copy.h"

/**
 * @brief Read data from stdin.
 *
 * @param len Length of data to read
 */
unsigned char *read_stdin(size_t *len) {
    size_t buf_size = 1024;
    unsigned char *buffer = (unsigned char *)malloc(buf_size);
    unsigned char *write_ptr = buffer;
    while (true) {

        // Double buffer if we run out of space
        // Conserve write position (may change after realloc)
        if ((buffer + buf_size - write_ptr) < 1) {
            size_t pos = write_ptr - buffer;

            buf_size = buf_size * 2;
            buffer = realloc(buffer, buf_size);

            write_ptr = buffer + pos;
        }

        size_t bytes =
            fread(write_ptr, 1, buffer + buf_size - write_ptr, stdin);

        if (bytes < 1) {
            break;
        }

        write_ptr += bytes;
    }

    *len = write_ptr - buffer;
    return buffer;
}

/**
 * @brief Connect to a peer of the chord ring.
 *
 * @param host Hostname of peer
 * @param port Port of peer
 */
int connect_socket(char *hostname, char *port) {
    struct addrinfo *res;
    struct addrinfo hints;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    int status = getaddrinfo(hostname, port, &hints, &res);
    if (status != 0) {
        perror("getaddrinfo:");
        return -1;
    }

    struct addrinfo *p;
    int sock = -1;
    bool connected = false;

    char ipstr[INET6_ADDRSTRLEN];

    for (p = res; p != NULL; p = p->ai_next) {
        sock = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sock < 0) {
            continue;
        }

        get_ip_str(p->ai_addr, ipstr, INET6_ADDRSTRLEN);
        fprintf(stderr, "Attempting connection to %s\n", ipstr);

        status = connect(sock, p->ai_addr, p->ai_addrlen);
        if (status < 0) {
            perror("connect");
            close(sock);
            continue;
        }
        connected = true;
        break;
    }
    freeaddrinfo(res);

    if (!connected) {
        return -1;
    }

    fprintf(stderr, "Connected to %s.\n", ipstr);

    return sock;
}

