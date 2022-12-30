#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "hash_table.h"
#include "neighbour.h"
#include "packet.h"
#include "requests.h"
#include "server.h"
#include "util.h"

// my includes
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "client_copy.h"
#include "itoa.h"

// actual underlying hash table
htable **ht = NULL;
rtable **rt = NULL;

// chord peers
peer *self = NULL;
peer *pred = NULL;
peer *succ = NULL; // succ->socket should be handled as undefined


/**
 * convert the string representation of an ipv4 address to uint32 in network byte order
 **/
uint32_t ipv4str_to_net_uint32(char* hostanme) {
	struct in_addr addr = {0};
	if (inet_aton(self->hostname, &addr) == 0) {
		return 0;
	}
	return htonl(addr.s_addr);
}


/**
 * @brief Forward a packet to a peer.
 *
 * @param peer The peer to forward the request to. The socket is created via peer->hostname
 * @param pack The packet to forward
 * @return int The status of the sending procedure
 */
int forward(peer *p, packet *pack) {
	/* DONE (Bruno) */
	
	int socket = p->socket;
	char* port_str;
	itoa(&port_str, p->port);
	socket = connect_socket(p->hostname, port_str);
	free(port_str);
	if (socket < 1) {
		fprintf(stderr, "peer::Forward::Could not connect socket to %s:%d!",p->hostname, p->port);
		return CB_REMOVE_CLIENT;
	}

	int status = CB_REMOVE_CLIENT;
	size_t pkt_buf_size = 0;
	unsigned char* pkt_buf = packet_serialize(pack, &pkt_buf_size);
	fprintf(stderr, "Forward packet to %s: \"%s\"\n", p->hostname, pkt_buf);
	if (pkt_buf_size > 0) {
		status = sendall(socket, pkt_buf, pkt_buf_size);
	}
	else {
		fprintf(stderr, "peer::Forward::pkt_buf_size <= 0");
	}

	free(pkt_buf);
	close(socket);
	return status;
}

/**
 * @brief Forward a request to the successor.
 *
 * @param srv The server
 * @param csocket The socket of the client
 * @param p The packet to forward
 * @param n The peer to forward to
 * @return int The callback status
 */
int proxy_request(server *srv, int csocket, packet *p, peer *n) {
	/* DONE (Bruno) */
	unsigned char* pkt_buf;
	size_t pkt_buf_size;
	char* port_str;
	int status = 0;

	if (csocket < 1) {
		fprintf(stderr, "peer::proxy_request::client socket is closed!\n");
		return CB_REMOVE_CLIENT;
	}

	// proxy request 
	itoa(&port_str, n->port);
	int socket_proxy = connect_socket(n->hostname, port_str);
	free(port_str);
	if (socket_proxy < 1) {
		fprintf(stderr, "peer::Forward::Could not connect socket to %s:%d!",n->hostname, n->port);
		return CB_REMOVE_CLIENT;
	}

	pkt_buf_size = 0;
	pkt_buf = packet_serialize(p, &pkt_buf_size);
	if (pkt_buf_size == 0) {
		fprintf(stderr, "peer::proxy_request::Serialized packet has length 0!\n");
		free(pkt_buf);
		return CB_REMOVE_CLIENT;
	}
	
	status = sendall(socket_proxy, pkt_buf, pkt_buf_size); 
	free(pkt_buf);
	if (status < 0) {
		fprintf(stderr, "peer::proxy_request::Could not send packet to client!\n");
		return CB_REMOVE_CLIENT;
	}

	// receive response 
	pkt_buf = recvall(socket_proxy, &pkt_buf_size);
	close(socket_proxy);
	if (pkt_buf == NULL) {
		fprintf(stderr, "peer::proxy_request::Didn't received response from %s:%d!\n", n->hostname, n->port);
		return CB_REMOVE_CLIENT;
	}

	// send proxied response to client 
	status = sendall(csocket, pkt_buf, pkt_buf_size); 
	free(pkt_buf);
	if (status < 0) {
		fprintf(stderr, "peer::proxy_request::Could not send packet to client!");
		return CB_REMOVE_CLIENT;
	}
	
	return status;
}

/**
 * @brief Lookup the peer responsible for a hash_id.
 *
 * @param hash_id The hash to lookup
 * @return int The callback status
 */
int lookup_peer(uint16_t hash_id) {
	/* DONE (Bruno) */
	// build lookup packet
	packet* pkt = packet_new();
	pkt->flags     = PKT_FLAG_CTRL | PKT_FLAG_LKUP;
	pkt->hash_id   = htons(hash_id);
	pkt->node_id   = htons(self->node_id);
	pkt->node_port = htons(self->port);
	pkt->node_ip   = ipv4str_to_net_uint32(self->hostname);
	if (pkt->node_ip == 0) {
		packet_free(pkt);
		return CB_REMOVE_CLIENT;
	}
	// send it to the successor
	int status = forward(succ, pkt);

	packet_free(pkt);
	return status;
}


/**
 * @brief Handle a client request we are resonspible for.
 *
 * @param srv The server
 * @param c The client
 * @param p The (data) packet
 * @return int The callback status
 */
int handle_own_request(server *srv, client *c, packet *pkt_rcvd) {
	/* TOTEST (Bruno) */
	if (pkt_rcvd->key_len == 0) {
		fprintf(stderr, "peer::handle_own_request::Received empty request!\n");
		return CB_REMOVE_CLIENT;
	}

	// build response packet 
	packet* pkt_snd = packet_new();
	pkt_snd->key_len = pkt_rcvd->key_len;
	pkt_snd->key = malloc(ntohs(pkt_rcvd->key_len)*sizeof(char));
	strncpy((char*) pkt_snd->key, (const char*) pkt_rcvd->key, ntohs(pkt_rcvd->key_len));

	if (pkt_rcvd->flags & PKT_FLAG_GET) {
		fprintf(stderr, "Handling a get request\n");
		htable* item = htable_get(ht, pkt_rcvd->key, pkt_rcvd->key_len);
		pkt_snd->flags = PKT_FLAG_RPLY;
		if (item) {
			pkt_snd->value = malloc(ntohs(pkt_rcvd->value_len)*sizeof(char));
			strncpy((char*) pkt_snd->value, (const char*) item->value, ntohs(item->value_len));
			pkt_snd->value_len = item->value_len;
		} else {
			pkt_snd->value_len = 0;
		}
	}
	else if (pkt_rcvd->flags & PKT_FLAG_SET) {
		fprintf(stderr, "Handling a set request\n");
		htable_set(ht, pkt_rcvd->key, pkt_rcvd->key_len, pkt_rcvd->value, pkt_rcvd->value_len);
		pkt_snd->flags = PKT_FLAG_ACK;
	} 
	else if (pkt_rcvd->flags & PKT_FLAG_DEL) {
		fprintf(stderr, "Handling a del request\n");
		htable_delete(ht, pkt_rcvd->key, pkt_rcvd->key_len);
		pkt_snd->flags = PKT_FLAG_ACK;
	}

	// send response 
	int status;
	size_t pkt_buffer_length = 0;

	unsigned char* pkt_buffer = packet_serialize(pkt_snd, &pkt_buffer_length);
	packet_free(pkt_snd);
	if (pkt_buffer_length == 0) {
		free(pkt_buffer);
	}

	fprintf(stderr, "Answer with packet: \"%s\"\n", pkt_buffer);
	status = sendall(c->socket, pkt_buffer, pkt_buffer_length);
	free(pkt_buffer);
	if (status < 0) {
		fprintf(stderr, "peer::handle_own_request::Failed to send packet to socket %d\n", c->socket);
		return CB_REMOVE_CLIENT;
	}
	return CB_OK;
}

/**
 * @brief Answer a lookup request from a peer.
 *
 * @param p The packet
 * @param n The peer
 * @return int The callback status
 */
int answer_lookup(packet *pkt_rcvd, peer *peer_from) {
	/* DONE (Bruno) */

	// build response packet
	packet* pkt_snd = packet_new();
	pkt_snd->flags     = PKT_FLAG_CTRL | PKT_FLAG_RPLY;
	pkt_snd->hash_id   = pkt_rcvd->hash_id;  // requested hash
	pkt_snd->node_id   = peer_from->node_id; // node_id who can resolve the given hash
	pkt_snd->node_port = peer_from->port;    // port
	pkt_snd->node_ip   = ipv4str_to_net_uint32(peer_from->hostname);
	if (pkt_snd->node_ip == 0) { 
		packet_free(pkt_snd);
		return CB_REMOVE_CLIENT;
	}
	
	// send response to packet origin
	peer peer_to = {0};
	peer_to.port = pkt_snd->node_port;
	peer_to.hostname = inet_ntoa(*(struct in_addr*) &pkt_rcvd->node_ip); // die Sterne sind wichtig
	int status = forward(&peer_to, pkt_snd);

	packet_free(pkt_snd);
	return status;
}

/**
 * @brief Handle a key request request from a client.
 *
 * @param srv The server
 * @param c The client
 * @param p The packet
 * @return int The callback status
 */
int handle_packet_data(server *srv, client *c, packet *p) {
    // Hash the key of the <key, value> pair to use for the hash table
    uint16_t hash_id = pseudo_hash(p->key, p->key_len);
    fprintf(stderr, "Hash id: %d\n", hash_id);
    fprintf(stderr, "Key: %s\n", p->key);

    // Forward the packet to the correct peer
    if (peer_is_responsible(pred->node_id, self->node_id, hash_id)) {
        // We are responsible for this key
        fprintf(stderr, "We are responsible.\n");
        return handle_own_request(srv, c, p);
    } else if (peer_is_responsible(self->node_id, succ->node_id, hash_id)) {
        // Our successor is responsible for this key
        fprintf(stderr, "Successor's business.\n");
        return proxy_request(srv, c->socket, p, succ);
    } else {
        // We need to find the peer responsible for this key
        fprintf(stderr, "No idea! Just looking it up!.\n");
        add_request(rt, hash_id, c->socket, p);
        lookup_peer(hash_id); // TODO Add this to open lookup requests
        return CB_OK;
    }
}

/**
 * @brief Handle a control packet from another peer.
 * Lookup vs. Proxy Reply
 *
 * @param srv The server
 * @param c The client
 * @param p The packet
 * @return int The callback status
 */
int handle_packet_ctrl(server *srv, client *c, packet *p) {

    fprintf(stderr, "Handling control packet...\n");

    if (p->flags & PKT_FLAG_LKUP) {
        // we received a lookup request
        if (peer_is_responsible(pred->node_id, self->node_id, p->hash_id)) {
            // Our business
            fprintf(stderr, "Lol! This should not happen!\n");
            return answer_lookup(p, self);
        } else if (peer_is_responsible(self->node_id, succ->node_id,
                                       p->hash_id)) {
            return answer_lookup(p, succ);
        } else {
            // Great! Somebody else's job!
	    fprintf(stderr, "Forwarding to successor: %s\n", succ->hostname);
            forward(succ, p);
        }
    } else if (p->flags & PKT_FLAG_RPLY) {
        // Look for open requests and proxy them
        peer *n = peer_from_packet(p);
	fprintf(stderr, "Received response from node %s\n", n->hostname);
        for (request *r = get_requests(rt, p->hash_id); r != NULL;
             r = r->next) {
	    fprintf(stderr, "Let's proxy it into socket %d\n", r->socket);
            proxy_request(srv, r->socket, r->packet, n);
            server_close_socket(srv, r->socket);
        }
        clear_requests(rt, p->hash_id);
    } else {
    }
    return CB_REMOVE_CLIENT;
}

/**
 * @brief Handle a received packet.
 * This can be a key request received from a client or a control packet from
 * another peer.
 *
 * @param srv The server instance
 * @param c The client instance
 * @param p The packet instance
 * @return int The callback status
 */
int handle_packet(server *srv, client *c, packet *p) {
    if (p->flags & PKT_FLAG_CTRL) {
        return handle_packet_ctrl(srv, c, p);
    } else {
        return handle_packet_data(srv, c, p);
    }
}

/**
 * @brief Main entry for a peer of the chord ring.
 *
 * Requires 9 arguments:
 * 1. Id
 * 2. Hostname
 * 3. Port
 * 4. Id of the predecessor
 * 5. Hostname of the predecessor
 * 6. Port of the predecessor
 * 7. Id of the successor
 * 8. Hostname of the successor
 * 9. Port of the successor
 *
 * @param argc The number of arguments
 * @param argv The arguments
 * @return int The exit code
 */
int main(int argc, char **argv) {

    if (argc < 10) {
        fprintf(stderr, "Not enough args! I need ID IP PORT ID_P IP_P PORT_P "
                        "ID_S IP_S PORT_S\n");
    }

    // Read arguments for self
    uint16_t idSelf = strtoul(argv[1], NULL, 10);
    char *hostSelf = argv[2];
    char *portSelf = argv[3];

    // Read arguments for predecessor
    uint16_t idPred = strtoul(argv[4], NULL, 10);
    char *hostPred = argv[5];
    char *portPred = argv[6];

    // Read arguments for successor
    uint16_t idSucc = strtoul(argv[7], NULL, 10);
    char *hostSucc = argv[8];
    char *portSucc = argv[9];

    // Initialize all chord peers
    self = peer_init(
        idSelf, hostSelf,
        portSelf); //  Not really necessary but convenient to store us as a peer
    pred = peer_init(idPred, hostPred, portPred); //

    succ = peer_init(idSucc, hostSucc, portSucc);

    // Initialize outer server for communication with clients
    server *srv = server_setup(portSelf);
    if (srv == NULL) {
        fprintf(stderr, "Server setup failed!\n");
        return -1;
    }
    // Initialize hash table
    ht = (htable **)malloc(sizeof(htable *));
    // Initiale reuqest table
    rt = (rtable **)malloc(sizeof(rtable *));
    *ht = NULL;
    *rt = NULL;

    srv->packet_cb = handle_packet;
    server_run(srv);
    close(srv->socket);
}
