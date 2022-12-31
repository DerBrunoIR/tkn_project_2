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
#include "itoa.h"

// actual underlying hash table
htable **ht = NULL;
rtable **rt = NULL;

// chord peers
peer *self = NULL;
peer *pred = NULL;
peer *succ = NULL; // succ->socket should be handled as undefined


// ----------------
// Hilfsfunktionen
// ----------------

// convert packet into specific byte order
void packet_host_byte_order(packet* p) {
	p->hash_id = ntohs(p->hash_id);
	p->key_len = ntohs(p->key_len);
	p->value_len = ntohl(p->key_len);
	p->node_port = ntohs(p->node_port);
	p->node_ip = ntohl(p->node_ip);
}

void packet_network_byte_order(packet* p) {
	p->hash_id = htons(p->hash_id);
	p->key_len = htons(p->key_len);
	p->value_len = htonl(p->key_len);
	p->node_port = htons(p->node_port);
	p->node_ip = htonl(p->node_ip);
}

int send_packet(int socket, packet* pkt) {
	fprintf(stderr, "sending packet to socket %d\n", socket);
	if (socket < 1) {
		fprintf(stderr, "peer.c::send_packet::received closed socket!\n");
		return -1;
	}
	size_t pkt_buf_size = 0;
	unsigned char* pkt_buf = packet_serialize(pkt, &pkt_buf_size);
	int status = sendall(socket, pkt_buf, pkt_buf_size);
	free(pkt_buf);
	return status;
}

// -----------------
// Vorgabe
// -----------------

/**
 * @brief Forward a packet to a peer.
 *
 * @param peer The peer to forward the request to. The socket is created via peer->hostname
 * @param pack The packet to forward
 * @return int The status of the sending procedure
 */
int forward(peer *p, packet *pack) {
	fprintf(stderr, "forwarding packet to peer %s\n", p->hostname);
	/* DONE (Bruno) */
	peer_connect(p);
	send_packet(p->socket, pack); 
	peer_disconnect(p);
	return CB_OK;
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
	fprintf(stderr, "sending proxy request to %s\n", n->hostname);
	/* DONE (Bruno) */
	
	// do request and receive response
	peer_connect(n);
	send_packet(n->socket, p);
	
	size_t pkt_buf_size = 0;
	unsigned char* pkt_buf = recvall(n->socket, &pkt_buf_size);
	peer_disconnect(n);

	// proxy response 
	sendall(csocket, pkt_buf, pkt_buf_size);
	free(pkt_buf);
	
	return CB_OK;
}

/**
 * @brief Lookup the peer responsible for a hash_id.
 *
 * @param hash_id The hash to lookup
 * @return int The callback status
 */
int lookup_peer(uint16_t hash_id) {
	fprintf(stderr, "lookup peer responsible for %d\n", hash_id);
	/* DONE (Bruno) */
	// build lookup packet
	packet* pkt = packet_new();
	pkt->flags     = PKT_FLAG_CTRL | PKT_FLAG_LKUP;
	pkt->hash_id   = hash_id;
	pkt->node_id   = self->node_id;
	pkt->node_port = self->port;
	pkt->node_ip   = peer_get_ip(self);

	// send it to the Successor
	peer_connect(succ);
	send_packet(succ->socket, pkt);
	peer_disconnect(succ);

	packet_free(pkt);
	return CB_OK;
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
	fprintf(stderr, "handle own request");
	/* TOTEST (Bruno) */
	// build response packet 
	packet* pkt_snd = packet_new();
	pkt_snd->value_len = 0;
	pkt_snd->key_len = pkt_rcvd->key_len;
	pkt_snd->key = malloc(pkt_rcvd->key_len * sizeof(char));
	strncpy(pkt_snd->key, pkt_rcvd->key, pkt_rcvd->key_len);

	if (pkt_rcvd->flags & PKT_FLAG_GET) {
		pkt_snd->flags = PKT_FLAG_RPLY;
		htable* item = htable_get(ht, pkt_rcvd->key, pkt_rcvd->key_len);
		if (item) {
			pkt_snd->value = malloc(item->value_len * sizeof(char));
			strncpy(pkt_snd->value, item->value, item->value_len);
			pkt_snd->value_len = item->value_len;
		} 
	}
	else if (pkt_rcvd->flags & PKT_FLAG_SET) {
		htable_set(ht, pkt_rcvd->key, pkt_rcvd->key_len, pkt_rcvd->value, pkt_rcvd->value_len);
		pkt_snd->flags = PKT_FLAG_ACK;
	} 
	else if (pkt_rcvd->flags & PKT_FLAG_DEL) {
		htable_delete(ht, pkt_rcvd->key, pkt_rcvd->key_len);
		pkt_snd->flags = PKT_FLAG_ACK;
	}

	// send response 
	send_packet(c->socket, pkt_snd);

	packet_free(pkt_snd);
	return CB_OK;
}

/**
 * @brief Answer a lookup request from a peer.
 *
 * @param p The packet
 * @param n The peer
 * @return int The callback status
 */
int answer_lookup(packet *pkt_rcvd, peer *p) {
	fprintf(stderr, "answer lookup from peer %s\n", p->hostname);
	/* DONE (Bruno) */
	// build response packet
	peer* n = peer_from_packet(pkt_rcvd);
	packet* pkt_snd = packet_new();
	pkt_snd->flags     = PKT_FLAG_CTRL | PKT_FLAG_RPLY;
	pkt_snd->hash_id   = pkt_rcvd->hash_id;  // requested hash
	pkt_snd->node_id   = p->node_id; // node_id who can resolve the given hash
	pkt_snd->node_port = p->port;    // port
	pkt_snd->node_ip   = peer_get_ip(p);
	
	// send response to packet origin
	peer_connect(n);
	send_packet(n->socket, pkt_snd);
	peer_disconnect(n);

	packet_free(pkt_snd);
	return 0;
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
	fprintf(stderr, "DATA\n");
    // Hash the key of the <key, value> pair to use for the hash table
    uint16_t hash_id = pseudo_hash(p->key, p->key_len);
    fprintf(stderr, "Hash id: %d\n", hash_id);

    // Forward the packet to the correct peer
    if (peer_is_responsible(pred->node_id, self->node_id, hash_id)) {
        // We are responsible for this key
        fprintf(stderr, "This node can answer the request.\n");
        return handle_own_request(srv, c, p);
    } else if (peer_is_responsible(self->node_id, succ->node_id, hash_id)) {
        // Our successor is responsible for this key
        fprintf(stderr, "The successor can answer the request.\n");
        return proxy_request(srv, c->socket, p, succ);
    } else {
        // We need to find the peer responsible for this key
        fprintf(stderr, "Some other node can answer the request.\n");
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
	fprintf(stderr, "CTRL\n");
    if (p->flags & PKT_FLAG_LKUP) {
	fprintf(stderr, "LKUP for hash_id %d\n", p->hash_id);
        // we received a lookup request
        if (peer_is_responsible(pred->node_id, self->node_id, p->hash_id)) {
            // Our business
            fprintf(stderr, "This node is responsible (should not happen!).\n");
            return answer_lookup(p, self);
        } else if (peer_is_responsible(self->node_id, succ->node_id,
                                       p->hash_id)) {
            fprintf(stderr, "The successor is responsible.\n");
            return answer_lookup(p, succ);
        } else {
            // Great! Somebody else's job!
	    fprintf(stderr, "Some other node is responsible.\n");
            forward(succ, p);
        }
    } else if (p->flags & PKT_FLAG_RPLY) {
        // Look for open requests and proxy them
        peer *n = peer_from_packet(p);
	fprintf(stderr, "Received lookup answer from node %s:%d.\n", n->hostname, n->port);
        for (request *r = get_requests(rt, p->hash_id); r != NULL;
             r = r->next) {
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
	fprintf(stderr, "Received packet\n");
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

    fprintf(stderr, "My Hostname: %s:%d\n", self->hostname, self->port);
    fprintf(stderr, "My Hash Id: %d\n", self->node_id);
    srv->packet_cb = handle_packet;
    server_run(srv);
    close(srv->socket);
}
