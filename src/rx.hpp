// -*- C++ -*-
//
// Copyright (C) 2017, 2018 Vasily Evseenko <svpcom@p2ptech.org>

/*
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; version 3.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License along
 *   with this program; if not, write to the Free Software Foundation, Inc.,
 *   51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <unordered_map>

typedef enum {
    LOCAL,
    FORWARDER,
    AGGREGATOR
} rx_mode_t;

class BaseAggregator
{
public:
    virtual void process_packet(const uint8_t *buf, size_t size, uint8_t wlan_idx, const uint8_t *antenna, const int8_t *rssi, sockaddr_in *sockaddr) = 0;
    virtual void dump_stats(FILE *fp) = 0;
protected:
    int open_udp_socket_for_tx(const string &client_addr, int client_port)
    {
        struct sockaddr_in saddr;
        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0) throw runtime_error(string_format("Error opening socket: %s", strerror(errno)));

        bzero((char *) &saddr, sizeof(saddr));
        saddr.sin_family = AF_INET;
        saddr.sin_addr.s_addr = inet_addr(client_addr.c_str());
        saddr.sin_port = htons((unsigned short)client_port);

        if (connect(fd, (struct sockaddr *) &saddr, sizeof(saddr)) < 0)
        {
            throw runtime_error(string_format("Connect error: %s", strerror(errno)));
        }
        return fd;
    }
};


class Forwarder : public BaseAggregator
{
public:
    Forwarder(const string &client_addr, int client_port);
    ~Forwarder();
    virtual void process_packet(const uint8_t *buf, size_t size, uint8_t wlan_idx, const uint8_t *antenna, const int8_t *rssi, sockaddr_in *sockaddr);
    virtual void dump_stats(FILE *fp) {}
private:
    int sockfd;
};


typedef struct {
    uint64_t block_idx;
    uint8_t** fragments;
    uint8_t *fragment_map;
    uint8_t send_fragment_idx;
    uint8_t has_fragments;
} rx_ring_item_t;


#define RX_RING_SIZE 40

static inline int modN(int x, int base)
{
    return (base + (x % base)) % base;
}

class antennaItem
{
public:
    antennaItem(void) : count_all(0), rssi_sum(0), rssi_min(0), rssi_max(0) {}

    void log_rssi(int8_t rssi){
        if(count_all == 0){
            rssi_min = rssi;
            rssi_max = rssi;
        } else {
            rssi_min = min(rssi, rssi_min);
            rssi_max = max(rssi, rssi_max);
        }
        rssi_sum += rssi;
        count_all += 1;
    }

    int wlan_idx;
    int32_t count_all;
    int32_t rssi_sum;
    int8_t rssi_min;
    int8_t rssi_max;
};

typedef std::unordered_map<uint64_t, antennaItem> antenna_stat_t;

class Aggregator : public BaseAggregator
{
public:
    Aggregator(const string &client_addr, int client_port, int k, int n, const string &keypair);
    ~Aggregator();
    virtual void process_packet(const uint8_t *buf, size_t size, uint8_t wlan_idx, const uint8_t *antenna, const int8_t *rssi, sockaddr_in *sockaddr);
    virtual void dump_stats(FILE *fp);
private:
    void send_packet(int ring_idx, int fragment_idx);
    void apply_fec(int ring_idx);
    void log_rssi(const sockaddr_in *sockaddr, uint8_t wlan_idx, const uint8_t *ant, const int8_t *rssi);
    int get_block_ring_idx(uint64_t block_idx);
    int rx_ring_push(void);
    fec_t* fec_p;
    int fec_k;  // RS number of primary fragments in block
    int fec_n;  // RS total number of fragments in block
    int sockfd;
    uint32_t seq;
    rx_ring_item_t rx_ring[RX_RING_SIZE];
    int rx_ring_front; // current packet
    int rx_ring_alloc; // number of allocated entries
    uint64_t last_known_block;  //id of last known block

    // rx->tx keypair
    uint8_t rx_secretkey[crypto_box_SECRETKEYBYTES];
    uint8_t tx_publickey[crypto_box_PUBLICKEYBYTES];
    uint8_t session_key[crypto_aead_chacha20poly1305_KEYBYTES];

    antenna_stat_t antenna_stat;
    uint32_t count_p_all;
    uint32_t count_p_dec_err;
    uint32_t count_p_dec_ok;
    uint32_t count_p_fec_recovered;
    uint32_t count_p_lost;
    uint32_t count_p_bad;
};

class Receiver
{
public:
    Receiver(const char* wlan, int wlan_idx, int port, BaseAggregator* agg);
    ~Receiver();
    void loop_iter(void);
    int getfd(void){ return fd; }
private:
    int wlan_idx;
    BaseAggregator *agg;
    int fd;
    pcap_t *ppcap;
};

#define	MAX_PENUMBRA_INTERFACES 8

typedef struct {
	uint32_t received_packet_cnt;
	uint32_t wrong_crc_cnt;
	int8_t current_signal_dbm;
	int8_t type; // 0 = Atheros, 1 = Ralink
	int signal_good;
} wifi_adapter_rx_status_t;

typedef struct {
	time_t last_update;
	uint32_t received_block_cnt;
	uint32_t damaged_block_cnt;
	uint32_t lost_packet_cnt;
	uint32_t received_packet_cnt;
	uint32_t lost_per_block_cnt;
	uint32_t tx_restart_cnt;
	uint32_t kbitrate;
	uint32_t wifi_adapter_cnt;
	wifi_adapter_rx_status_t adapter[MAX_PENUMBRA_INTERFACES];
} wifibroadcast_rx_status_t;

bool video_rssi_enabled = false;


void status_memory_init(wifibroadcast_rx_status_t *s) {
	s->received_block_cnt = 0;
	s->damaged_block_cnt = 0;
	s->received_packet_cnt = 0;
	s->lost_packet_cnt = 0;
	s->tx_restart_cnt = 0;
	s->wifi_adapter_cnt = 0;
	s->kbitrate = 0;

	int i;
	for(i=0; i<MAX_PENUMBRA_INTERFACES; ++i) {
		s->adapter[i].received_packet_cnt = 0;
		s->adapter[i].wrong_crc_cnt = 0;
		s->adapter[i].current_signal_dbm = -126;
		s->adapter[i].type = 2; // set to 2 to see if it didnt get set later ...
	}
}


wifibroadcast_rx_status_t *status_memory_open(void) {
	char buf[128];
	int fd;
	
	sprintf(buf, "/wifibroadcast_rx_status_%d", 0);
///	fd = shm_open(buf, O_RDWR, S_IRUSR | S_IWUSR);
	fd = shm_open(buf, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);

	if(fd < 0) {
		perror("shm_open");
		exit(1);
	}

	if (ftruncate(fd, sizeof(wifibroadcast_rx_status_t)) == -1) {
		perror("ftruncate");
		exit(1);
	}

	void *retval = mmap(NULL, sizeof(wifibroadcast_rx_status_t), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (retval == MAP_FAILED) {
		perror("mmap");
		exit(1);
	}
	
	wifibroadcast_rx_status_t *tretval = (wifibroadcast_rx_status_t*)retval;
	status_memory_init(tretval);
	
	return tretval;
}

wifibroadcast_rx_status_t *rx_status = NULL;