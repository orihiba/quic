#include <iostream>

enum config_flags
{
	FLAGS_NONE = 0,
	FLAGS_FIFO = 0x00000001,
	FLAGS_LOSSLESS = 0x00000002,
};

#define PRINT_FIELD(X) << #X ":\t" << X << std::endl

typedef struct connection_status_
{
	uint64_t packets_sent;
	uint64_t bytes_sent;
	uint64_t packets_received;
	uint64_t bytes_received;
	uint64_t packets_revived;
	uint64_t packet_lost;
	uint64_t min_rtt; // in microseconds
	uint64_t smoothed_rtt; // in microseconds
	//net::QuicTime connection_creation_time;
	uint32_t sending_fec_configuration;
	uint32_t receiving_fec_configuration;
	float loss_rate;

	void print() {
		std::cout << "Connection status:" << std::endl
			PRINT_FIELD(packets_sent)
			PRINT_FIELD(bytes_sent)
			PRINT_FIELD(packets_received)
			PRINT_FIELD(bytes_received)
			PRINT_FIELD(packets_revived)
			PRINT_FIELD(packet_lost)
			PRINT_FIELD(min_rtt)
			PRINT_FIELD(smoothed_rtt)
			//<< "connection_creation_time:\t" << net::QuicTime::Delta::FromMicroseconds(connection_creation_time.ToDebuggingValue()) << std::endl
			PRINT_FIELD(sending_fec_configuration)
			PRINT_FIELD(receiving_fec_configuration)
			PRINT_FIELD(loss_rate);
	}

} connection_status;