// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/core/quic_fec_group.h"

#include <limits>

#include "base/logging.h"
#include "base/stl_util.h"

using namespace cat;


using base::ContainsKey;
using base::StringPiece;
using std::numeric_limits;
using std::set;


namespace net {

QuicFecGroup::QuicFecGroup(QuicPacketNumber fec_group_number) 
    : min_protected_packet_(fec_group_number),
      max_protected_packet_(fec_group_number + kDefaultMaxPacketsPerFecGroup - 1),
      payload_parity_len_(0),
	block_count_(kDefaultMaxPacketsPerFecGroup),
	recovery_block_count_(kDefaultRecoveryBlocksCount),
	
      effective_encryption_level_(NUM_ENCRYPTION_LEVELS) {}

QuicFecGroup::~QuicFecGroup() {}

// appends the length of the original packet to the beginning of the packet, so we can remove the padding when getting the fixed size packet at the reviving stage
StringPiece * appendLenToPayload(StringPiece payload, QuicPacketNumberLength packet_number_len)
{
	unsigned short payload_len = payload.size();
	
	DCHECK_LE(payload_len, 0xffff >> 2); // make sure 2 last bits are reserved
	unsigned short ext_payload_len = payload_len | (packet_number_len << 14);

	char * payload_with_len = new char[payload_len + 2];
	memcpy(payload_with_len, (char*)(&ext_payload_len), 2);
	memcpy(payload_with_len + 2, payload.as_string().c_str(), payload_len);

	return new StringPiece(payload_with_len, payload_len + 2);
}


// called each time fec protected packet is sent
bool QuicFecGroup::UpdateSentList(EncryptionLevel encryption_level,
	const QuicPacketHeader& header,
	StringPiece decrypted_payload) {
	DCHECK_EQ(min_protected_packet_, header.fec_group);
	DCHECK_NE(kInvalidPacketNumber, header.packet_number);
	
	// add the packet size to the beginning of the packet, and add it to the list
	ParityPacket * packet = new ParityPacket(header.packet_number, *appendLenToPayload(decrypted_payload, header.public_header.packet_number_length), header.public_header.packet_number_length);
	parity_sent_packets_.push_back(packet);
	DVLOG(1) << "Sending! Saving packet number " << header.packet_number;


	//received_packets_.insert(header.packet_number);
	//if (encryption_level < effective_encryption_level_) {
	//	effective_encryption_level_ = encryption_level;
	//}
	return true;
}


// called each time fec protected packet is received
bool QuicFecGroup::UpdateReceivedList(EncryptionLevel encryption_level,
                          const QuicPacketHeader& header,
                          StringPiece decrypted_payload,
							bool is_fec_data) {
  DCHECK_EQ(min_protected_packet_, header.fec_group);
  DCHECK_NE(kInvalidPacketNumber, header.packet_number);

  // the last fec protected packet before fec packet, will be the max_protected_packet
  // irrelevant, because we set max on ctor
  //if (!is_fec_data)
  //{
  //  max_protected_packet_ = header.packet_number;
  //}

  if (ContainsKey(received_packets_, header.packet_number)) {
    return false;
  }
  if (header.packet_number < min_protected_packet_){ //||
    //  (has_received_fec_packet() &&
    //   header.packet_number > max_protected_packet_)) {
    DLOG(ERROR) << "FEC group does not cover received packet: "
                << header.packet_number;
    return false;
  }

  StringPiece payloadToSave(decrypted_payload);
  if (!is_fec_data)
  {
	  payloadToSave = *appendLenToPayload(payloadToSave, header.public_header.packet_number_length);
  }
  ParityPacket * packet = new ParityPacket(header.packet_number, payloadToSave, header.public_header.packet_number_length);
  parity_received_packets_.push_back(packet);
  DVLOG(1) << "Received! Saving packet number " << header.packet_number;
  
  received_packets_.insert(header.packet_number);
  if (encryption_level < effective_encryption_level_) {
    effective_encryption_level_ = encryption_level;
  }
  return true;
}

// called when a fec packet is received
bool QuicFecGroup::UpdateFec(EncryptionLevel encryption_level,
                             const QuicPacketHeader& header,
                             StringPiece redundancy) {

	if (encryption_level < effective_encryption_level_) {
		effective_encryption_level_ = encryption_level;
	}

  return UpdateReceivedList(encryption_level, header, redundancy, true);
}

bool QuicFecGroup::CanRevive() const {
	// we can revive if we have at least kDefaultMaxPacketsPerFecGroup packets, include the fec packets.
		return received_packets_.size() >= kDefaultMaxPacketsPerFecGroup;
}

// used to compare parityPackets by their size. used with max_element function
bool compare_packets_size(const ParityPacket* a, const ParityPacket* b)
{
	return a->packet_data.size() < b->packet_data.size();
}

// return blocks[i].data if block[i].row == row_number
unsigned char * QuicFecGroup::getBlockData(unsigned int row_number, Block * blocks)
{
	for (size_t i = 0; i < block_count_; ++i)
	{
		if (blocks[i].row == row_number)
		{
			return blocks[i].data;
		}
	}
	return nullptr;
}

std::list<ParityPacket> QuicFecGroup::getRevivedPackets()
{
	std::list<ParityPacket> revived_packets;

	if (!CanRevive()) {
		return revived_packets;
	}
	
	// Identify the packet number to be resurrected.
	std::list<QuicPacketNumber> missing_packets_number;
	for (QuicPacketNumber i = min_protected_packet_; i <= max_protected_packet_;
		++i) {
		// check if this packet is missing
		if (received_packets_.count(i) == 0) {
			missing_packets_number.push_back(i);
			received_packets_.insert(i);
		}
	}

	// if no packet is missing
	if (missing_packets_number.empty())
	{ 
		return revived_packets;
	}
	
	Block *blocks = new Block[block_count_];

	std::list<ParityPacket *>::const_iterator it;
	size_t i = 0;

	auto max_packet = std::max_element(parity_received_packets_.begin(), parity_received_packets_.end(), compare_packets_size);
	size_t block_bytes = (*max_packet)->packet_data.size();

	// put the content of the source packets in the proper data structure for the longhair api
	for (it = parity_received_packets_.begin(), i = 0; it != parity_received_packets_.end() && i < block_count_; ++it, ++i) {

		blocks[i].data = new unsigned char[block_bytes];
		memset(blocks[i].data, 0, block_bytes);
		memcpy(blocks[i].data, (unsigned char*)(*it)->packet_data.c_str(), (*it)->packet_data.size()); 
		blocks[i].row = (*it)->packet_number - min_protected_packet_; 
	}
	
	// get the revived packets from the source packets
	assert(!cauchy_256_decode(block_count_, recovery_block_count_, blocks, block_bytes));

	// put the result in the revive packets list
	for (std::list<QuicPacketNumber>::iterator it = missing_packets_number.begin(); it != missing_packets_number.end(); ++it)
	{
		unsigned char * payload = getBlockData(*it - min_protected_packet_, blocks);
		if (nullptr == payload) {
			return revived_packets;
		}

		// extract len and packet number len from the first 2 bytes
		unsigned short len = *(unsigned short*)payload;
		unsigned short packet_number_len = len >> 14;
		len &= 0x3fff;
		revived_packets.push_back(ParityPacket(*it, StringPiece((char *)payload + 2, len).as_string(), (QuicPacketNumberLength)packet_number_len));
	}

	return revived_packets;

}


bool QuicFecGroup::IsWaitingForPacketBefore(QuicPacketNumber num) const {
  // Entire range is larger than the threshold.
  if (min_protected_packet_ >= num) {
    return false;
  }

  // Entire range is smaller than the threshold.
  if (received_packets_.size() > 0 ? *received_packets_.rbegin() + 1 < num
                                   : min_protected_packet_ < num) {
    return true;
  }

  // Range spans the threshold so look for a missing packet below the threshold.
  QuicPacketNumber target = min_protected_packet_;
  for (QuicPacketNumber packet : received_packets_) {
    if (target++ != packet) {
      return true;
    }
    if (target >= num) {
      return false;
    }
  }

  // No missing packets below the threshold.
  return false;
}


QuicPacketCount QuicFecGroup::NumMissingPackets() const {
 // if (!has_received_fec_packet()) {
 //   return numeric_limits<QuicPacketCount>::max();
 // }
  return static_cast<QuicPacketCount>(
      (max_protected_packet_ - min_protected_packet_ + 1) -
      received_packets_.size());
}

// create the redundant packets
const std::list<ParityPacket *> QuicFecGroup::getRedundancyPackets() {
	std::list<ParityPacket *> payloads;
	std::list<ParityPacket *>::const_iterator it;
	
	cauchy_256_init();

	// get the maximal packet size for making packets in a fixed size
	auto max_packet = std::max_element(parity_sent_packets_.begin(), parity_sent_packets_.end(), compare_packets_size);
	int max_payload_length = (*max_packet)->packet_data.size();
	
	int block_bytes = max_payload_length;
	if (block_bytes % 8)
	{
		block_bytes += 8 - max_payload_length % 8;  // a multiple of 8
	}

	block_count_ = parity_sent_packets_.size(); // k = kDefaultMaxPacketsPerFecGroup
	assert(kDefaultMaxPacketsPerFecGroup == block_count_); 

	u8 *data = new u8[block_bytes * block_count_];
	memset(data, 0, block_bytes * block_count_);
	u8 *recovery_blocks = new u8[block_bytes * recovery_block_count_];

	// pointers to real packets
	const u8 *data_ptrs[256];

	// put the content of the source packets in the proper data structure for the longhair api
	size_t i = 0;
	for (it = parity_sent_packets_.begin(),  i = 0; it != parity_sent_packets_.end() && i < block_count_; ++it,  ++i) {
		memcpy(data + i*block_bytes, (*it)->packet_data.c_str(), (*it)->packet_data.size());
		data_ptrs[i] = data + i * block_bytes;
	}

	// erasures_count = min(recovery_block_count_, block_count);
	erasure_count_ = recovery_block_count_;;
	if (block_count_ < erasure_count_)
	{
		erasure_count_ = block_count_;
	}

	// prepare the redundant packets 
	assert(!cauchy_256_encode(block_count_, recovery_block_count_, data_ptrs, recovery_blocks, block_bytes));

	// add the packets to the list returned
	// put the correct index at ecah packet
	for (size_t i = 0; i < recovery_block_count_; ++i)
	{
		size_t erasure_index = recovery_block_count_ - i - 1;
		payloads.push_back(new ParityPacket((QuicPacketNumber)(min_protected_packet_ + block_count_ + erasure_index), StringPiece((char*)(recovery_blocks + erasure_index * block_bytes), block_bytes), PACKET_1BYTE_PACKET_NUMBER)); // packet number len is not used
	}

	return payloads;
}

QuicPacketCount QuicFecGroup::NumReceivedPackets() const {
  return received_packets_.size();
}

QuicPacketCount QuicFecGroup::NumSentPackets() const {
	return parity_sent_packets_.size();
}

EncryptionLevel QuicFecGroup::EffectiveEncryptionLevel() const {
  return effective_encryption_level_;
}

QuicFecGroupNumber QuicFecGroup::FecGroupNumber() const {
  return min_protected_packet_;
}

}  // namespace net
