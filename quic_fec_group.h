// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// Tracks information about an FEC group, including the packets
// that have been seen, and the running parity.  Provides the ability
// to revive a dropped packet.

#ifndef NET_QUIC_QUIC_FEC_GROUP_H_
#define NET_QUIC_QUIC_FEC_GROUP_H_

#include <cstddef>

#include "base/macros.h"
#include "base/strings/string_piece.h"
#include "net/quic/core/quic_protocol.h"
#include "net/quic/core/libcat/cauchy_256.h"
#include "net/quic/core/libcat/AbyssinianPRNG.hpp"

namespace net {

using base::StringPiece;
class NET_EXPORT_PRIVATE ParityPacket
{
public:
	QuicPacketNumber packet_number;
	std::string packet_data;
	QuicPacketNumberLength packet_number_len;
	ParityPacket(QuicPacketNumber packet_number_, StringPiece packet_data_, QuicPacketNumberLength packet_number_len_) : packet_number(packet_number_), packet_data(packet_data_.as_string()), packet_number_len(packet_number_len_) { } // error!! should copythe string
};

class NET_EXPORT_PRIVATE QuicFecGroup {


 public:
  explicit QuicFecGroup(QuicPacketNumber fec_group_number);
  virtual ~QuicFecGroup();

  bool UpdateReceivedList(EncryptionLevel encryption_level,
              const QuicPacketHeader& header,
              base::StringPiece decrypted_payload, 
			bool is_fec_data) ;
  bool UpdateSentList(EncryptionLevel encryption_level,
	  const QuicPacketHeader& header,
	  base::StringPiece decrypted_payload);
  bool UpdateFec(EncryptionLevel encryption_level,
                 const QuicPacketHeader& header,
                 base::StringPiece redundancy) ;
  bool CanRevive() const ;
  bool IsFinished() const ;
  // revives all lost packets and returns them
  std::list<ParityPacket> getRevivedPackets();
  size_t Revive(QuicPacketHeader* header,
                char* decrypted_payload,
                size_t decrypted_payload_len) ;
  bool IsWaitingForPacketBefore(QuicPacketNumber num) const ;
  const std::list<ParityPacket *> PayloadParity(QuicByteCount max_payload_length) const ;
  QuicPacketCount NumReceivedPackets() const ;
  QuicPacketCount NumSentPackets() const;
  EncryptionLevel EffectiveEncryptionLevel() const ;
  QuicFecGroupNumber FecGroupNumber() const ;
  const std::list<ParityPacket *> getRedundancyPackets();

 private:

  // Returns the number of missing packets, or QuicPacketCount max
  // if the number of missing packets is not known.
  QuicPacketCount NumMissingPackets() const;

  unsigned char * getBlockData(unsigned int row_number, Block * blocks);

  std::list<ParityPacket *> parity_received_packets_;
  std::list<ParityPacket *> parity_sent_packets_;

  // Set of packets that we have recevied.
  PacketNumberSet received_packets_;
  // packet number of the first protected packet in this group (the one
  // with the lowest packet number).  Will only be set once the FEC
  // packet has been seen.
  const QuicPacketNumber min_protected_packet_;
  // packet number of the last protected packet in this group (the one
  // with the highest packet number).  Will only be set once the FEC
  // packet has been seen.
  QuicPacketNumber max_protected_packet_;
  // The cumulative parity calculation of all received packets.
  char payload_parity_[kMaxPacketSize];
  size_t payload_parity_len_;

  size_t block_count_; // k
  size_t recovery_block_count_; // m
  size_t block_bytes_; // a multiple of 8
  size_t erasure_count_; // revived packets number

  // The effective encryption level, which is the lowest encryption level of
  // the data and FEC in the group.
  EncryptionLevel effective_encryption_level_;

  DISALLOW_COPY_AND_ASSIGN(QuicFecGroup);
};

}  // namespace net

#endif  // NET_QUIC_QUIC_FEC_GROUP_H_
