// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/core/quic_packet_creator.h"

#include <algorithm>

#include "base/logging.h"
#include "base/macros.h"
#include "net/quic/core/crypto/crypto_protocol.h"
#include "net/quic/core/crypto/quic_random.h"
#include "net/quic/core/quic_bug_tracker.h"
#include "net/quic/core/quic_data_writer.h"
#include "net/quic/core/quic_flags.h"
#include "net/quic/core/quic_utils.h"

using base::StringPiece;
using std::make_pair;
using std::max;
using std::min;
using std::pair;
using std::string;
using std::vector;

// If true, enforce that QUIC CHLOs fit in one packet.
//bool FLAGS_quic_enforce_single_packet_chlo = true;
bool FLAGS_quic_enforce_single_packet_chlo = false; // HIBA

namespace net {


QuicPacketCreator::QuicPacketCreator(QuicConnectionId connection_id,
                                     QuicFramer* framer,
                                     QuicRandom* random_generator,
                                     QuicBufferAllocator* buffer_allocator,
                                     DelegateInterface* delegate)
    : delegate_(delegate),
      debug_delegate_(nullptr),
      framer_(framer),
      random_bool_source_(random_generator),
      buffer_allocator_(buffer_allocator),
      send_version_in_packet_(framer->perspective() == Perspective::IS_CLIENT),
      send_path_id_in_packet_(false),
      next_packet_number_length_(PACKET_1BYTE_PACKET_NUMBER),
      have_diversification_nonce_(false),
      max_packet_length_(0),
      connection_id_length_(PACKET_8BYTE_CONNECTION_ID),
      packet_size_(0),
      connection_id_(connection_id),
	packet_(kDefaultPathId,
		0,
		PACKET_1BYTE_PACKET_NUMBER,
		nullptr,
		0,
		0,
		false,
		false,
		false),
	  should_fec_protect_next_packet_(false),
	  fec_protect_(true),
	  max_packets_per_fec_group_(kDefaultMaxPacketsPerFecGroup),
     
	fec_timeout_(QuicTime::Delta::Zero())
{
  SetMaxPacketLength(kDefaultMaxPacketSize);

}

QuicPacketCreator::~QuicPacketCreator() {
  QuicUtils::DeleteFrames(&packet_.retransmittable_frames);
}

void QuicPacketCreator::OnBuiltFecProtectedPayload(
	const QuicPacketHeader& header,
	StringPiece payload) {
	if (fec_group_.get() != nullptr) {
		DCHECK_NE(0u, header.fec_group);
		fec_group_->UpdateSentList(packet_.encryption_level, header, payload);
	}
}

void QuicPacketCreator::SetEncrypter(EncryptionLevel level,
                                     QuicEncrypter* encrypter) {
  framer_->SetEncrypter(level, encrypter);
  max_plaintext_size_ = framer_->GetMaxPlaintextSize(max_packet_length_);
}

bool QuicPacketCreator::CanSetMaxPacketLength() const {
  // |max_packet_length_| should not be changed mid-packet.
  return queued_frames_.empty();
}

void QuicPacketCreator::SetMaxPacketLength(QuicByteCount length) {
  DCHECK(CanSetMaxPacketLength());

  // Avoid recomputing |max_plaintext_size_| if the length does not actually
  // change.
  if (length == max_packet_length_) {
    return;
  }

  max_packet_length_ = length;
  max_plaintext_size_ = framer_->GetMaxPlaintextSize(max_packet_length_);
}
void QuicPacketCreator::set_max_packets_per_fec_group(
	size_t max_packets_per_fec_group) {
	max_packets_per_fec_group_ = max(kLowestMaxPacketsPerFecGroup,
		max_packets_per_fec_group);
	DCHECK_LT(0u, max_packets_per_fec_group_);
}

bool QuicPacketCreator::ShouldSendFec(bool force_close) const {
	DCHECK(!HasPendingFrames());
	return fec_group_.get() != nullptr && fec_group_->NumSentPackets() > 0 &&
		(force_close ||
	//	fec_group_->NumSentPackets() >= max_packets_per_fec_group_);
		fec_group_->NumSentPackets() >= kDefaultMaxPacketsPerFecGroup);
}

void QuicPacketCreator::ResetFecGroup() {
	if (HasPendingFrames()) {
		LOG_IF(DFATAL, packet_size_ != 0)
			<< "Cannot reset FEC group with pending frames.";
		return;
	}
	fec_group_.reset(nullptr);
}

bool QuicPacketCreator::IsFecGroupOpen() const {
	return fec_group_.get() != nullptr;
}

void QuicPacketCreator::StartFecProtectingPackets() {
	if (!IsFecEnabled()) {
		LOG(DFATAL) << "Cannot start FEC protection when FEC is not enabled.";
		return;
	}
	// TODO(jri): This currently requires that the generator flush out any
	// pending frames when FEC protection is turned on. If current packet can be
	// converted to an FEC protected packet, do it. This will require the
	// generator to check if the resulting expansion still allows the incoming
	// frame to be added to the packet.
	if (HasPendingFrames()) {
		LOG(DFATAL) << "Cannot start FEC protection with pending frames.";
		return;
	}
	DCHECK(!fec_protect_);
	fec_protect_ = true;
}

void QuicPacketCreator::StopFecProtectingPackets() {
	if (fec_group_.get() != nullptr) {
		LOG(DFATAL) << "Cannot stop FEC protection with open FEC group.";
		return;
	}
	DCHECK(fec_protect_);
	fec_protect_ = false;
}

bool QuicPacketCreator::IsFecProtected() const {
	return fec_protect_;
}

bool QuicPacketCreator::IsFecEnabled() const {
	return max_packets_per_fec_group_ > 0;
}

InFecGroup QuicPacketCreator::MaybeUpdateLengthsAndStartFec() {
	if (fec_group_.get() != nullptr) {
		// Don't update any lengths when an FEC group is open, to ensure same
		// packet header size in all packets within a group.
		return IN_FEC_GROUP;
	}
	if (!queued_frames_.empty()) {
		// Don't change creator state if there are frames queued.
		return NOT_IN_FEC_GROUP;
	}
	// Update packet number length only on packet and FEC group boundaries. -- causes bugs
	//packet_.packet_number_length = next_packet_number_length_;
	if (!fec_protect_) {
		return NOT_IN_FEC_GROUP;
	}
	// Start a new FEC group since protection is on. Set the fec group number to
	// the packet number of the next packet.
	// Set fec configuration according to the current packet-loss
	fec_group_.reset(new QuicFecGroup(packet_.packet_number + 1, current_fec_configuration));
	return IN_FEC_GROUP;
}

void QuicPacketCreator::MaybeStartFecProtection() {
	if (max_packets_per_fec_group_ == 0 || fec_protect_) {
		// Do not start FEC protection when FEC protection is not enabled or FEC
		// protection is already on.
		return;
	}
	DVLOG(1) << "Turning FEC protection ON";
	// Flush current open packet.
	Flush();

	StartFecProtectingPackets();
	DCHECK(fec_protect_);
}

void QuicPacketCreator::MaybeSendFecPacketAndCloseGroup(bool force_send_fec,
                                                        bool is_fec_timeout) {
	if (ShouldSendFec(force_send_fec)) {
  //  if ((fec_send_policy_ == FEC_ALARM_TRIGGER && !is_fec_timeout)) {
  //    ResetFecGroup();
  //    delegate_->OnResetFecGroup();
  //  } else {
      // TODO(zhongyi): Change the default 64 alignas value (used the default
      // value from CACHELINE_SIZE).
      //ALIGNAS(64) char seralized_fec_buffer[kMaxPacketSize];
      //SerializeFec(seralized_fec_buffer, kMaxPacketSize);
	  
	  SerializeFec();
	  return;
//      OnSerializedPacket();
  //  }
  }

  if (!should_fec_protect_next_packet_ && fec_protect_ && !IsFecGroupOpen()) {
    StopFecProtectingPackets();
  }
}

QuicTime::Delta QuicPacketCreator::GetFecTimeout(
	QuicPacketNumber packet_number) {
	// Do not set up FEC alarm for |packet_number| it is not the first packet in
	// the current group.
	if (fec_group_.get() != nullptr &&
		(packet_number == fec_group_->FecGroupNumber())) {
		return QuicTime::Delta::Max(
			fec_timeout_, QuicTime::Delta::FromMilliseconds(kMinFecTimeoutMs));
	}
	return QuicTime::Delta::Infinite();
}

// Stops serializing version of the protocol in packets sent after this call.
// A packet that is already open might send kQuicVersionSize bytes less than the
// maximum packet size if we stop sending version before it is serialized.
void QuicPacketCreator::StopSendingVersion() {
  DCHECK(send_version_in_packet_);
  send_version_in_packet_ = false;
  if (packet_size_ > 0) {
    DCHECK_LT(kQuicVersionSize, packet_size_);
    packet_size_ -= kQuicVersionSize;
  }
}

void QuicPacketCreator::SetDiversificationNonce(
    const DiversificationNonce& nonce) {
  DCHECK(!have_diversification_nonce_);
  have_diversification_nonce_ = true;
  diversification_nonce_ = nonce;
}

void QuicPacketCreator::UpdatePacketNumberLength(
    QuicPacketNumber least_packet_awaited_by_peer,
    QuicPacketCount max_packets_in_flight) {
  if (!queued_frames_.empty()) {
    // Don't change creator state if there are frames queued.
    QUIC_BUG << "Called UpdatePacketNumberLength with " << queued_frames_.size()
             << " queued_frames.  First frame type:"
             << queued_frames_.front().type
             << " last frame type:" << queued_frames_.back().type;
    return;
  }

  DCHECK_LE(least_packet_awaited_by_peer, packet_.packet_number + 1);
  const QuicPacketNumber current_delta =
      packet_.packet_number + 1 - least_packet_awaited_by_peer;
  const uint64_t delta = max(current_delta, max_packets_in_flight);
  packet_.packet_number_length =
      QuicFramer::GetMinSequenceNumberLength(delta * 4);
}

bool QuicPacketCreator::ConsumeData(QuicStreamId id,
                                    QuicIOVector iov,
                                    size_t iov_offset,
                                    QuicStreamOffset offset,
                                    bool fin,
                                    bool needs_full_padding,
                                    QuicFrame* frame,
									FecProtection fec_protection) {
  if (!HasRoomForStreamFrame(id, offset)) {
    return false;
  }

  if (fec_protection == MUST_FEC_PROTECT) {
	  should_fec_protect_next_packet_ = true;
	  MaybeStartFecProtection();
  }

  CreateStreamFrame(id, iov, iov_offset, offset, fin, frame);
  // Explicitly disallow multi-packet CHLOs.
  if (id == kCryptoStreamId &&
      frame->stream_frame->data_length >= sizeof(kCHLO) &&
      strncmp(frame->stream_frame->data_buffer,
              reinterpret_cast<const char*>(&kCHLO), sizeof(kCHLO)) == 0) {
    DCHECK_EQ(static_cast<size_t>(0), iov_offset);
    if (FLAGS_quic_enforce_single_packet_chlo &&
        frame->stream_frame->data_length < iov.iov->iov_len) {
      const string error_details = "Client hello won't fit in a single packet.";
      QUIC_BUG << error_details << " Constructed stream frame length: "
               << frame->stream_frame->data_length
               << " CHLO length: " << iov.iov->iov_len;
      delegate_->OnUnrecoverableError(QUIC_CRYPTO_CHLO_TOO_LARGE, error_details,
                                      ConnectionCloseSource::FROM_SELF);
      delete frame->stream_frame;
      return false;
    }
  }
  if (!AddFrame(*frame, /*save_retransmittable_frames=*/true)) {
    // Fails if we try to write unencrypted stream data.
    delete frame->stream_frame;
    return false;
  }
  if (needs_full_padding) {
    packet_.num_padding_bytes = -1;
  }

  if (fec_protection == MUST_FEC_PROTECT &&
	  iov_offset + frame->stream_frame->data_length == iov.total_length) {
	  // Turn off FEC protection when we're done writing protected data.
	  DVLOG(1) << "Turning FEC protection OFF";
	  should_fec_protect_next_packet_ = false;
  }
  return true;
}

bool QuicPacketCreator::HasRoomForStreamFrame(QuicStreamId id,
                                              QuicStreamOffset offset) {
  return BytesFree() > QuicFramer::GetMinStreamFrameSize(id, offset, true, fec_protect_ ? IN_FEC_GROUP : NOT_IN_FEC_GROUP);
}

// static
size_t QuicPacketCreator::StreamFramePacketOverhead(
    QuicVersion version,
    QuicConnectionIdLength connection_id_length,
    bool include_version,
    bool include_path_id,
    bool include_diversification_nonce,
    QuicPacketNumberLength packet_number_length,
    QuicStreamOffset offset,
	InFecGroup is_in_fec_group) {
  return GetPacketHeaderSize(version, connection_id_length, include_version,
                             include_path_id, include_diversification_nonce,
                             packet_number_length, is_in_fec_group) +
         // Assumes this is a stream with a single lone packet.
         QuicFramer::GetMinStreamFrameSize(1u, offset, true, is_in_fec_group);
}


void QuicPacketCreator::CreateStreamFrame(QuicStreamId id,
                                          QuicIOVector iov,
                                          size_t iov_offset,
                                          QuicStreamOffset offset,
                                          bool fin,
                                          QuicFrame* frame) {
  

	InFecGroup is_in_fec_group = MaybeUpdateLengthsAndStartFec();
	DCHECK_GT(max_packet_length_,
            StreamFramePacketOverhead(framer_->version(), connection_id_length_,
                                      kIncludeVersion, kIncludePathId,
                                      IncludeNonceInPublicHeader(),
                                      PACKET_6BYTE_PACKET_NUMBER, offset, is_in_fec_group));
  
  QUIC_BUG_IF(!HasRoomForStreamFrame(id, offset))
      << "No room for Stream frame, BytesFree: " << BytesFree()
      << " MinStreamFrameSize: "
      << QuicFramer::GetMinStreamFrameSize(id, offset, true, is_in_fec_group);

  if (iov_offset == iov.total_length) {
    QUIC_BUG_IF(!fin) << "Creating a stream frame with no data or fin.";
    // Create a new packet for the fin, if necessary.
    *frame = QuicFrame(new QuicStreamFrame(id, true, offset, StringPiece()));
    return;
  }

  const size_t data_size = iov.total_length - iov_offset;
  size_t min_frame_size = QuicFramer::GetMinStreamFrameSize(
      id, offset, /* last_frame_in_packet= */ true, is_in_fec_group);
  // HIBA 2 for size. not sure if needed
  size_t bytes_consumed = min<size_t>(BytesFree() - min_frame_size - 2, data_size);

  bool set_fin = fin && bytes_consumed == data_size;  // Last frame.
  UniqueStreamBuffer buffer =
      NewStreamBuffer(buffer_allocator_, bytes_consumed);
  CopyToBuffer(iov, iov_offset, bytes_consumed, buffer.get());
  *frame = QuicFrame(new QuicStreamFrame(id, set_fin, offset, bytes_consumed,
                                         std::move(buffer)));
}

// static
void QuicPacketCreator::CopyToBuffer(QuicIOVector iov,
                                     size_t iov_offset,
                                     size_t length,
                                     char* buffer) {
  int iovnum = 0;
  while (iovnum < iov.iov_count && iov_offset >= iov.iov[iovnum].iov_len) {
    iov_offset -= iov.iov[iovnum].iov_len;
    ++iovnum;
  }
  DCHECK_LE(iovnum, iov.iov_count);
  DCHECK_LE(iov_offset, iov.iov[iovnum].iov_len);
  if (iovnum >= iov.iov_count || length == 0) {
    return;
  }

  // Unroll the first iteration that handles iov_offset.
  const size_t iov_available = iov.iov[iovnum].iov_len - iov_offset;
  size_t copy_len = min(length, iov_available);

  // Try to prefetch the next iov if there is at least one more after the
  // current. Otherwise, it looks like an irregular access that the hardware
  // prefetcher won't speculatively prefetch. Only prefetch one iov because
  // generally, the iov_offset is not 0, input iov consists of 2K buffers and
  // the output buffer is ~1.4K.
  if (copy_len == iov_available && iovnum + 1 < iov.iov_count) {
    // TODO(ckrasic) - this is unused without prefetch()
    // char* next_base = static_cast<char*>(iov.iov[iovnum + 1].iov_base);
    // char* next_base = static_cast<char*>(iov.iov[iovnum + 1].iov_base);
    // Prefetch 2 cachelines worth of data to get the prefetcher started; leave
    // it to the hardware prefetcher after that.
    // TODO(ckrasic) - investigate what to do about prefetch directives.
    // prefetch(next_base, PREFETCH_HINT_T0);
    if (iov.iov[iovnum + 1].iov_len >= 64) {
      // TODO(ckrasic) - investigate what to do about prefetch directives.
      // prefetch(next_base + CACHELINE_SIZE, PREFETCH_HINT_T0);
    }
  }

  const char* src = static_cast<char*>(iov.iov[iovnum].iov_base) + iov_offset;
  while (true) {
    memcpy(buffer, src, copy_len);
    length -= copy_len;
    buffer += copy_len;
    if (length == 0 || ++iovnum >= iov.iov_count) {
      break;
    }
    src = static_cast<char*>(iov.iov[iovnum].iov_base);
    copy_len = min(length, iov.iov[iovnum].iov_len);
  }
  QUIC_BUG_IF(length > 0) << "Failed to copy entire length to buffer.";
}

void QuicPacketCreator::ReserializeAllFrames(
    const PendingRetransmission& retransmission,
    char* buffer,
    size_t buffer_len) {
	//return;
  DCHECK(queued_frames_.empty());
  DCHECK_EQ(0, packet_.num_padding_bytes);
  QUIC_BUG_IF(retransmission.retransmittable_frames.empty())
      << "Attempt to serialize empty packet";
  const EncryptionLevel default_encryption_level = packet_.encryption_level;

  // Temporarily set the packet number length and change the encryption level.
  packet_.packet_number_length = retransmission.packet_number_length;
  packet_.num_padding_bytes = retransmission.num_padding_bytes;
  // Only preserve the original encryption level if it's a handshake packet or
  // if we haven't gone forward secure.
  if (retransmission.has_crypto_handshake ||
      packet_.encryption_level != ENCRYPTION_FORWARD_SECURE) {
    packet_.encryption_level = retransmission.encryption_level;
  }

  // Serialize the packet and restore packet number length state.
  for (const QuicFrame& frame : retransmission.retransmittable_frames) {
    bool success = AddFrame(frame, false);
    QUIC_BUG_IF(!success) << " Failed to add frame of type:" << frame.type
                          << " num_frames:"
                          << retransmission.retransmittable_frames.size()
                          << " retransmission.packet_number_length:"
                          << retransmission.packet_number_length
                          << " packet_.packet_number_length:"
                          << packet_.packet_number_length;
  }
  SerializePacket(buffer, buffer_len);
  packet_.original_path_id = retransmission.path_id;
  packet_.original_packet_number = retransmission.packet_number;
  packet_.transmission_type = retransmission.transmission_type;
  OnSerializedPacket(false);
  // Restore old values.
  packet_.encryption_level = default_encryption_level;
}

void QuicPacketCreator::Flush() {
  if (!HasPendingFrames()) {
    return;
  }

  // TODO(rtenneti): Change the default 64 alignas value (used the default
  // value from CACHELINE_SIZE).
  ALIGNAS(64) char seralized_packet_buffer[kMaxPacketSize];
  SerializePacket(seralized_packet_buffer, kMaxPacketSize);
  OnSerializedPacket(false);
}

void QuicPacketCreator::OnSerializedPacket(bool is_fec_packet) {
  if (packet_.encrypted_buffer == nullptr) {
    const string error_details = "Failed to SerializePacket.";
    QUIC_BUG << error_details;
    delegate_->OnUnrecoverableError(QUIC_FAILED_TO_SERIALIZE_PACKET,
                                    error_details,
                                    ConnectionCloseSource::FROM_SELF);
    return;
  }

  delegate_->OnSerializedPacket(&packet_);
  ClearPacket();
  if (!is_fec_packet)
  {
	  MaybeSendFecPacketAndCloseGroup(/*force_send_fec=*/false, /*is_fec_timeout=*/false);
  }
  // Maximum packet size may be only enacted while no packet is currently being
  // constructed, so here we have a good opportunity to actually change it.
  if (CanSetMaxPacketLength()) {
    SetMaxPacketLength(max_packet_length_);
  }
}

void QuicPacketCreator::ClearPacket() {
  packet_.has_ack = false;
  packet_.has_stop_waiting = false;
  packet_.has_crypto_handshake = NOT_HANDSHAKE;
  packet_.num_padding_bytes = 0;
  packet_.original_path_id = kInvalidPathId;
  packet_.original_packet_number = 0;
  packet_.transmission_type = NOT_RETRANSMISSION;
  packet_.encrypted_buffer = nullptr;
  packet_.encrypted_length = 0;
  DCHECK(packet_.retransmittable_frames.empty());
  packet_.listeners.clear();
}

// HIBA was in origin, I removed
//void QuicPacketCreator::CreateAndSerializeStreamFrame(
//    QuicStreamId id,
//    const QuicIOVector& iov,
//    QuicStreamOffset iov_offset,
//    QuicStreamOffset stream_offset,
//    bool fin,
//    QuicAckListenerInterface* listener,
//    size_t* num_bytes_consumed) {
//  DCHECK(queued_frames_.empty());
//  // Write out the packet header
//  QuicPacketHeader header;
//  //FillPacketHeader(&header);
//  FillPacketHeader(fec_protect_ ? fec_group_number_ : 0, false, &header);
//  ALIGNAS(64) char encrypted_buffer[kMaxPacketSize];
//  QuicDataWriter writer(arraysize(encrypted_buffer), encrypted_buffer);
//  if (!framer_->AppendPacketHeader(header, &writer)) {
//    QUIC_BUG << "AppendPacketHeader failed";
//    return;
//  }
//
//  // Create a Stream frame with the remaining space.
//  QUIC_BUG_IF(iov_offset == iov.total_length && !fin)
//      << "Creating a stream frame with no data or fin.";
//  const size_t remaining_data_size = iov.total_length - iov_offset;
//  const size_t min_frame_size = QuicFramer::GetMinStreamFrameSize(
//      id, stream_offset, /* last_frame_in_packet= */ true);
//  const size_t available_size =
//      max_plaintext_size_ - writer.length() - min_frame_size;
//  const size_t bytes_consumed =
//      min<size_t>(available_size, remaining_data_size);
//
//  const bool set_fin = fin && (bytes_consumed == remaining_data_size);
//  UniqueStreamBuffer stream_buffer =
//      NewStreamBuffer(buffer_allocator_, bytes_consumed);
//  CopyToBuffer(iov, iov_offset, bytes_consumed, stream_buffer.get());
//  std::unique_ptr<QuicStreamFrame> frame(new QuicStreamFrame(
//      id, set_fin, stream_offset, bytes_consumed, std::move(stream_buffer)));
//  DVLOG(1) << "Adding frame: " << *frame;
//
//  // TODO(ianswett): AppendTypeByte and AppendStreamFrame could be optimized
//  // into one method that takes a QuicStreamFrame, if warranted.
//  if (!framer_->AppendTypeByte(QuicFrame(frame.get()),
//                               /* no stream frame length */ true, &writer)) {
//    QUIC_BUG << "AppendTypeByte failed";
//    return;
//  }
//  if (!framer_->AppendStreamFrame(*frame, /* no stream frame length */ true,
//                                  &writer)) {
//    QUIC_BUG << "AppendStreamFrame failed";
//    return;
//  }
//
//  size_t encrypted_length = framer_->EncryptInPlace(
//      packet_.encryption_level, packet_.path_id, packet_.packet_number,
//      GetStartOfEncryptedData(framer_->version(), header), writer.length(),
//      arraysize(encrypted_buffer), encrypted_buffer);
//  if (encrypted_length == 0) {
//    QUIC_BUG << "Failed to encrypt packet number " << header.packet_number;
//    return;
//  }
//  // TODO(ianswett): Optimize the storage so RetransmitableFrames can be
//  // unioned with a QuicStreamFrame and a UniqueStreamBuffer.
//  *num_bytes_consumed = bytes_consumed;
//  packet_size_ = 0;
//  packet_.entropy_hash = QuicFramer::GetPacketEntropyHash(header);
//  packet_.encrypted_buffer = encrypted_buffer;
//  packet_.encrypted_length = encrypted_length;
//  if (listener != nullptr) {
//    packet_.listeners.emplace_back(listener, bytes_consumed);
//  }
//  packet_.retransmittable_frames.push_back(QuicFrame(frame.release()));
//  OnSerializedPacket();
//}

bool QuicPacketCreator::HasPendingFrames() const {
  return !queued_frames_.empty();
}

bool QuicPacketCreator::HasPendingRetransmittableFrames() const {
  return !packet_.retransmittable_frames.empty();
}

size_t QuicPacketCreator::ExpansionOnNewFrame() const {
	// If packet is FEC protected, there's no expansion.
	if (fec_protect_) {
		return 0;
	}
	
	// If the last frame in the packet is a stream frame, then it will expand to
  // include the stream_length field when a new frame is added.
  bool has_trailing_stream_frame =
      !queued_frames_.empty() && queued_frames_.back().type == STREAM_FRAME;
  return has_trailing_stream_frame ? kQuicStreamPayloadLengthSize : 0;
}

size_t QuicPacketCreator::BytesFree() {
  DCHECK_GE(max_plaintext_size_, PacketSize());
  return max_plaintext_size_ - 
         min(max_plaintext_size_, PacketSize() + ExpansionOnNewFrame());
}

size_t QuicPacketCreator::PacketSize() {
  if (!queued_frames_.empty()) {
    return packet_size_;
  }
  packet_size_ = GetPacketHeaderSize(
      framer_->version(), connection_id_length_, send_version_in_packet_,
      send_path_id_in_packet_, IncludeNonceInPublicHeader(),
      packet_.packet_number_length, fec_protect_ ? IN_FEC_GROUP : NOT_IN_FEC_GROUP);
  return packet_size_;
}

bool QuicPacketCreator::AddSavedFrame(const QuicFrame& frame) {
  return AddFrame(frame, /*save_retransmittable_frames=*/true);
}

bool QuicPacketCreator::AddPaddedSavedFrame(const QuicFrame& frame) {
  if (AddFrame(frame, /*save_retransmittable_frames=*/true)) {
    packet_.num_padding_bytes = -1;
    return true;
  }
  return false;
}

void QuicPacketCreator::AddAckListener(QuicAckListenerInterface* listener,
                                       QuicPacketLength length) {
  DCHECK(!queued_frames_.empty());
  packet_.listeners.emplace_back(listener, length);
}

void QuicPacketCreator::SerializePacket(char* encrypted_buffer,
                                        size_t encrypted_buffer_len) {
  DCHECK_LT(0u, encrypted_buffer_len);
  QUIC_BUG_IF(queued_frames_.empty()) << "Attempt to serialize empty packet";
  QuicPacketHeader header;
  // FillPacketHeader increments packet_number_.
  FillPacketHeader(false, &header);

  MaybeAddPadding();

  DCHECK_GE(max_plaintext_size_, packet_size_);
  // Use the packet_size_ instead of the buffer size to ensure smaller
  // packet sizes are properly used.
  size_t length = framer_->BuildDataPacket(header, queued_frames_,
                                           encrypted_buffer, packet_size_);
  if (length == 0) {
    QUIC_BUG << "Failed to serialize " << queued_frames_.size() << " frames.";
    return;
  }

  const size_t start_of_fec = GetPacketHeaderSize(framer_->version(), header);

  OnBuiltFecProtectedPayload(header, StringPiece(encrypted_buffer + start_of_fec, length - start_of_fec));

  // ACK Frames will be truncated due to length only if they're the only frame
  // in the packet, and if packet_size_ was set to max_plaintext_size_. If
  // truncation due to length occurred, then GetSerializedFrameLength will have
  // returned all bytes free.
  bool possibly_truncated_by_length = packet_size_ == max_plaintext_size_ &&
                                      queued_frames_.size() == 1 &&
                                      queued_frames_.back().type == ACK_FRAME;
  // Because of possible truncation, we can't be confident that our
  // packet size calculation worked correctly.
  if (!possibly_truncated_by_length) {
    DCHECK_EQ(packet_size_, length);
  }
  const size_t encrypted_length = framer_->EncryptInPlace(
      packet_.encryption_level, packet_.path_id, packet_.packet_number,
      GetStartOfEncryptedData(framer_->version(), header), length,
      encrypted_buffer_len, encrypted_buffer);
  if (encrypted_length == 0) {
    QUIC_BUG << "Failed to encrypt packet number " << packet_.packet_number;
    return;
  }

  packet_size_ = 0;
  queued_frames_.clear();
  packet_.entropy_hash = QuicFramer::GetPacketEntropyHash(header);
  packet_.encrypted_buffer = encrypted_buffer;
  packet_.encrypted_length = encrypted_length;
}

QuicEncryptedPacket* QuicPacketCreator::SerializeVersionNegotiationPacket(
    const QuicVersionVector& supported_versions) {
  DCHECK_EQ(Perspective::IS_SERVER, framer_->perspective());
  QuicEncryptedPacket* encrypted = QuicFramer::BuildVersionNegotiationPacket(
      connection_id_, supported_versions);
  DCHECK(encrypted);
  DCHECK_GE(max_packet_length_, encrypted->length());
  return encrypted;
}

// TODO(jri): Make this a public method of framer?
SerializedPacket QuicPacketCreator::NoPacket() {
  return SerializedPacket(kInvalidPathId, 0, PACKET_1BYTE_PACKET_NUMBER,
                          nullptr, 0, 0, false, false, false);
}

//void QuicPacketCreator::FillPacketHeader(QuicPacketHeader* header) {
void QuicPacketCreator::FillPacketHeader(bool fec_flag,
	QuicPacketHeader* header) {
  header->public_header.connection_id = connection_id_;
  header->public_header.connection_id_length = connection_id_length_;
  header->public_header.multipath_flag = send_path_id_in_packet_;
  header->public_header.reset_flag = false;
  header->public_header.version_flag = send_version_in_packet_;
  if (IncludeNonceInPublicHeader()) {
    DCHECK_EQ(Perspective::IS_SERVER, framer_->perspective());
    header->public_header.nonce = &diversification_nonce_;
  } else {
    header->public_header.nonce = nullptr;
  }
  header->path_id = packet_.path_id;
  header->packet_number = ++packet_.packet_number;
  header->public_header.packet_number_length = packet_.packet_number_length;
  header->entropy_flag = random_bool_source_.RandBool();

  QuicFecGroupNumber fec_group = fec_group_ != nullptr ? fec_group_->FecGroupNumber() : 0;
  header->fec_flag = fec_flag;
  header->is_in_fec_group = fec_group == 0 ? NOT_IN_FEC_GROUP : IN_FEC_GROUP;
  header->fec_group = fec_group;
  header->fec_configuration = fec_group_ != nullptr ? fec_group_->fec_configuration : FEC_100_5; // put default. not used

}

bool QuicPacketCreator::ShouldRetransmit(const QuicFrame& frame) {
  switch (frame.type) {
    case ACK_FRAME:
    case PADDING_FRAME:
    case STOP_WAITING_FRAME:
    case MTU_DISCOVERY_FRAME:
      return false;
    default:
      return true;
  }
}

bool QuicPacketCreator::AddFrame(const QuicFrame& frame,
                                 bool save_retransmittable_frames) {
  DVLOG(1) << "Adding frame: " << frame;
  if (frame.type == STREAM_FRAME &&
      frame.stream_frame->stream_id != kCryptoStreamId &&
      packet_.encryption_level == ENCRYPTION_NONE) {
    const string error_details = "Cannot send stream data without encryption.";
    QUIC_BUG << error_details;
    delegate_->OnUnrecoverableError(
        QUIC_ATTEMPT_TO_SEND_UNENCRYPTED_STREAM_DATA, error_details,
        ConnectionCloseSource::FROM_SELF);
    return false;
  }
  InFecGroup is_in_fec_group = MaybeUpdateLengthsAndStartFec();

  size_t frame_len = framer_->GetSerializedFrameLength(
      frame, BytesFree(), queued_frames_.empty(), true,
	  is_in_fec_group,
      packet_.packet_number_length);
  if (frame_len == 0) {
    // Current open packet is full.
    Flush();
    return false;
  }
  DCHECK_LT(0u, packet_size_);
  packet_size_ += ExpansionOnNewFrame() + frame_len;

  if (save_retransmittable_frames && ShouldRetransmit(frame)) {
    if (packet_.retransmittable_frames.empty()) {
      packet_.retransmittable_frames.reserve(2);
    }
    packet_.retransmittable_frames.push_back(frame);
    queued_frames_.push_back(frame);
    if (frame.type == STREAM_FRAME &&
        frame.stream_frame->stream_id == kCryptoStreamId) {
      packet_.has_crypto_handshake = IS_HANDSHAKE;
    }
  } else {
    queued_frames_.push_back(frame);
  }

  if (frame.type == ACK_FRAME) {
    packet_.has_ack = true;
  }
  if (frame.type == STOP_WAITING_FRAME) {
    packet_.has_stop_waiting = true;
  }
  if (debug_delegate_ != nullptr) {
    debug_delegate_->OnFrameAddedToPacket(frame);
  }

  return true;
}

void QuicPacketCreator::MaybeAddPadding() {
  if (packet_.num_padding_bytes == 0) {
    return;
  }

  if (BytesFree() == 0) {
    // Don't pad full packets.
    return;
  }

  bool success =
      AddFrame(QuicFrame(QuicPaddingFrame(packet_.num_padding_bytes)), false);
  DCHECK(success);
}


void QuicPacketCreator::SetCurrentPath(
    QuicPathId path_id,
    QuicPacketNumber least_packet_awaited_by_peer,
    QuicPacketCount max_packets_in_flight) {
  if (packet_.path_id == path_id) {
    return;
  }

  if (HasPendingFrames()) {
    QUIC_BUG << "Unable to change paths when a packet is under construction.";
    return;
  }
  // Send FEC packet and close FEC group.
  MaybeSendFecPacketAndCloseGroup(/*force_send_fec=*/true, /*is_fec_timeout=*/false);

  // Save current packet number and load switching path's packet number.
  multipath_packet_number_[packet_.path_id] = packet_.packet_number;
  std::unordered_map<QuicPathId, QuicPacketNumber>::iterator it =
      multipath_packet_number_.find(path_id);
  // If path_id is not in the map, it's a new path. Set packet_number to 0.
  packet_.packet_number = it == multipath_packet_number_.end() ? 0 : it->second;
  packet_.path_id = path_id;
  DCHECK(packet_.path_id != kInvalidPathId);
  // Send path in packet if current path is not the default path.
  send_path_id_in_packet_ = packet_.path_id != kDefaultPathId ? true : false;
  // Switching path needs to update packet number length.
  UpdatePacketNumberLength(least_packet_awaited_by_peer, max_packets_in_flight);
}

bool QuicPacketCreator::IncludeNonceInPublicHeader() {
  return have_diversification_nonce_ &&
         packet_.encryption_level == ENCRYPTION_INITIAL;
}

QuicPacketCreator::QuicRandomBoolSource::QuicRandomBoolSource(
    QuicRandom* random)
    : random_(random), bit_bucket_(0), bit_mask_(0) {}

QuicPacketCreator::QuicRandomBoolSource::~QuicRandomBoolSource() {}

bool QuicPacketCreator::QuicRandomBoolSource::RandBool() {
  if (bit_mask_ == 0) {
    bit_bucket_ = random_->RandUint64();
    bit_mask_ = 1;
  }
  bool result = ((bit_bucket_ & bit_mask_) != 0);
  bit_mask_ <<= 1;
  return result;
}

void QuicPacketCreator::SerializeFec() {
	if (fec_group_.get() == nullptr || fec_group_->NumSentPackets() <= 0) {
		QUIC_BUG << "SerializeFEC called but no group or zero packets in group.";
		return;
	}

	std::list<ParityPacket *> parities = fec_group_->getRedundancyPackets();

	for (std::list<ParityPacket *>::reverse_iterator it = parities.rbegin(); it != parities.rend(); it++)
	{
		QuicPacketHeader header;
		//header.is_in_fec_group = IN_FEC_GROUP;
		//header.fec_flag = true;
		header.public_header.multipath_flag = send_path_id_in_packet_;

		// will choose the packet number automatically . we will override it
		FillPacketHeader(true, &header);
		header.packet_number = (*it)->packet_number;

		std::unique_ptr<QuicPacket> packet(framer_->BuildFecPacket(header, StringPiece((*it)->packet_data)));
		
		packet_.entropy_hash = QuicFramer::GetPacketEntropyHash(header);
	
		ALIGNAS(64) char seralized_fec_buffer[kMaxPacketSize];
		memcpy(seralized_fec_buffer, packet->data(), packet->length());

		size_t encrypted_length = framer_->EncryptInPlace(
			packet_.encryption_level, packet_.path_id, header.packet_number, GetStartOfEncryptedData(framer_->version(), header), packet->length(),
			kMaxPacketSize, seralized_fec_buffer);
		if (encrypted_length == 0) {
			QUIC_BUG << "Failed to encrypt packet number " << packet_.packet_number;
			return;
		}

		//packet_.packet_number = header.packet_number; causes errors when trying to send the packet at the wrong order... 
		packet_.entropy_hash = QuicFramer::GetPacketEntropyHash(header);
		packet_.encrypted_buffer = seralized_fec_buffer;
		packet_.encrypted_length = encrypted_length;
		packet_.is_fec_packet = true;
		DVLOG(1) << "serialized fec! number: " << header.packet_number << " size: " << packet_.encrypted_length << " || " << StringPiece((*it)->packet_data).size();
		
		OnSerializedPacket(true);

		// instead? will be probelmatic during receiving
		/*QuicFrame frame;
		QuicIOVector io_vector(MakeIOVector(data));
		ConsumeData(kClientDataStreamId1, io_vector, 0u,
			kOffset, false, false, &frame);
		size_t bytes_consumed = frame.stream_frame->data_length;
		creator_.Flush();*/
	}
	fec_group_.reset(nullptr); 
	packet_size_ = 0;
}


}  // namespace net