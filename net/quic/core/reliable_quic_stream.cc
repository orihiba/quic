// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/core/reliable_quic_stream.h"

#include "base/logging.h"
#include "net/quic/core/iovector.h"
#include "net/quic/core/quic_bug_tracker.h"
#include "net/quic/core/quic_flags.h"
#include "net/quic/core/quic_flow_controller.h"
#include "net/quic/core/quic_session.h"
#include "net/quic/core/quic_write_blocked_list.h"
#include "base/strings/string_number_conversions.h"


// for -fec command line
//#include "base/command_line.h"
//#include "base/base_switches.h"

using base::StringPiece;
using std::min;
using std::string;

namespace net {

#define ENDPOINT \
  (perspective_ == Perspective::IS_SERVER ? "Server: " : "Client: ")

namespace {

struct iovec MakeIovec(StringPiece data) {
  struct iovec iov = {const_cast<char*>(data.data()),
                      static_cast<size_t>(data.size())};
  return iov;
}

size_t GetInitialStreamFlowControlWindowToSend(QuicSession* session) {
  return session->config()->GetInitialStreamFlowControlWindowToSend();
}

size_t GetReceivedFlowControlWindow(QuicSession* session) {
  if (session->config()->HasReceivedInitialStreamFlowControlWindowBytes()) {
    return session->config()->ReceivedInitialStreamFlowControlWindowBytes();
  }

  return kMinimumFlowControlSendWindow;
}

}  // namespace

ReliableQuicStream::PendingData::PendingData(
    string data_in,
    QuicAckListenerInterface* ack_listener_in)
    : data(std::move(data_in)), offset(0), ack_listener(ack_listener_in) {}

ReliableQuicStream::PendingData::~PendingData() {}

ReliableQuicStream::ReliableQuicStream(QuicStreamId id, QuicSession* session)
    : queued_data_bytes_(0),
      sequencer_(this, session->connection()->clock()),
      id_(id),
      session_(session),
      stream_bytes_read_(0),
      stream_bytes_written_(0),
      stream_error_(QUIC_STREAM_NO_ERROR),
      connection_error_(QUIC_NO_ERROR),
      read_side_closed_(false),
      write_side_closed_(false),
      fin_buffered_(false),
      fin_sent_(false),
      fin_received_(false),
      rst_sent_(false),
      rst_received_(false),
	  fec_policy_(MAY_FEC_PROTECT), // don't use FEC as default
      perspective_(session_->perspective()),
      flow_controller_(session_->connection(),
                       id_,
                       perspective_,
                       GetReceivedFlowControlWindow(session),
                       GetInitialStreamFlowControlWindowToSend(session),
                       session_->flow_controller()->auto_tune_receive_window()),
      connection_flow_controller_(session_->flow_controller()),
      stream_contributes_to_connection_flow_control_(true),
      busy_counter_(0) {
  SetFromConfig();
}

ReliableQuicStream::~ReliableQuicStream() {}

void ReliableQuicStream::SetFromConfig() {
	if (useFec)
	{
		fec_policy_ = MUST_FEC_PROTECT;
	}	
}

void ReliableQuicStream::OnStreamFrame(const QuicStreamFrame& frame) {
  DCHECK_EQ(frame.stream_id, id_);

  DCHECK(!(read_side_closed_ && write_side_closed_));

  if (frame.fin) {
    fin_received_ = true;
    if (fin_sent_) {
      session_->StreamDraining(id_);
    }
  }

  if (read_side_closed_) {
    DVLOG(1) << ENDPOINT << "Ignoring data in frame " << frame.stream_id;
    // The subclass does not want to read data:  blackhole the data.
    return;
  }

  // This count includes duplicate data received.
  size_t frame_payload_size = frame.data_length;
  stream_bytes_read_ += frame_payload_size;

  // Flow control is interested in tracking highest received offset.
  // Only interested in received frames that carry data.
  if (frame_payload_size > 0 &&
      MaybeIncreaseHighestReceivedOffset(frame.offset + frame_payload_size)) {
    // As the highest received offset has changed, check to see if this is a
    // violation of flow control.
    if (flow_controller_.FlowControlViolation() ||
        connection_flow_controller_->FlowControlViolation()) {
      CloseConnectionWithDetails(
          QUIC_FLOW_CONTROL_RECEIVED_TOO_MUCH_DATA,
          "Flow control violation after increasing offset");
      return;
    }
  }

  sequencer_.OnStreamFrame(frame);
}

int ReliableQuicStream::num_frames_received() const {
  return sequencer_.num_frames_received();
}

int ReliableQuicStream::num_duplicate_frames_received() const {
  return sequencer_.num_duplicate_frames_received();
}

void ReliableQuicStream::OnStreamReset(const QuicRstStreamFrame& frame) {
  rst_received_ = true;
  MaybeIncreaseHighestReceivedOffset(frame.byte_offset);

  stream_error_ = frame.error_code;
  CloseWriteSide();
  CloseReadSide();
}

void ReliableQuicStream::OnConnectionClosed(QuicErrorCode error,
                                            ConnectionCloseSource /*source*/) {
  if (read_side_closed_ && write_side_closed_) {
    return;
  }
  if (error != QUIC_NO_ERROR) {
    stream_error_ = QUIC_STREAM_CONNECTION_ERROR;
    connection_error_ = error;
  }

  CloseWriteSide();
  CloseReadSide();
}

void ReliableQuicStream::OnFinRead() {
  DCHECK(sequencer_.IsClosed());
  // OnFinRead can be called due to a FIN flag in a headers block, so there may
  // have been no OnStreamFrame call with a FIN in the frame.
  fin_received_ = true;
  // If fin_sent_ is true, then CloseWriteSide has already been called, and the
  // stream will be destroyed by CloseReadSide, so don't need to call
  // StreamDraining.
  CloseReadSide();
}

void ReliableQuicStream::Reset(QuicRstStreamErrorCode error) {
  stream_error_ = error;
  // Sending a RstStream results in calling CloseStream.
  session()->SendRstStream(id(), error, stream_bytes_written_);
  rst_sent_ = true;
}

void ReliableQuicStream::CloseConnectionWithDetails(QuicErrorCode error,
                                                    const string& details) {
  session()->connection()->CloseConnection(
      error, details, ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
}

void ReliableQuicStream::WriteOrBufferData(
    StringPiece data,
    bool fin,
    QuicAckListenerInterface* ack_listener) {
  if (data.empty() && !fin) {
    QUIC_BUG << "data.empty() && !fin";
    return;
  }

  if (fin_buffered_) {
    QUIC_BUG << "Fin already buffered";
    return;
  }
  if (write_side_closed_) {
    DLOG(ERROR) << ENDPOINT << "Attempt to write when the write side is closed";
    return;
  }

  QuicConsumedData consumed_data(0, false);
  fin_buffered_ = fin;

  if (queued_data_.empty()) {
    struct iovec iov(MakeIovec(data));
    consumed_data = WritevData(&iov, 1, fin, ack_listener);
    DCHECK_LE(consumed_data.bytes_consumed, data.length());
  }

  // If there's unconsumed data or an unconsumed fin, queue it.
  if (consumed_data.bytes_consumed < data.length() ||
      (fin && !consumed_data.fin_consumed)) {
    StringPiece remainder(data.substr(consumed_data.bytes_consumed));
    queued_data_bytes_ += remainder.size();
    queued_data_.emplace_back(remainder.as_string(), ack_listener);
  }
}

void ReliableQuicStream::OnCanWrite() {
  bool fin = false;
  while (!queued_data_.empty()) {
    PendingData* pending_data = &queued_data_.front();
    QuicAckListenerInterface* ack_listener = pending_data->ack_listener.get();
    if (queued_data_.size() == 1 && fin_buffered_) {
      fin = true;
    }
    if (pending_data->offset > 0 &&
        pending_data->offset >= pending_data->data.size()) {
      // This should be impossible because offset tracks the amount of
      // pending_data written thus far.
      QUIC_BUG << "Pending offset is beyond available data. offset: "
               << pending_data->offset << " vs: " << pending_data->data.size();
      return;
    }
    size_t remaining_len = pending_data->data.size() - pending_data->offset;
    struct iovec iov = {
        const_cast<char*>(pending_data->data.data()) + pending_data->offset,
        remaining_len};
    QuicConsumedData consumed_data = WritevData(&iov, 1, fin, ack_listener);
    queued_data_bytes_ -= consumed_data.bytes_consumed;
    if (consumed_data.bytes_consumed == remaining_len &&
        fin == consumed_data.fin_consumed) {
      queued_data_.pop_front();
    } else {
      if (consumed_data.bytes_consumed > 0) {
        pending_data->offset += consumed_data.bytes_consumed;
      }
      break;
    }
  }
}

void ReliableQuicStream::MaybeSendBlocked() {
  flow_controller_.MaybeSendBlocked();
  if (!stream_contributes_to_connection_flow_control_) {
    return;
  }
  connection_flow_controller_->MaybeSendBlocked();
  // If the stream is blocked by connection-level flow control but not by
  // stream-level flow control, add the stream to the write blocked list so that
  // the stream will be given a chance to write when a connection-level
  // WINDOW_UPDATE arrives.
  if (connection_flow_controller_->IsBlocked() &&
      !flow_controller_.IsBlocked()) {
    session_->MarkConnectionLevelWriteBlocked(id());
  }
}

QuicConsumedData ReliableQuicStream::WritevData(
    const struct iovec* iov,
    int iov_count,
    bool fin,
    QuicAckListenerInterface* ack_listener) {
  if (write_side_closed_) {
    DLOG(ERROR) << ENDPOINT << "Attempt to write when the write side is closed";
    return QuicConsumedData(0, false);
  }

  // How much data was provided.
  size_t write_length = TotalIovecLength(iov, iov_count);

  // A FIN with zero data payload should not be flow control blocked.
  bool fin_with_zero_data = (fin && write_length == 0);

  // How much data flow control permits to be written.
  QuicByteCount send_window = flow_controller_.SendWindowSize();
  if (stream_contributes_to_connection_flow_control_) {
    send_window =
        min(send_window, connection_flow_controller_->SendWindowSize());
  }

  if (session_->ShouldYield(id())) {
    session_->MarkConnectionLevelWriteBlocked(id());
    return QuicConsumedData(0, false);
  }

  if (send_window == 0 && !fin_with_zero_data) {
    // Quick return if nothing can be sent.
    MaybeSendBlocked();
    return QuicConsumedData(0, false);
  }

  if (write_length > send_window) {
    // Don't send the FIN unless all the data will be sent.
    fin = false;

    // Writing more data would be a violation of flow control.
    write_length = static_cast<size_t>(send_window);
    DVLOG(1) << "stream " << id() << " shortens write length to "
             << write_length << " due to flow control";
  }
  DVLOG(1) << "stream id " << id();
  QuicConsumedData consumed_data =
      WritevDataInner(QuicIOVector(iov, iov_count, write_length),
                      stream_bytes_written_, fin, ack_listener);
  stream_bytes_written_ += consumed_data.bytes_consumed;

  AddBytesSent(consumed_data.bytes_consumed);

  // The write may have generated a write error causing this stream to be
  // closed. If so, simply return without marking the stream write blocked.
  if (write_side_closed_) {
    return consumed_data;
  }

  if (consumed_data.bytes_consumed == write_length) {
    if (!fin_with_zero_data) {
      MaybeSendBlocked();
    }
    if (fin && consumed_data.fin_consumed) {
      fin_sent_ = true;
      if (fin_received_) {
        session_->StreamDraining(id_);
      }
      CloseWriteSide();
    } else if (fin && !consumed_data.fin_consumed) {
      session_->MarkConnectionLevelWriteBlocked(id());
    }
  } else {
    session_->MarkConnectionLevelWriteBlocked(id());
  }
  return consumed_data;
}

QuicConsumedData ReliableQuicStream::WritevDataInner(
    QuicIOVector iov,
    QuicStreamOffset offset,
    bool fin,
    QuicAckListenerInterface* ack_notifier_delegate) {
  return session()->WritevData(this, id(), iov, offset, fin,
	  fec_policy_, ack_notifier_delegate); // HIBA start fec protection if --fec is given in command line
}

void ReliableQuicStream::CloseReadSide() {
  if (read_side_closed_) {
    return;
  }
  DVLOG(1) << ENDPOINT << "Done reading from stream " << id();

  read_side_closed_ = true;
  sequencer_.ReleaseBuffer();

  if (write_side_closed_) {
    DVLOG(1) << ENDPOINT << "Closing stream: " << id();
    session_->CloseStream(id());
  }
}

void ReliableQuicStream::CloseReadSideHack() {
	CloseReadSide();
}

void ReliableQuicStream::CloseWriteSide() {
  if (write_side_closed_) {
    return;
  }
  DVLOG(1) << ENDPOINT << "Done writing to stream " << id();

  write_side_closed_ = true;
  if (read_side_closed_) {
    DVLOG(1) << ENDPOINT << "Closing stream: " << id();
    session_->CloseStream(id());
  }
}

bool ReliableQuicStream::HasBufferedData() const {
  return !queued_data_.empty();
}

QuicVersion ReliableQuicStream::version() const {
  return session_->connection()->version();
}

void ReliableQuicStream::StopReading() {
  DVLOG(1) << ENDPOINT << "Stop reading from stream " << id();
  sequencer_.StopReading();
}

const IPEndPoint& ReliableQuicStream::PeerAddressOfLatestPacket() const {
  return session_->connection()->last_packet_source_address();
}

void ReliableQuicStream::OnClose() {
  CloseReadSide();
  CloseWriteSide();

  if (!fin_sent_ && !rst_sent_) {
    // For flow control accounting, tell the peer how many bytes have been
    // written on this stream before termination. Done here if needed, using a
    // RST_STREAM frame.
    DVLOG(1) << ENDPOINT << "Sending RST_STREAM in OnClose: " << id();
    session_->SendRstStream(id(), QUIC_RST_ACKNOWLEDGEMENT,
                            stream_bytes_written_);
    rst_sent_ = true;
  }

  // The stream is being closed and will not process any further incoming bytes.
  // As there may be more bytes in flight, to ensure that both endpoints have
  // the same connection level flow control state, mark all unreceived or
  // buffered bytes as consumed.
  QuicByteCount bytes_to_consume =
      flow_controller_.highest_received_byte_offset() -
      flow_controller_.bytes_consumed();
  AddBytesConsumed(bytes_to_consume);
}

void ReliableQuicStream::OnWindowUpdateFrame(
    const QuicWindowUpdateFrame& frame) {
  if (flow_controller_.UpdateSendWindowOffset(frame.byte_offset)) {
    // Writing can be done again!
    // TODO(rjshade): This does not respect priorities (e.g. multiple
    //                outstanding POSTs are unblocked on arrival of
    //                SHLO with initial window).
    // As long as the connection is not flow control blocked, write on!
    OnCanWrite();
  }
}

bool ReliableQuicStream::MaybeIncreaseHighestReceivedOffset(
    QuicStreamOffset new_offset) {
  uint64_t increment =
      new_offset - flow_controller_.highest_received_byte_offset();
  if (!flow_controller_.UpdateHighestReceivedOffset(new_offset)) {
    return false;
  }

  // If |new_offset| increased the stream flow controller's highest received
  // offset, increase the connection flow controller's value by the incremental
  // difference.
  if (stream_contributes_to_connection_flow_control_) {
    connection_flow_controller_->UpdateHighestReceivedOffset(
        connection_flow_controller_->highest_received_byte_offset() +
        increment);
  }
  return true;
}

void ReliableQuicStream::AddBytesSent(QuicByteCount bytes) {
  flow_controller_.AddBytesSent(bytes);
  if (stream_contributes_to_connection_flow_control_) {
    connection_flow_controller_->AddBytesSent(bytes);
  }
}

void ReliableQuicStream::AddBytesConsumed(QuicByteCount bytes) {
  // Only adjust stream level flow controller if still reading.
  if (!read_side_closed_) {
    flow_controller_.AddBytesConsumed(bytes);
  }

  if (stream_contributes_to_connection_flow_control_) {
    connection_flow_controller_->AddBytesConsumed(bytes);
  }
}

void ReliableQuicStream::UpdateSendWindowOffset(QuicStreamOffset new_window) {
  if (flow_controller_.UpdateSendWindowOffset(new_window)) {
    OnCanWrite();
  }
}


// --------------------------------------------------------------------------------------------------
class BoundedAlarmDelegate : public QuicAlarm::Delegate {
public:
	explicit BoundedAlarmDelegate(QuicNormalStream* stream)
		: stream_(stream) {}

	void OnAlarm() override { stream_->Reset(QUIC_STREAM_CANCELLED); }

private:
	QuicNormalStream* stream_;

	DISALLOW_COPY_AND_ASSIGN(BoundedAlarmDelegate);
};

QuicNormalStream::QuicNormalStream(QuicStreamId id, QuicSession * quic_session)
	: ReliableQuicStream(id, quic_session),
	session_(quic_session),
	visitor_(nullptr),
	bounded_delay_alarm_(nullptr),
	arena_(),
	bytes_remaining_(0) {

	if (session_->IsIncomingStream(id)) {
		bounded_delay_alarm_ = session_->connection()->alarm_factory()->CreateAlarm(
			arena_.New<BoundedAlarmDelegate>(this),
			&arena_);
		bounded_delay_alarm_->Set(session_->connection()->clock()->ApproximateNow() + QuicTime::Delta::FromMilliseconds(100000));
	}

	session_->RegisterStream(id);
}

QuicNormalStream::~QuicNormalStream() {
	if (session_ != nullptr) {
		session_->UnregisterStream(id());
	}
};

void QuicNormalStream::CloseWriteSide() {
	if (!fin_received() && !rst_received() && sequencer()->ignore_read_data() &&
		!rst_sent()) {
		DCHECK(fin_sent());
		// Tell the peer to stop sending further data.
		DVLOG(1) << ENDPOINT << "Send QUIC_STREAM_NO_ERROR on stream " << id();
		Reset(QUIC_STREAM_NO_ERROR);
	}

	ReliableQuicStream::CloseWriteSide();
}

void QuicNormalStream::StopReading() {
	if (!fin_received() && !rst_received() && write_side_closed() &&
		!rst_sent()) {
		DCHECK(fin_sent());
		// Tell the peer to stop sending further data.
		DVLOG(1) << ENDPOINT << "Send QUIC_STREAM_NO_ERROR on stream " << id();
		Reset(QUIC_STREAM_NO_ERROR);
	}
	ReliableQuicStream::StopReading();
}

size_t QuicNormalStream::Readv(const struct iovec* iov, size_t iov_len) {
	return sequencer()->Readv(iov, iov_len);
}

int QuicNormalStream::GetReadableRegions(iovec* iov, size_t iov_len) const {
	return sequencer()->GetReadableRegions(iov, iov_len);
}

void QuicNormalStream::MarkConsumed(size_t num_bytes) {
	return sequencer()->MarkConsumed(num_bytes);
}

bool QuicNormalStream::IsDoneReading() const {
	return sequencer()->IsClosed();
}

bool QuicNormalStream::HasBytesToRead() const {
	return sequencer()->HasBytesToRead();
}
// use super imp
//void QuicNormalStream::OnStreamReset(const QuicRstStreamFrame& frame) {
//	if (frame.error_code != QUIC_STREAM_NO_ERROR) {
//		ReliableQuicStream::OnStreamReset(frame);
//		return;
//	}
//	DVLOG(1) << "Received QUIC_STREAM_NO_ERROR, not discarding response";
//	set_rst_received(true);
//	MaybeIncreaseHighestReceivedOffset(frame.byte_offset);
//	set_stream_error(frame.error_code);
//	CloseWriteSide();
//}

void QuicNormalStream::OnClose() {
	//if (!fin_sent() && !rst_sent()) {
	//	// For flow control accounting, tell the peer how many bytes have been
	//	// written on this stream before termination. Done here if needed, using a
	//	// RST_STREAM frame.
	//	DVLOG(1) << ENDPOINT << "Sending RST_STREAM in OnClose: " << id();
	//	session_->SendRstStream(id(), QUIC_RST_ACKNOWLEDGEMENT,
	//	stream_bytes_written());
	//	set_rst_sent(true);
	//}

	if (visitor_) {
		Visitor* visitor = visitor_;
		// Calling Visitor::OnClose() may result the destruction of the visitor,
		// so we need to ensure we don't call it again.
		visitor_ = nullptr;
		visitor->OnClose(this);
	}

	if (bounded_delay_alarm_ != nullptr) {
		bounded_delay_alarm_->Cancel();
	}

	ReliableQuicStream::OnClose();
}

void QuicNormalStream::OnCanWrite() {
	ReliableQuicStream::OnCanWrite();

	// Trailers (and hence a FIN) may have been sent ahead of queued body bytes.
	if (!HasBufferedData() && fin_sent()) {
		CloseWriteSide();
	}
}

void QuicNormalStream::ClearSession() {
	session_ = nullptr;
}

QuicConsumedData QuicNormalStream::WritevDataInner(
	QuicIOVector iov,
	QuicStreamOffset offset,
	bool fin,
	QuicAckListenerInterface* ack_notifier_delegate) {

	return ReliableQuicStream::WritevDataInner(iov, offset, fin,
		ack_notifier_delegate);
}

void QuicNormalStream::OnDataAvailable() {
	// For push streams, visitor will not be set until the rendezvous
	// between server promise and client request is complete.
	/*if (visitor() == nullptr) // HIBA removed
		return;*/

 //	while (HasBytesToRead()) {
	//	struct iovec iov;
	//	if (GetReadableRegions(&iov, 1) == 0) {
	//		// No more data to read.
	//		break;
	//	}
	//	DVLOG(1) << ENDPOINT << " processed " << iov.iov_len << " bytes for stream "
	//		<< id();
	//	data_.append(static_cast<char*>(iov.iov_base), iov.iov_len);

	//	MarkConsumed(iov.iov_len);
	//}
	//if (sequencer()->IsClosed()) {
	//	OnFinRead();
	//}
	//else {
	//	sequencer()->SetUnblocked();
	//}
}

int QuicNormalStream::Read(char* buf, size_t buf_len)
{
	std::string data;
	while (HasBytesToRead() && buf_len) {
		struct iovec iov;
		if (GetReadableRegions(&iov, 1) == 0) {
			// No more data to read.
			break;
		}

		if (iov.iov_len > buf_len) {
			iov.iov_len = buf_len;
		}

		DVLOG(1) << ENDPOINT << " processed " << iov.iov_len << " bytes for stream "
			<< id();
		data.append(static_cast<char*>(iov.iov_base), iov.iov_len);

		MarkConsumed(iov.iov_len);
		buf_len -= iov.iov_len;
	}
	if (sequencer()->IsClosed()) {
		OnFinRead();
	}
	else {
		sequencer()->SetUnblocked();
	}

	memcpy(buf, data.c_str(), data.size());
	return data.size();
}

int QuicNormalStream::ReadFifoInner(char* buf, size_t buf_len)
{
	if (!data_.empty()) {
		// if new message
		if (bytes_remaining_ == 0) {
			bytes_remaining_ = *(uint32_t *)(data_.c_str());
			data_.erase(0, sizeof(bytes_remaining_));
		}

		size_t bytes_to_read = bytes_remaining_ < buf_len ? bytes_remaining_ : buf_len;

		// if received more than a message, cut the first message
		if (bytes_to_read < data_.size()) {
			strncpy(buf, data_.c_str(), bytes_to_read);

			// mark as read
			data_.erase(0, bytes_to_read);

			bytes_remaining_ -= bytes_to_read;
			return bytes_to_read;
		}
	}
	return 0;
}

int QuicNormalStream::ReadFifo(char* buf, size_t buf_len) {
	if (!data_.empty()) {
		int res = this->ReadFifoInner(buf, buf_len);
		if (res != 0) {
			return res;
		}
	}

	while (HasBytesToRead()) {
		struct iovec iov;
		if (GetReadableRegions(&iov, 1) == 0) {
			// No more data to read.
			break;
		}

		DVLOG(1) << ENDPOINT << " processed " << iov.iov_len << " bytes for stream "
			<< id();
		data_.append(static_cast<char*>(iov.iov_base), iov.iov_len);
		MarkConsumed(iov.iov_len);

		int res = this->ReadFifoInner(buf, buf_len);
		if (res != 0) {
			return res;
		}
	}

	// didn't receive the whole message
	if (bytes_remaining_ != data_.size()) {
		return 0;
	}

	if (sequencer()->IsClosed()) {
		OnFinRead();
	}
	else {
		sequencer()->SetUnblocked();
	}

	size_t bytes_to_read = data_.size();
	strncpy(buf, data_.c_str(), bytes_to_read);
	data_.erase(0, bytes_to_read);
	bytes_remaining_ -= bytes_to_read;
	return bytes_to_read;
}

int QuicNormalStream::ReadAll(char* buf, int buf_len) {
	size_t bytes_read = 0;
	while (buf_len > 0) {
		size_t bytes_read_cur = Read(buf + bytes_read, buf_len - bytes_read);
		bytes_read += bytes_read_cur;
	}
	return bytes_read;
}

void QuicNormalStream::OnStreamFrame(const QuicStreamFrame& frame) {
	ReliableQuicStream::OnStreamFrame(frame);

	QuicNormalSession *cur_session = (QuicNormalSession*)session();

	if (frame.fin || cur_session->fifo_session()) {
		cur_session->AddRedableStream(this);
	}
}

void QuicNormalStream::OnFinRead()
{
	ReliableQuicStream::OnFinRead();
	
	QuicNormalSession *cur_session = (QuicNormalSession*)session();
	cur_session->RemoveRedableStream(this);

	CloseWriteSide(); // this stream is used for read only. this will close the stream
}

void QuicNormalStream::WriteOrBufferData(
	StringPiece data,
	bool fin,
	QuicAckListenerInterface* ack_listener)
{
	// this stream is for write only. Now WriteOrBufferData will close the stream
	if (fin) {
		CloseReadSideHack();
	}

	if (((QuicNormalSession*)session())->fifo_session()) {
		// add data len at the beginning (4 bytes)
		uint32_t data_len = data.size();
		std::string data_copy = data.as_string();
		data_copy.insert(0, (char*)&data_len, sizeof(data_len));
		ReliableQuicStream::WriteOrBufferData(data_copy, fin, ack_listener);
	} else {
		ReliableQuicStream::WriteOrBufferData(data, fin, ack_listener);
	}
}

}  // namespace net
