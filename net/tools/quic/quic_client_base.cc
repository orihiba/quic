// Copyright (c) 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/tools/quic/quic_client_base.h"

#include "base/strings/string_number_conversions.h"
#include "net/quic/core/crypto/quic_random.h"
#include "net/quic/core/quic_server_id.h"
#include "net/quic/core/spdy_utils.h"

using base::StringPiece;
using base::StringToInt;
using std::string;
using std::vector;

namespace net {

void QuicClientBase::ClientQuicDataToResend::Resend() {
  client_->SendRequest(*headers_, body_, fin_);
  headers_ = nullptr;
}

QuicClientBase::QuicDataToResend::QuicDataToResend(
    std::unique_ptr<SpdyHeaderBlock> headers,
    StringPiece body,
    bool fin)
    : headers_(std::move(headers)), body_(body), fin_(fin) {}

QuicClientBase::QuicDataToResend::~QuicDataToResend() {}

QuicClientBase::QuicClientBase(const QuicServerId& server_id,
	const QuicVersionVector& supported_versions,
	const QuicConfig& config,
	QuicConnectionHelperInterface* helper,
	QuicAlarmFactory* alarm_factory,
	std::unique_ptr<ProofVerifier> proof_verifier)
	: server_id_(server_id),
	initialized_(false),
	local_port_(0),
	config_(config),
	crypto_config_(std::move(proof_verifier)),
	helper_(helper),
	alarm_factory_(alarm_factory),
	supported_versions_(supported_versions),
	initial_max_packet_length_(0),
	num_stateless_rejects_received_(0),
	num_sent_client_hellos_(0),
	connection_error_(QUIC_NO_ERROR),
	connected_or_attempting_connect_(false),
	store_response_(false),
      latest_response_code_(-1),
	wanted_active_requests_(0) {}

QuicClientBase::~QuicClientBase() {}

void QuicClientBase::OnClose(QuicSpdyStream* stream) {
  DCHECK(stream != nullptr);
  QuicSpdyClientStream* client_stream =
      static_cast<QuicSpdyClientStream*>(stream);

  const SpdyHeaderBlock& response_headers = client_stream->response_headers();
  if (response_listener_ != nullptr) {
    response_listener_->OnCompleteResponse(stream->id(), response_headers,
                                           client_stream->data());
  }

  // Store response headers and body.
  if (store_response_) {
    auto status = response_headers.find(":status");
    if (status == response_headers.end() ||
        !StringToInt(status->second, &latest_response_code_)) {
      LOG(ERROR) << "Invalid response headers";
    }
    latest_response_headers_ = response_headers.DebugString();
    latest_response_header_block_ = response_headers.Clone();
    latest_response_body_ = client_stream->data();
    latest_response_trailers_ =
        client_stream->received_trailers().DebugString();
  }
}

bool QuicClientBase::Initialize() {
  num_sent_client_hellos_ = 0;
  num_stateless_rejects_received_ = 0;
  connection_error_ = QUIC_NO_ERROR;
  connected_or_attempting_connect_ = false;

  // If an initial flow control window has not explicitly been set, then use the
  // same values that Chrome uses.
  const uint32_t kSessionMaxRecvWindowSize = 15 * 1024 * 1024;  // 15 MB
  const uint32_t kStreamMaxRecvWindowSize = 6 * 1024 * 1024;    //  6 MB
  if (config()->GetInitialStreamFlowControlWindowToSend() ==
      kMinimumFlowControlSendWindow) {
    config()->SetInitialStreamFlowControlWindowToSend(kStreamMaxRecvWindowSize);
  }
  if (config()->GetInitialSessionFlowControlWindowToSend() ==
      kMinimumFlowControlSendWindow) {
    config()->SetInitialSessionFlowControlWindowToSend(
        kSessionMaxRecvWindowSize);
  }

  if (!CreateUDPSocketAndBind(server_address_, bind_to_address_, local_port_)) {
    return false;
  }

  initialized_ = true;
  return true;
}

bool QuicClientBase::Connect() {
  // Attempt multiple connects until the maximum number of client hellos have
  // been sent.
  while (!connected() &&
         GetNumSentClientHellos() <= QuicCryptoClientStream::kMaxClientHellos) {
    StartConnect();
    while (EncryptionBeingEstablished()) {
      WaitForEvents();
    }
    if (FLAGS_enable_quic_stateless_reject_support && connected()) {
      // Resend any previously queued data.
      ResendSavedData();
    }
    if (session() != nullptr &&
        session()->error() != QUIC_CRYPTO_HANDSHAKE_STATELESS_REJECT) {
      // We've successfully created a session but we're not connected, and there
      // is no stateless reject to recover from.  Give up trying.
      break;
    }
  }
  if (!connected() &&
      GetNumSentClientHellos() > QuicCryptoClientStream::kMaxClientHellos &&
      session() != nullptr &&
      session()->error() == QUIC_CRYPTO_HANDSHAKE_STATELESS_REJECT) {
    // The overall connection failed due too many stateless rejects.
    set_connection_error(QUIC_CRYPTO_TOO_MANY_REJECTS);
  }
  return session()->connection()->connected();
}

void QuicClientBase::StartConnect() {
  DCHECK(initialized_);
  DCHECK(!connected());

  QuicPacketWriter* writer = CreateQuicPacketWriter();

  if (connected_or_attempting_connect()) {
    // If the last error was not a stateless reject, then the queued up data
    // does not need to be resent.
    if (session()->error() != QUIC_CRYPTO_HANDSHAKE_STATELESS_REJECT) {
      ClearDataToResend();
    }
    // Before we destroy the last session and create a new one, gather its stats
    // and update the stats for the overall connection.
    UpdateStats();
  }

  CreateQuicClientSession(new QuicConnection(
      GetNextConnectionId(), server_address(), helper(), alarm_factory(),
      writer,
      /* owns_writer= */ false, Perspective::IS_CLIENT, supported_versions()));

  // Reset |writer()| after |session()| so that the old writer outlives the old
  // session.
  set_writer(writer);
  session()->Initialize();
  session()->CryptoConnect();
  set_connected_or_attempting_connect(true);
}

void QuicClientBase::Disconnect() {
  DCHECK(initialized_);

  if (connected()) {
    session()->connection()->CloseConnection(
        QUIC_PEER_GOING_AWAY, "Client disconnecting",
        ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
  }

  ClearDataToResend();

  CleanUpAllUDPSockets();

  initialized_ = false;
}

ProofVerifier* QuicClientBase::proof_verifier() const {
  return crypto_config_.proof_verifier();
}

QuicClientSession* QuicClientBase::CreateQuicClientSession(
    QuicConnection* connection) {
  session_.reset(new QuicClientSession(config_, connection, server_id_,
                                       &crypto_config_, &push_promise_index_));
  if (initial_max_packet_length_ != 0) {
    session()->connection()->SetMaxPacketLength(initial_max_packet_length_);
  }
  return session_.get();
}

bool QuicClientBase::EncryptionBeingEstablished() {
  return !session_->IsEncryptionEstablished() &&
         session_->connection()->connected();
}

void QuicClientBase::SendRequest(const SpdyHeaderBlock& headers,
                                 StringPiece body,
                                 bool fin) {
  QuicClientPushPromiseIndex::TryHandle* handle;
  QuicAsyncStatus rv = push_promise_index()->Try(headers, this, &handle);
  if (rv == QUIC_SUCCESS)
    return;

  if (rv == QUIC_PENDING) {
    // May need to retry request if asynchronous rendezvous fails.
    AddPromiseDataToResend(headers, body, fin);
    return;
  }

  QuicSpdyClientStream* stream = CreateReliableClientStream();
  if (stream == nullptr) {
    QUIC_BUG << "stream creation failed!";
    return;
  }
  stream->SendRequest(headers.Clone(), body, fin);
  // Record this in case we need to resend.
  MaybeAddDataToResend(headers, body, fin);
}

void QuicClientBase::WriteOrBufferData(base::StringPiece data,
	bool fin)
{
	void *a = this;
	a = a;
	QuicSpdyClientStream* stream = CreateReliableClientStream();
	if (stream == nullptr) {
		QUIC_BUG << "stream creation failed!";
		return;
	}
	stream->WriteOrBufferData(data, fin, nullptr);
	// Record this in case we need to resend.
	std::unique_ptr<QuicDataToResend> data_to_resend(
		new ClientQuicDataToResend(nullptr, data, fin, this));
	MaybeAddQuicDataToResend(std::move(data_to_resend));
}

void QuicClientBase::SendRequestAndWaitForResponse(
    const SpdyHeaderBlock& headers,
    StringPiece body,
    bool fin) {
  SendRequest(headers, body, fin);
  while (WaitForEvents()) {
  }
}

void QuicClientBase::SendRequestsAndWaitForResponse(
    const vector<string>& url_list) {
	wanted_active_requests_ = url_list.size(); // init number of requests
  for (size_t i = 0; i < url_list.size(); ++i) {
    SpdyHeaderBlock headers;
    if (!SpdyUtils::PopulateHeaderBlockFromUrl(url_list[i], &headers)) {
      QUIC_BUG << "Unable to create request";
      continue;
    }
    SendRequest(headers, "", true);
  }
  //while (WaitForEvents()) {
  while (WaitForEvent()) {
  }
}

QuicSpdyClientStream* QuicClientBase::CreateReliableClientStream() {
  if (!connected()) {
    return nullptr;
  }

  QuicSpdyClientStream* stream =
      session_->CreateOutgoingDynamicStream(kDefaultPriority);
  if (stream) {
    stream->set_visitor(this);
  }
  return stream;
}

bool QuicClientBase::WaitForEvents() {
  DCHECK(connected());

  RunEventLoop();

  DCHECK(session() != nullptr);
  if (!connected() &&
      session()->error() == QUIC_CRYPTO_HANDSHAKE_STATELESS_REJECT) {
    DCHECK(FLAGS_enable_quic_stateless_reject_support);
    DVLOG(1) << "Detected stateless reject while waiting for events.  "
             << "Attempting to reconnect.";
    Connect();
  }

  return session()->num_active_requests() != 0;
}

void QuicClientBase::WaitForNextEvent()
{
	while (WaitForEvent()) {}
}

bool QuicClientBase::WaitForEvent() {
	DCHECK(connected());

	RunEventLoop();

	DCHECK(session() != nullptr);
	if (!connected() &&
		session()->error() == QUIC_CRYPTO_HANDSHAKE_STATELESS_REJECT) {
		DCHECK(FLAGS_enable_quic_stateless_reject_support);
		DVLOG(1) << "Detected stateless reject while waiting for events.  "
			<< "Attempting to reconnect.";
		Connect();
	}

	if (wanted_active_requests_ == 0)
	{
		return false;
	}
	
	if (session()->num_active_requests() < wanted_active_requests_)
	{
		// some request completed
		wanted_active_requests_--;
		return false;
	}
	return true;
}

bool QuicClientBase::MigrateSocket(const IPAddress& new_host) {
  if (!connected()) {
    return false;
  }

  CleanUpAllUDPSockets();

  set_bind_to_address(new_host);
  if (!CreateUDPSocketAndBind(server_address_, bind_to_address_, local_port_)) {
    return false;
  }

  session()->connection()->SetSelfAddress(GetLatestClientAddress());

  QuicPacketWriter* writer = CreateQuicPacketWriter();
  set_writer(writer);
  session()->connection()->SetQuicPacketWriter(writer, false);

  return true;
}

void QuicClientBase::WaitForStreamToClose(QuicStreamId id) {
  DCHECK(connected());

  while (connected() && !session_->IsClosedStream(id)) {
    WaitForEvents();
  }
}

void QuicClientBase::WaitForCryptoHandshakeConfirmed() {
  DCHECK(connected());

  while (connected() && !session_->IsCryptoHandshakeConfirmed()) {
    WaitForEvents();
  }
}

bool QuicClientBase::connected() const {
  return session_.get() && session_->connection() &&
         session_->connection()->connected();
}

bool QuicClientBase::goaway_received() const {
  return session_ != nullptr && session_->goaway_received();
}

int QuicClientBase::GetNumSentClientHellos() {
  // If we are not actively attempting to connect, the session object
  // corresponds to the previous connection and should not be used.
  const int current_session_hellos = !connected_or_attempting_connect_
                                         ? 0
                                         : session_->GetNumSentClientHellos();
  return num_sent_client_hellos_ + current_session_hellos;
}

void QuicClientBase::UpdateStats() {
  num_sent_client_hellos_ += session()->GetNumSentClientHellos();
  if (session()->error() == QUIC_CRYPTO_HANDSHAKE_STATELESS_REJECT) {
    ++num_stateless_rejects_received_;
  }
}

int QuicClientBase::GetNumReceivedServerConfigUpdates() {
  // If we are not actively attempting to connect, the session object
  // corresponds to the previous connection and should not be used.
  // We do not need to take stateless rejects into account, since we
  // don't expect any scup messages to be sent during a
  // statelessly-rejected connection.
  return !connected_or_attempting_connect_
             ? 0
             : session_->GetNumReceivedServerConfigUpdates();
}

QuicErrorCode QuicClientBase::connection_error() const {
  // Return the high-level error if there was one.  Otherwise, return the
  // connection error from the last session.
  if (connection_error_ != QUIC_NO_ERROR) {
    return connection_error_;
  }
  if (session_ == nullptr) {
    return QUIC_NO_ERROR;
  }
  return session_->error();
}

QuicConnectionId QuicClientBase::GetNextConnectionId() {
  QuicConnectionId server_designated_id = GetNextServerDesignatedConnectionId();
  return server_designated_id ? server_designated_id
                              : GenerateNewConnectionId();
}

QuicConnectionId QuicClientBase::GetNextServerDesignatedConnectionId() {
  QuicCryptoClientConfig::CachedState* cached =
      crypto_config_.LookupOrCreate(server_id_);
  // If the cached state indicates that we should use a server-designated
  // connection ID, then return that connection ID.
  CHECK(cached != nullptr) << "QuicClientCryptoConfig::LookupOrCreate returned "
                           << "unexpected nullptr.";
  return cached->has_server_designated_connection_id()
             ? cached->GetNextServerDesignatedConnectionId()
             : 0;
}

QuicConnectionId QuicClientBase::GenerateNewConnectionId() {
  return QuicRandom::GetInstance()->RandUint64();
}

void QuicClientBase::MaybeAddDataToResend(const SpdyHeaderBlock& headers,
                                          StringPiece body,
                                          bool fin) {
  if (!FLAGS_enable_quic_stateless_reject_support) {
    return;
  }

  if (session()->IsCryptoHandshakeConfirmed()) {
    // The handshake is confirmed.  No need to continue saving requests to
    // resend.
    data_to_resend_on_connect_.clear();
    return;
  }

  // The handshake is not confirmed.  Push the data onto the queue of data to
  // resend if statelessly rejected.
  std::unique_ptr<SpdyHeaderBlock> new_headers(
      new SpdyHeaderBlock(headers.Clone()));
  std::unique_ptr<QuicDataToResend> data_to_resend(
      new ClientQuicDataToResend(std::move(new_headers), body, fin, this));
  MaybeAddQuicDataToResend(std::move(data_to_resend));
}

void QuicClientBase::MaybeAddQuicDataToResend(
    std::unique_ptr<QuicDataToResend> data_to_resend) {
  data_to_resend_on_connect_.push_back(std::move(data_to_resend));
}

void QuicClientBase::ClearDataToResend() {
  data_to_resend_on_connect_.clear();
}

void QuicClientBase::ResendSavedData() {
  // Calling Resend will re-enqueue the data, so swap out
  //  data_to_resend_on_connect_ before iterating.
  vector<std::unique_ptr<QuicDataToResend>> old_data;
  old_data.swap(data_to_resend_on_connect_);
  for (const auto& data : old_data) {
    data->Resend();
  }
}

void QuicClientBase::AddPromiseDataToResend(const SpdyHeaderBlock& headers,
                                            StringPiece body,
                                            bool fin) {
  std::unique_ptr<SpdyHeaderBlock> new_headers(
      new SpdyHeaderBlock(headers.Clone()));
  push_promise_data_to_resend_.reset(
      new ClientQuicDataToResend(std::move(new_headers), body, fin, this));
}

bool QuicClientBase::CheckVary(const SpdyHeaderBlock& client_request,
                               const SpdyHeaderBlock& promise_request,
                               const SpdyHeaderBlock& promise_response) {
  return true;
}

void QuicClientBase::OnRendezvousResult(QuicSpdyStream* stream) {
  std::unique_ptr<ClientQuicDataToResend> data_to_resend =
      std::move(push_promise_data_to_resend_);
  if (stream) {
    stream->set_visitor(this);
    stream->OnDataAvailable();
  } else if (data_to_resend.get()) {
    data_to_resend->Resend();
  }
}

size_t QuicClientBase::latest_response_code() const {
  QUIC_BUG_IF(!store_response_) << "Response not stored!";
  return latest_response_code_;
}

const string& QuicClientBase::latest_response_headers() const {
  QUIC_BUG_IF(!store_response_) << "Response not stored!";
  return latest_response_headers_;
}

const SpdyHeaderBlock& QuicClientBase::latest_response_header_block() const {
  QUIC_BUG_IF(!store_response_) << "Response not stored!";
  return latest_response_header_block_;
}

const string& QuicClientBase::latest_response_body() const {
  QUIC_BUG_IF(!store_response_) << "Response not stored!";
  return latest_response_body_;
}

const string& QuicClientBase::latest_response_trailers() const {
  QUIC_BUG_IF(!store_response_) << "Response not stored!";
  return latest_response_trailers_;
}

// -----------------------------------------------------------------------------------------------

//void QuicNormalClientBase::ClientQuicDataToResend::Resend() {
//	client_->SendRequest(*headers_, body_, fin_);
//	headers_ = nullptr;
//}

QuicNormalClientBase::QuicDataToResend::QuicDataToResend(
	std::unique_ptr<SpdyHeaderBlock> headers,
	StringPiece body,
	bool fin)
	: headers_(std::move(headers)), body_(body), fin_(fin) {}

QuicNormalClientBase::QuicDataToResend::~QuicDataToResend() {}

QuicNormalClientBase::QuicNormalClientBase(const QuicServerId& server_id,
	const QuicVersionVector& supported_versions,
	const QuicConfig& config,
	QuicConnectionHelperInterface* helper,
	QuicAlarmFactory* alarm_factory,
	std::unique_ptr<ProofVerifier> proof_verifier)
	: server_id_(server_id),
	initialized_(false),
	local_port_(0),
	config_(config),
	crypto_config_(std::move(proof_verifier)),
	helper_(helper),
	alarm_factory_(alarm_factory),
	supported_versions_(supported_versions),
	initial_max_packet_length_(0),
	num_stateless_rejects_received_(0),
	num_sent_client_hellos_(0),
	connection_error_(QUIC_NO_ERROR),
	connected_or_attempting_connect_(false),
	store_response_(false),
	latest_response_code_(-1),
	wanted_active_requests_(0) {}

QuicNormalClientBase::~QuicNormalClientBase() {}

void QuicNormalClientBase::OnClose(QuicNormalStream* stream) {
	//DCHECK(stream != nullptr);
	//QuicNormalStream* client_stream =
	//	static_cast<QuicNormalStream*>(stream);

	//const SpdyHeaderBlock& response_headers = client_stream->response_headers();
	//if (response_listener_ != nullptr) {
	//	response_listener_->OnCompleteResponse(stream->id(), response_headers,
	//		client_stream->data());
	//}

	//// Store response headers and body.
	//if (store_response_) {
	//	auto status = response_headers.find(":status");
	//	if (status == response_headers.end() ||
	//		!StringToInt(status->second, &latest_response_code_)) {
	//		LOG(ERROR) << "Invalid response headers";
	//	}
	//	latest_response_headers_ = response_headers.DebugString();
	//	latest_response_header_block_ = response_headers.Clone();
	//	latest_response_body_ = client_stream->data();
	//	latest_response_trailers_ =
	//		client_stream->received_trailers().DebugString();
	//}
}

bool QuicNormalClientBase::Initialize() {
	num_sent_client_hellos_ = 0;
	num_stateless_rejects_received_ = 0;
	connection_error_ = QUIC_NO_ERROR;
	connected_or_attempting_connect_ = false;

	// If an initial flow control window has not explicitly been set, then use the
	// same values that Chrome uses.
	const uint32_t kSessionMaxRecvWindowSize = 15 * 1024 * 1024;  // 15 MB
	const uint32_t kStreamMaxRecvWindowSize = 6 * 1024 * 1024;    //  6 MB
	if (config()->GetInitialStreamFlowControlWindowToSend() ==
		kMinimumFlowControlSendWindow) {
		config()->SetInitialStreamFlowControlWindowToSend(kStreamMaxRecvWindowSize);
	}
	if (config()->GetInitialSessionFlowControlWindowToSend() ==
		kMinimumFlowControlSendWindow) {
		config()->SetInitialSessionFlowControlWindowToSend(
			kSessionMaxRecvWindowSize);
	}

	if (!CreateUDPSocketAndBind(server_address_, bind_to_address_, local_port_)) {
		return false;
	}

	initialized_ = true;
	return true;
}

bool QuicNormalClientBase::Connect() {
	// Attempt multiple connects until the maximum number of client hellos have
	// been sent.
	while (!connected() &&
		GetNumSentClientHellos() <= QuicCryptoClientStream::kMaxClientHellos) {
		StartConnect();
		while (EncryptionBeingEstablished()) {
			WaitForEvents();
		}
		//if (FLAGS_enable_quic_stateless_reject_support && connected()) {
		//	// Resend any previously queued data.
		//	ResendSavedData();
		//}
		if (session() != nullptr &&
			session()->error() != QUIC_CRYPTO_HANDSHAKE_STATELESS_REJECT) {
			// We've successfully created a session but we're not connected, and there
			// is no stateless reject to recover from.  Give up trying.
			break;
		}
	}
	if (!connected() &&
		GetNumSentClientHellos() > QuicCryptoClientStream::kMaxClientHellos &&
		session() != nullptr &&
		session()->error() == QUIC_CRYPTO_HANDSHAKE_STATELESS_REJECT) {
		// The overall connection failed due too many stateless rejects.
		set_connection_error(QUIC_CRYPTO_TOO_MANY_REJECTS);
	}
	return session()->connection()->connected();
}

void QuicNormalClientBase::StartConnect() {
	DCHECK(initialized_);
	DCHECK(!connected());

	QuicPacketWriter* writer = CreateQuicPacketWriter();

	if (connected_or_attempting_connect()) {
		// If the last error was not a stateless reject, then the queued up data
		// does not need to be resent.
		if (session()->error() != QUIC_CRYPTO_HANDSHAKE_STATELESS_REJECT) {
			ClearDataToResend();
		}
		// Before we destroy the last session and create a new one, gather its stats
		// and update the stats for the overall connection.
		UpdateStats();
	}

	CreateQuicClientSession(new QuicConnection(
		GetNextConnectionId(), server_address(), helper(), alarm_factory(),
		writer,
		/* owns_writer= */ false, Perspective::IS_CLIENT, supported_versions()));

	// Reset |writer()| after |session()| so that the old writer outlives the old
	// session.
	set_writer(writer);
	session()->Initialize();
	session()->CryptoConnect();
	set_connected_or_attempting_connect(true);
}

void QuicNormalClientBase::Disconnect() {
	DCHECK(initialized_);

	if (connected()) {
		session()->connection()->CloseConnection(
			QUIC_PEER_GOING_AWAY, "Client disconnecting",
			ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
	}

	ClearDataToResend();

	CleanUpAllUDPSockets();

	initialized_ = false;
}

ProofVerifier* QuicNormalClientBase::proof_verifier() const {
	return crypto_config_.proof_verifier();
}

QuicNormalClientSession* QuicNormalClientBase::CreateQuicClientSession(
	QuicConnection* connection) {
	session_.reset(new QuicNormalClientSession(config_, connection, server_id_,
		&crypto_config_, &push_promise_index_));
	if (initial_max_packet_length_ != 0) {
		session()->connection()->SetMaxPacketLength(initial_max_packet_length_);
	}
	return session_.get();
}

bool QuicNormalClientBase::EncryptionBeingEstablished() {
	return !session_->IsEncryptionEstablished() &&
		session_->connection()->connected();
}

void QuicNormalClientBase::WriteOrBufferData(base::StringPiece data,
	bool fin)
{
	void *a = this;
	a = a;
	QuicNormalStream* stream = CreateReliableClientStream();
	if (stream == nullptr) {
		QUIC_BUG << "stream creation failed!";
		return;
	}
	stream->WriteOrBufferData(data, fin, nullptr);
	// Record this in case we need to resend.
	std::unique_ptr<QuicDataToResend> data_to_resend(
		new ClientQuicDataToResend(nullptr, data, fin, this));
	MaybeAddQuicDataToResend(std::move(data_to_resend));
}

//void QuicNormalClientBase::SendRequestAndWaitForResponse(
//	const SpdyHeaderBlock& headers,
//	StringPiece body,
//	bool fin) {
//	SendRequest(headers, body, fin);
//	while (WaitForEvents()) {
//	}
//}

//void QuicNormalClientBase::SendRequestsAndWaitForResponse(
//	const vector<string>& url_list) {
//	wanted_active_requests_ = url_list.size(); // init number of requests
//	for (size_t i = 0; i < url_list.size(); ++i) {
//		SpdyHeaderBlock headers;
//		if (!SpdyUtils::PopulateHeaderBlockFromUrl(url_list[i], &headers)) {
//			QUIC_BUG << "Unable to create request";
//			continue;
//		}
//		SendRequest(headers, "", true);
//	}
//	//while (WaitForEvents()) {
//	while (WaitForEvent()) {
//	}
//}

QuicNormalStream* QuicNormalClientBase::CreateReliableClientStream() {
	if (!connected()) {
		return nullptr;
	}

	QuicNormalStream* stream =
		session_->CreateOutgoingDynamicStream(kDefaultPriority);
	if (stream) {
		stream->set_visitor(this);
	}
	return stream;
}

bool QuicNormalClientBase::WaitForEvents() {
	DCHECK(connected());

	RunEventLoop();

	DCHECK(session() != nullptr);
	if (!connected() &&
		session()->error() == QUIC_CRYPTO_HANDSHAKE_STATELESS_REJECT) {
		DCHECK(FLAGS_enable_quic_stateless_reject_support);
		DVLOG(1) << "Detected stateless reject while waiting for events.  "
			<< "Attempting to reconnect.";
		Connect();
	}

	return session()->num_active_requests() != 0;
}

void QuicNormalClientBase::WaitForNextEvent()
{
	while (WaitForEvent()) {}
}

bool QuicNormalClientBase::WaitForEvent() {
	DCHECK(connected());

	RunEventLoop();

	DCHECK(session() != nullptr);
	if (!connected() &&
		session()->error() == QUIC_CRYPTO_HANDSHAKE_STATELESS_REJECT) {
		DCHECK(FLAGS_enable_quic_stateless_reject_support);
		DVLOG(1) << "Detected stateless reject while waiting for events.  "
			<< "Attempting to reconnect.";
		Connect();
	}

	if (wanted_active_requests_ == 0)
	{
		return false;
	}

	if (session()->num_active_requests() < wanted_active_requests_)
	{
		// some request completed
		wanted_active_requests_--;
		return false;
	}
	return true;
}

bool QuicNormalClientBase::MigrateSocket(const IPAddress& new_host) {
	if (!connected()) {
		return false;
	}

	CleanUpAllUDPSockets();

	set_bind_to_address(new_host);
	if (!CreateUDPSocketAndBind(server_address_, bind_to_address_, local_port_)) {
		return false;
	}

	session()->connection()->SetSelfAddress(GetLatestClientAddress());

	QuicPacketWriter* writer = CreateQuicPacketWriter();
	set_writer(writer);
	session()->connection()->SetQuicPacketWriter(writer, false);

	return true;
}

void QuicNormalClientBase::WaitForStreamToClose(QuicStreamId id) {
	DCHECK(connected());

	while (connected() && !session_->IsClosedStream(id)) {
		WaitForEvents();
	}
}

void QuicNormalClientBase::WaitForCryptoHandshakeConfirmed() {
	DCHECK(connected());

	while (connected() && !session_->IsCryptoHandshakeConfirmed()) {
		WaitForEvents();
	}
}

bool QuicNormalClientBase::connected() const {
	return session_.get() && session_->connection() &&
		session_->connection()->connected();
}

bool QuicNormalClientBase::goaway_received() const {
	return session_ != nullptr && session_->goaway_received();
}

int QuicNormalClientBase::GetNumSentClientHellos() {
	// If we are not actively attempting to connect, the session object
	// corresponds to the previous connection and should not be used.
	const int current_session_hellos = !connected_or_attempting_connect_
		? 0
		: session_->GetNumSentClientHellos();
	return num_sent_client_hellos_ + current_session_hellos;
}

void QuicNormalClientBase::UpdateStats() {
	num_sent_client_hellos_ += session()->GetNumSentClientHellos();
	if (session()->error() == QUIC_CRYPTO_HANDSHAKE_STATELESS_REJECT) {
		++num_stateless_rejects_received_;
	}
}

int QuicNormalClientBase::GetNumReceivedServerConfigUpdates() {
	// If we are not actively attempting to connect, the session object
	// corresponds to the previous connection and should not be used.
	// We do not need to take stateless rejects into account, since we
	// don't expect any scup messages to be sent during a
	// statelessly-rejected connection.
	return !connected_or_attempting_connect_
		? 0
		: session_->GetNumReceivedServerConfigUpdates();
}

QuicErrorCode QuicNormalClientBase::connection_error() const {
	// Return the high-level error if there was one.  Otherwise, return the
	// connection error from the last session.
	if (connection_error_ != QUIC_NO_ERROR) {
		return connection_error_;
	}
	if (session_ == nullptr) {
		return QUIC_NO_ERROR;
	}
	return session_->error();
}

QuicConnectionId QuicNormalClientBase::GetNextConnectionId() {
	QuicConnectionId server_designated_id = GetNextServerDesignatedConnectionId();
	return server_designated_id ? server_designated_id
		: GenerateNewConnectionId();
}

QuicConnectionId QuicNormalClientBase::GetNextServerDesignatedConnectionId() {
	QuicCryptoClientConfig::CachedState* cached =
		crypto_config_.LookupOrCreate(server_id_);
	// If the cached state indicates that we should use a server-designated
	// connection ID, then return that connection ID.
	CHECK(cached != nullptr) << "QuicClientCryptoConfig::LookupOrCreate returned "
		<< "unexpected nullptr.";
	return cached->has_server_designated_connection_id()
		? cached->GetNextServerDesignatedConnectionId()
		: 0;
}

QuicConnectionId QuicNormalClientBase::GenerateNewConnectionId() {
	return QuicRandom::GetInstance()->RandUint64();
}

void QuicNormalClientBase::MaybeAddDataToResend(const SpdyHeaderBlock& headers,
	StringPiece body,
	bool fin) {
	if (!FLAGS_enable_quic_stateless_reject_support) {
		return;
	}

	if (session()->IsCryptoHandshakeConfirmed()) {
		// The handshake is confirmed.  No need to continue saving requests to
		// resend.
		data_to_resend_on_connect_.clear();
		return;
	}

	// The handshake is not confirmed.  Push the data onto the queue of data to
	// resend if statelessly rejected.
	std::unique_ptr<SpdyHeaderBlock> new_headers(
		new SpdyHeaderBlock(headers.Clone()));
	std::unique_ptr<QuicDataToResend> data_to_resend(
		new ClientQuicDataToResend(std::move(new_headers), body, fin, this));
	MaybeAddQuicDataToResend(std::move(data_to_resend));
}

void QuicNormalClientBase::MaybeAddQuicDataToResend(
	std::unique_ptr<QuicDataToResend> data_to_resend) {
	data_to_resend_on_connect_.push_back(std::move(data_to_resend));
}

void QuicNormalClientBase::ClearDataToResend() {
	data_to_resend_on_connect_.clear();
}

//void QuicNormalClientBase::ResendSavedData() {
//	// Calling Resend will re-enqueue the data, so swap out
//	//  data_to_resend_on_connect_ before iterating.
//	vector<std::unique_ptr<QuicDataToResend>> old_data;
//	old_data.swap(data_to_resend_on_connect_);
//	for (const auto& data : old_data) {
//		data->Resend();
//	}
//}

void QuicNormalClientBase::AddPromiseDataToResend(const SpdyHeaderBlock& headers,
	StringPiece body,
	bool fin) {
	std::unique_ptr<SpdyHeaderBlock> new_headers(
		new SpdyHeaderBlock(headers.Clone()));
	push_promise_data_to_resend_.reset(
		new ClientQuicDataToResend(std::move(new_headers), body, fin, this));
}

bool QuicNormalClientBase::CheckVary(const SpdyHeaderBlock& client_request,
	const SpdyHeaderBlock& promise_request,
	const SpdyHeaderBlock& promise_response) {
	return true;
}

void QuicNormalClientBase::OnRendezvousResult(QuicNormalStream* stream) {
	std::unique_ptr<ClientQuicDataToResend> data_to_resend =
		std::move(push_promise_data_to_resend_);
	if (stream) {
		stream->set_visitor(this);
		stream->OnDataAvailable();
	}
	/*else if (data_to_resend.get()) {
		data_to_resend->Resend();
	}*/
}

size_t QuicNormalClientBase::latest_response_code() const {
	QUIC_BUG_IF(!store_response_) << "Response not stored!";
	return latest_response_code_;
}

const string& QuicNormalClientBase::latest_response_headers() const {
	QUIC_BUG_IF(!store_response_) << "Response not stored!";
	return latest_response_headers_;
}

const SpdyHeaderBlock& QuicNormalClientBase::latest_response_header_block() const {
	QUIC_BUG_IF(!store_response_) << "Response not stored!";
	return latest_response_header_block_;
}

const string& QuicNormalClientBase::latest_response_body() const {
	QUIC_BUG_IF(!store_response_) << "Response not stored!";
	return latest_response_body_;
}

const string& QuicNormalClientBase::latest_response_trailers() const {
	QUIC_BUG_IF(!store_response_) << "Response not stored!";
	return latest_response_trailers_;
}


}  // namespace net
