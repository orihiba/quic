// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// A toy server, which listens on a specified address for QUIC traffic and
// handles incoming responses.

#ifndef NET_QUIC_TOOLS_QUIC_SIMPLE_SERVER_H_
#define NET_QUIC_TOOLS_QUIC_SIMPLE_SERVER_H_

#include <memory>

#include "base/macros.h"
#include "net/base/io_buffer.h"
#include "net/base/ip_endpoint.h"
#include "net/log/net_log.h"
#include "net/quic/chromium/quic_chromium_alarm_factory.h"
#include "net/quic/chromium/quic_chromium_connection_helper.h"
#include "net/quic/core/crypto/quic_crypto_server_config.h"
#include "net/quic/core/quic_clock.h"
#include "net/quic/core/quic_config.h"
#include "base/synchronization/waitable_event.h"

#include "net/quic/core/reliable_quic_stream.h"

namespace net {

class UDPServerSocket;


class QuicDispatcher;
class QuicDispatcher2;

namespace test {
class QuicSimpleServerPeer;
}  // namespace test

class QuicSimpleServer {
 public:
  QuicSimpleServer(
      std::unique_ptr<ProofSource> proof_source,
      const QuicConfig& config,
      const QuicCryptoServerConfig::ConfigOptions& crypto_config_options,
      const QuicVersionVector& supported_versions);

  virtual ~QuicSimpleServer();

  // Start listening on the specified address. Returns an error code.
  int Listen(const IPEndPoint& address);

  // Server deletion is imminent. Start cleaning up.
  void Shutdown();

  // Start reading on the socket. On asynchronous reads, this registers
  // OnReadComplete as the callback, which will then call StartReading again.
  void StartReading();

  // Called on reads that complete asynchronously. Dispatches the packet and
  // continues the read loop.
  void OnReadComplete(int result);

  void SetStrikeRegisterNoStartupPeriod() {
    crypto_config_.set_strike_register_no_startup_period();
  }

  QuicDispatcher* dispatcher() { return dispatcher_.get(); }

  IPEndPoint server_address() const { return server_address_; }

 private:
  friend class test::QuicSimpleServerPeer;

  // Initialize the internal state of the server.
  void Initialize();

  QuicVersionManager version_manager_;

  // Accepts data from the framer and demuxes clients to sessions.
  std::unique_ptr<QuicDispatcher> dispatcher_;

  // Used by the helper_ to time alarms.
  QuicClock clock_;

  // Used to manage the message loop. Owned by dispatcher_.
  QuicChromiumConnectionHelper* helper_;

  // Used to manage the message loop. Owned by dispatcher_.
  QuicChromiumAlarmFactory* alarm_factory_;

  // Listening socket. Also used for outbound client communication.
  std::unique_ptr<UDPServerSocket> socket_;

  // config_ contains non-crypto parameters that are negotiated in the crypto
  // handshake.
  QuicConfig config_;
  // crypto_config_ contains crypto parameters that are negotiated in the crypto
  // handshake.
  QuicCryptoServerConfig::ConfigOptions crypto_config_options_;
  // crypto_config_ contains crypto parameters for the handshake.
  QuicCryptoServerConfig crypto_config_;

  // The address that the server listens on.
  IPEndPoint server_address_;

  // Keeps track of whether a read is currently in flight, after which
  // OnReadComplete will be called.
  bool read_pending_;

  // The number of iterations of the read loop that have completed synchronously
  // and without posting a new task to the message loop.
  int synchronous_read_count_;

  // The target buffer of the current read.
  scoped_refptr<IOBufferWithSize> read_buffer_;

  // The source address of the current read.
  IPEndPoint client_address_;

  // The log to use for the socket.
  NetLog net_log_;

  base::WeakPtrFactory<QuicSimpleServer> weak_factory_;

  DISALLOW_COPY_AND_ASSIGN(QuicSimpleServer);
};

// --------------------------------------------------------------------------------------------------------------------

class QuicNormalServer {
public:
	QuicNormalServer(
		std::unique_ptr<ProofSource> proof_source,
		const QuicConfig& config,
		const QuicCryptoServerConfig::ConfigOptions& crypto_config_options,
		const QuicVersionVector& supported_versions,
		base::WaitableEvent *session_event,
		bool is_fifo,
		size_t max_delay,
		size_t lost_bytes_delta,
		bool lossless_connection);

	virtual ~QuicNormalServer();

	// Start listening on the specified address. Returns an error code.
	int Listen(const IPEndPoint& address);

	// Server deletion is imminent. Start cleaning up.
	void Shutdown();

	// Start reading on the socket. On asynchronous reads, this registers
	// OnReadComplete as the callback, which will then call StartReading again.
	void StartReading();

	// Called on reads that complete asynchronously. Dispatches the packet and
	// continues the read loop.
	void OnReadComplete(int result);

	void SetStrikeRegisterNoStartupPeriod() {
		crypto_config_.set_strike_register_no_startup_period();
	}

	QuicDispatcher2* dispatcher() { return dispatcher_.get(); }

	IPEndPoint server_address() const { return server_address_; }

	base::WaitableEvent *session_event() { return session_event_; }
	base::WaitableEvent *data_event() { return data_event_; }
	//void OnStreamClose(net::QuicNormalStream *stream);

	bool is_fifo() { return is_fifo_; }
	size_t max_delay() { return max_delay_;  }
	size_t lost_bytes_delta() { return lost_bytes_delta_; }

private:
	friend class test::QuicSimpleServerPeer;

	// Initialize the internal state of the server.
	void Initialize();

	QuicVersionManager version_manager_;

	// Accepts data from the framer and demuxes clients to sessions.
	std::unique_ptr<QuicDispatcher2> dispatcher_;

	// Used by the helper_ to time alarms.
	QuicClock clock_;

	// Used to manage the message loop. Owned by dispatcher_.
	QuicChromiumConnectionHelper* helper_;

	// Used to manage the message loop. Owned by dispatcher_.
	QuicChromiumAlarmFactory* alarm_factory_;

	// Listening socket. Also used for outbound client communication.
	std::unique_ptr<UDPServerSocket> socket_;

	// config_ contains non-crypto parameters that are negotiated in the crypto
	// handshake.
	QuicConfig config_;
	// crypto_config_ contains crypto parameters that are negotiated in the crypto
	// handshake.
	QuicCryptoServerConfig::ConfigOptions crypto_config_options_;
	// crypto_config_ contains crypto parameters for the handshake.
	QuicCryptoServerConfig crypto_config_;

	// The address that the server listens on.
	IPEndPoint server_address_;

	// Keeps track of whether a read is currently in flight, after which
	// OnReadComplete will be called.
	bool read_pending_;

	// The number of iterations of the read loop that have completed synchronously
	// and without posting a new task to the message loop.
	int synchronous_read_count_;

	// The target buffer of the current read.
	scoped_refptr<IOBufferWithSize> read_buffer_;

	// The source address of the current read.
	IPEndPoint client_address_;

	// The log to use for the socket.
	NetLog net_log_;

	base::WaitableEvent *session_event_;
	base::WaitableEvent *data_event_;

	std::vector<std::string> data_arr;

	bool is_fifo_;
	size_t max_delay_;
	size_t lost_bytes_delta_;

	base::WeakPtrFactory<QuicNormalServer> weak_factory_;

	DISALLOW_COPY_AND_ASSIGN(QuicNormalServer);
};
}  // namespace net

#endif  // NET_QUIC_TOOLS_QUIC_SIMPLE_SERVER_H_
