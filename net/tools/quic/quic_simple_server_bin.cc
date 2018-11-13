// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// A binary wrapper for QuicServer.  It listens forever on --port
// (default 6121) until it's killed or ctrl-cd to death.

#if defined(_MSC_VER)
//  Microsoft 
#define EXPORT __declspec(dllexport)
#define IMPORT __declspec(dllimport)
#elif defined(__GNUC__)
//  GCC
#define EXPORT __attribute__((visibility("default")))
#define IMPORT
#endif

#include <iostream>
#include "base/at_exit.h"
#include "base/command_line.h"
#include "base/logging.h"
#include "base/synchronization/waitable_event.h"
#include "base/run_loop.h"
#include "base/strings/string_number_conversions.h"
#include "net/base/ip_address.h"
#include "net/base/ip_endpoint.h"
#include "net/quic/chromium/crypto/proof_source_chromium.h"
#include "net/quic/core/quic_protocol.h"
#include "net/tools/quic/quic_in_memory_cache.h"
#include "net/tools/quic/quic_simple_server.h"
#include "net/tools/quic/quic_dispatcher.h"
#include "net//tools/quic/quic_simple_server_session.h"


// The port the quic server will listen on.
int32_t FLAGS_port = 6121;

std::unique_ptr<net::ProofSource> CreateProofSource(
    const base::FilePath& cert_path,
    const base::FilePath& key_path) {
  std::unique_ptr<net::ProofSourceChromium> proof_source(
      new net::ProofSourceChromium());
  CHECK(proof_source->Initialize(cert_path, key_path, base::FilePath()));
  return std::move(proof_source);
}

extern "C" EXPORT
bool listenSocket(char * local_ip, uint16_t port);
extern "C" EXPORT
size_t listenSocket2(const char * local_ip, uint16_t port);
extern "C" EXPORT
int sendData(size_t connection_id, char * data, bool last_message);
extern "C" EXPORT
int recvData(size_t connection_id, char *buffer, size_t max_len);

net::QuicNormalServer *server;
base::TaskRunner *task_runner;

void server2()
{
	size_t connection_id = listenSocket2("0.0.0.0", 6121);
	
	/*connection_id = listenSocket2("0.0.0.0", 6121);
	sendData(connection_id, "abcabcabc");
	*///sendData(connection_id, "ddddeeee");
	//sendData(connection_id, "ffgghhjj");


	/*char buffer[9700] = { 0 };
	int bytes_received = 0;

	bytes_received = recvData(connection_id, buffer, 9682);
	buffer[bytes_received] = '\0';
	std::cout << "Received: " << buffer << std::endl;*/
	CHECK_NE(-1, sendData(connection_id, "abcabcabc", false));
	CHECK_NE(-1, sendData(connection_id, "abcaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaddde", true));
	//CHECK_NE(-1, sendData(connection_id, "xyzq", true, true));

	//while (true);
	/*bytes_received = recvData(connection_id, buffer, 9682);
	buffer[bytes_received] = '\0';
	std::cout << "Received: " << buffer << std::endl;

	bytes_received = recvData(connection_id, buffer, 9682);
	buffer[bytes_received] = '\0';
	std::cout << "Received: " << buffer << std::endl;*/

	//	sendData(connection_id, "abcabcabc");

	//while (true) {};
	server->data_event()->Wait();
	exit(1);
}

int main(int argc, char* argv[]) {

 

  base::CommandLine::Init(argc, argv);
  base::CommandLine* line = base::CommandLine::ForCurrentProcess();

  logging::LoggingSettings settings;
  settings.logging_dest = logging::LOG_TO_SYSTEM_DEBUG_LOG;
  CHECK(logging::InitLogging(settings));

  server2();

  base::AtExitManager exit_manager;
  base::MessageLoopForIO message_loop;

  if (line->HasSwitch("h") || line->HasSwitch("help")) {
    const char* help_str =
        "Usage: quic_server [options]\n"
        "\n"
        "Options:\n"
        "-h, --help                  show this help message and exit\n"
        "--port=<port>               specify the port to listen on\n"
        "--quic_in_memory_cache_dir  directory containing response data\n"
        "                            to load\n"
        "--certificate_file=<file>   path to the certificate chain\n"
        "--key_file=<file>           path to the pkcs8 private key\n";
    std::cout << help_str;
    exit(0);
  }

  if (line->HasSwitch("quic_in_memory_cache_dir")) {
    net::QuicInMemoryCache::GetInstance()->InitializeFromDirectory(
        line->GetSwitchValueASCII("quic_in_memory_cache_dir"));
  }

  if (line->HasSwitch("port")) {
    if (!base::StringToInt(line->GetSwitchValueASCII("port"), &FLAGS_port)) {
      LOG(ERROR) << "--port must be an integer\n";
      return 1;
    }
  }

  if (!line->HasSwitch("certificate_file")) {
    LOG(ERROR) << "missing --certificate_file";
    return 1;
  }

  if (!line->HasSwitch("key_file")) {
    LOG(ERROR) << "missing --key_file";
    return 1;
  }

  net::IPAddress ip = net::IPAddress::IPv6AllZeros();

  net::QuicConfig config;
  net::QuicSimpleServer server(
      CreateProofSource(line->GetSwitchValuePath("certificate_file"),
                        line->GetSwitchValuePath("key_file")),
      config, net::QuicCryptoServerConfig::ConfigOptions(),
      net::AllSupportedVersions());
  server.SetStrikeRegisterNoStartupPeriod();

  int rc = server.Listen(net::IPEndPoint(ip, FLAGS_port));
  if (rc < 0) {
    return 1;
  }

  base::RunLoop().Run();

  return 0;
}

base::AtExitManager quiqos_exit_manager;
extern "C" EXPORT
 bool listenSocket(char * local_ip, uint16_t port)
{
	std::cout << "In listenSocket" << std::endl;
	base::MessageLoopForIO message_loop;
        char name[10] = {'a','b','\0'};
	char* argv[1] = {name};
	base::CommandLine::Init(1, argv);
	logging::LoggingSettings settings;
	settings.logging_dest = logging::LOG_TO_SYSTEM_DEBUG_LOG;

	net::IPAddress ip_addr;

	if (!ip_addr.AssignFromIPLiteral(std::string(local_ip))) {
		return false;
	}
        
	net::QuicConfig config;
#if defined(OS_POSIX)
	auto certPath = base::BasicStringPiece<std::string>("certs/leaf_cert.pem");
	auto keyPath = base::BasicStringPiece<std::string>("certs/leaf_cert.pkcs8");
#elif defined(OS_WIN)
	auto certPath = base::BasicStringPiece<std::wstring>(L"certs\\leaf_cert.pem");
	auto keyPath = base::BasicStringPiece<std::wstring>(L"certs\\leaf_cert.pkcs8");
#endif

	net::QuicSimpleServer server(
		CreateProofSource(base::FilePath(certPath),
			base::FilePath(keyPath)),
		config, net::QuicCryptoServerConfig::ConfigOptions(),
		net::AllSupportedVersions());
	server.SetStrikeRegisterNoStartupPeriod();
	
	int rc = server.Listen(net::IPEndPoint(ip_addr, port));
	if (rc < 0) {
		return false;
	}

	base::RunLoop().Run();
	return true;
}

extern "C" EXPORT
bool insertData(char* name, char* data)
{
	std::cout << "In insertData" << std::endl;
	net::QuicInMemoryCache::GetInstance()->AddSimpleResponse("quiqos", "/" + std::string(name), 200, std::string(data));
	std::cout << "added data" << std::endl;
	return true;
}

extern "C" EXPORT
bool initFec(uint16_t k, uint16_t m)
{
	auto x = net::kDefaultMaxPacketsPerFecGroup;
	x = 1;

	return true;
}

class SerevrThread
	: public base::PlatformThread::Delegate {
public:
	SerevrThread(const char * _local_ip, uint16_t _port, net::QuicNormalServer **_server, base::WaitableEvent *_session_event, base::TaskRunner **_task_runner) : local_ip(_local_ip), port(_port), server(_server), session_event(_session_event), task_runner(_task_runner) {}
private:
	const char * local_ip;
	uint16_t port;
	net::QuicNormalServer **server;
	base::WaitableEvent *session_event;
	base::TaskRunner **task_runner;

	void ThreadMain() override {
		std::cout << "In listenSocket thread" << std::endl;

		base::MessageLoopForIO message_loop;
		//logging::LoggingSettings settings;
		//settings.logging_dest = logging::LOG_TO_SYSTEM_DEBUG_LOG;

		char name[10] = { 'a','b','\0' };
		char* argv[1] = { name };
		base::CommandLine::Init(1, argv);

		net::IPAddress ip_addr;

		if (!ip_addr.AssignFromIPLiteral(std::string(local_ip))) {
			//return false;
		}

		net::QuicConfig config;
#if defined(OS_POSIX)
		auto certPath = base::BasicStringPiece<std::string>("certs/leaf_cert.pem");
		auto keyPath = base::BasicStringPiece<std::string>("certs/leaf_cert.pkcs8");
#elif defined(OS_WIN)
		auto certPath = base::BasicStringPiece<std::wstring>(L"certs\\leaf_cert.pem");
		auto keyPath = base::BasicStringPiece<std::wstring>(L"certs\\leaf_cert.pkcs8");
#endif

		*server = new net::QuicNormalServer(
			CreateProofSource(base::FilePath(certPath),
				base::FilePath(keyPath)),
			config, net::QuicCryptoServerConfig::ConfigOptions(),
			net::AllSupportedVersions(), 
			session_event,
			false /* is fifo */);

		(*server)->SetStrikeRegisterNoStartupPeriod();

		int rc = (*server)->Listen(net::IPEndPoint(ip_addr, port));
		if (rc < 0) {
			//return false;
		}
		*task_runner = base::ThreadTaskRunnerHandle::Get().get();

		base::RunLoop().Run();
	}
};

void send_data(net::QuicNormalServerSessionBase *session, const char *data, bool last_message)
{
	session->SendData(data, last_message);
}


extern "C" EXPORT
size_t listenSocket2(const char * local_ip, uint16_t port)
{
	static base::WaitableEvent *session_event = new base::WaitableEvent(base::WaitableEvent::ResetPolicy::AUTOMATIC,
		base::WaitableEvent::InitialState::NOT_SIGNALED);
	static base::PlatformThreadHandle thread_handle;
	static SerevrThread delegate(local_ip, port, &server, session_event, &task_runner);
	if (thread_handle.is_null()) {
		base::PlatformThread::Create(0, &delegate, &thread_handle);
	}

	// accept:
	session_event->Wait();
	
	net::QuicDispatcher2::SessionMap session_map = server->dispatcher()->session_map();
	net::QuicDispatcher2::SessionMap::iterator it = session_map.begin();
	while (std::next(it) != session_map.end()) {
		it = std::next(it);
	}

	return it->first;
}

net::QuicNormalServerSessionBase *connectionToSession(size_t connection_id, net::QuicNormalServer *server)
{
	net::QuicDispatcher2::SessionMap session_map = server->dispatcher()->session_map();

	net::QuicDispatcher2::SessionMap::iterator it = session_map.find(connection_id);
	if (it == session_map.end()) {
		return nullptr;
	}
	return it->second;
}

extern "C" EXPORT
int sendData(size_t connection_id, char * data, bool last_message)
{
	net::QuicNormalServerSessionBase *session = connectionToSession(connection_id, server);
	if (session == nullptr) {
		return -1;
	}

	task_runner->PostTask(FROM_HERE, base::Bind(&send_data, session, data, last_message));

	return 0;
}

void reset_ended_streams(net::QuicNormalServerSession *session) {
	session->ResetStreams();
}

extern "C" EXPORT
int recvData(size_t connection_id, char *buffer, size_t max_len)
{
	net::QuicNormalServerSessionBase *session = nullptr;
	int bytes_read = 0;
	do {
		session = connectionToSession(connection_id, server);
		if (session == nullptr) {
			return -1;
		}
		bytes_read = session->ReadData(buffer, max_len);
	} while (bytes_read == 0);

	// maybe not necessary
	//task_runner->PostTask(FROM_HERE, base::Bind(&reset_ended_streams, (net::QuicNormalServerSession*)session));

	return bytes_read;
}

void flush()
{
	base::RunLoop().RunUntilIdle();
	server->data_event()->Signal();
}