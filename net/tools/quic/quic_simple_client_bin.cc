// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// A binary wrapper for QuicClient.
// Connects to a host using QUIC, sends a request to the provided URL, and
// displays the response.
//
// Some usage examples:
//
//   TODO(rtenneti): make --host optional by getting IP Address of URL's host.
//
//   Get IP address of the www.google.com
//   IP=`dig www.google.com +short | head -1`
//
// Standard request/response:
//   quic_client http://www.google.com  --host=${IP}
//   quic_client http://www.google.com --quiet  --host=${IP}
//   quic_client https://www.google.com --port=443  --host=${IP}
//
// Use a specific version:
//   quic_client http://www.google.com --quic_version=23  --host=${IP}
//
// Send a POST instead of a GET:
//   quic_client http://www.google.com --body="this is a POST body" --host=${IP}
//
// Append additional headers to the request:
//   quic_client http://www.google.com  --host=${IP}
//               --headers="Header-A: 1234; Header-B: 5678"
//
// Connect to a host different to the URL being requested:
//   Get IP address of the www.google.com
//   IP=`dig www.google.com +short | head -1`
//   quic_client mail.google.com --host=${IP}
//
// Try to connect to a host which does not speak QUIC:
//   Get IP address of the www.example.com
//   IP=`dig www.example.com +short | head -1`
//   quic_client http://www.example.com --host=${IP}

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
#include "base/message_loop/message_loop.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_split.h"
#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "base/files/file_util.h"
#include "net/base/ip_address.h"
#include "net/base/ip_endpoint.h"
#include "net/base/net_errors.h"
#include "net/base/privacy_mode.h"
#include "net/cert/cert_verifier.h"
#include "net/cert/multi_log_ct_verifier.h"
#include "net/http/http_request_info.h"
#include "net/http/transport_security_state.h"
#include "net/quic/chromium/crypto/proof_verifier_chromium.h"
#include "net/quic/core/quic_protocol.h"
#include "net/quic/core/quic_server_id.h"
#include "net/quic/core/quic_utils.h"
#include "net/spdy/spdy_header_block.h"
#include "net/spdy/spdy_http_utils.h"
#include "net/tools/quic/quic_simple_client.h"
#include "net/tools/quic/synchronous_host_resolver.h"
#include "url/gurl.h"

#include "net//tools/quic/quicr_api.h"

using base::StringPiece;
using net::CertVerifier;
using net::CTPolicyEnforcer;
using net::CTVerifier;
using net::MultiLogCTVerifier;
using net::ProofVerifierChromium;
using net::TransportSecurityState;
using std::cout;
using std::cerr;
using std::map;
using std::string;
using std::vector;
using std::endl;
using base::FilePath;

// The IP or hostname the quic client will connect to.
string FLAGS_host = "";
// The port to connect to.
int32_t FLAGS_port = 0;
// If set, send a POST with this body.
string FLAGS_body = "";
// If set, contents are converted from hex to ascii, before sending as body of
// a POST. e.g. --body_hex=\"68656c6c6f\"
string FLAGS_body_hex = "";
// A semicolon separated list of key:value pairs to add to request headers.
string FLAGS_headers = "";
// Set to true for a quieter output experience.
bool FLAGS_quiet = false;
// QUIC version to speak, e.g. 21. If not set, then all available versions are
// offered in the handshake.
int32_t FLAGS_quic_version = -1;
// If true, a version mismatch in the handshake is not considered a failure.
// Useful for probing a server to determine if it speaks any version of QUIC.
bool FLAGS_version_mismatch_ok = false;
// If true, an HTTP response code of 3xx is considered to be a successful
// response, otherwise a failure.
bool FLAGS_redirect_is_success = true;
// Initial MTU of the connection.
int32_t FLAGS_initial_mtu = 0;

class FakeCertVerifier : public net::CertVerifier {
 public:
  int Verify(const RequestParams& params,
             net::CRLSet* crl_set,
             net::CertVerifyResult* verify_result,
             const net::CompletionCallback& callback,
             std::unique_ptr<Request>* out_req,
             const net::NetLogWithSource& net_log) override {
    return net::OK;
  }

  // Returns true if this CertVerifier supports stapled OCSP responses.
  bool SupportsOCSPStapling() override { return false; }
};

class QuicrClient
{
private:
	bool is_fifo_;
	bool lossless_;
	size_t max_delay_;
	size_t lost_bytes_delta_;
	int sendInner(const char * data, size_t len, bool end_of_message);
	base::AtExitManager quicr_exit_manager;
	std::unique_ptr<net::QuicNormalClient> quicr_client;
	base::MessageLoopForIO quicr_message_loop;
public:
	QuicrClient(unsigned int flags = FLAGS_NONE, size_t max_delay = 0, size_t lost_bytes_delta = 0x100000);
	bool connect(const char *host, uint16_t port);
	int send(const char *data, size_t len, bool end_of_message);
	int send(const char *data, size_t len);
	int recv(char *buffer, size_t max_len);
	int recv_file(const FilePath &file_name);
	connection_status getStatus();
};

extern "C" EXPORT
bool quicr_connect(const char * host, uint16_t port, bool is_fifo);
extern "C" EXPORT
int quicr_send(char * data, size_t len, bool end_of_message);
extern "C" EXPORT
int quicr_recv(char *buffer, size_t max_len);
extern "C" EXPORT
void flush();

void parse_command_line(size_t *max_delay, size_t *lost_bytes_delta, bool *is_fifo, bool *lossless)
{
	base::CommandLine* command_line = base::CommandLine::ForCurrentProcess();
	*max_delay = 0;
	if (command_line->HasSwitch("max_delay"))
	{
		if (!base::StringToSizeT(command_line->GetSwitchValueASCII("max_delay"), max_delay)) {
			LOG(ERROR) << "max_delay must be an integer\n";
			exit(1);
		}
	}
	*lost_bytes_delta = 0;
	if (command_line->HasSwitch("lost_bytes_delta"))
	{
		if (!base::StringToSizeT(command_line->GetSwitchValueASCII("lost_bytes_delta"), lost_bytes_delta)) {
			LOG(ERROR) << "lost_bytes_delta must be an integer\n";
			exit(1);
		}
	}
	*is_fifo = command_line->HasSwitch("fifo");
	*lossless = command_line->HasSwitch("lossless");

	if (command_line->HasSwitch("host")) {
		FLAGS_host = command_line->GetSwitchValueASCII("host");
	}
	if (command_line->HasSwitch("port")) {
		if (!base::StringToInt(command_line->GetSwitchValueASCII("port"), &FLAGS_port)) {
			std::cerr << "--port must be an integer\n";
			exit(1);
		}
	}
}

void client2()
{

	size_t lost_bytes_delta = 0;
	size_t max_delay = 0;
	bool is_fifo = false;
	bool lossless = false;
	parse_command_line(&max_delay, &lost_bytes_delta, &is_fifo, &lossless);
	uint8_t flags = FLAGS_NONE;
	if (is_fifo) { flags |= FLAGS_FIFO; }
	if (lossless) { flags |= FLAGS_LOSSLESS; }

	if (is_fifo && !lossless) {
		LOG(ERROR) << "Fifo mode musn't be lossless\n";
		exit(1);
	}

	max_delay = 0;
	QuicrClient quicr_client(flags, max_delay, lost_bytes_delta);
	if (false == quicr_client.connect(FLAGS_host.c_str(), FLAGS_port)) { // 3 packets
		LOG(ERROR) << "Failed to connect server";
		return;
	}
	//quicr_client.send("aaaaaa", 6);

	//char buffer[10001];
	//int bytes_received = 0;
	////while (true);
	//bytes_received = quicr_client.recv(buffer, 5);
	//buffer[bytes_received] = '\0';
	//std::cout << "Received1: " << buffer << std::endl;

	//bytes_received = quicr_client.recv(buffer, 5);
	//buffer[bytes_received] = '\0';
	//std::cout << "Received2: " << buffer << std::endl;

	//bytes_received = quicr_client.recv(buffer, 10000);
	//buffer[bytes_received] = '\0';
	//std::cout << "Received3: " << buffer << std::endl;

	//bytes_received = quicr_client.recv(buffer, 10000);
	//buffer[bytes_received] = '\0';
	//std::cout << "Received4: " << buffer << std::endl;

	//bytes_received = quicr_client.recv(buffer, 10000);
	//buffer[bytes_received] = '\0';
	//std::cout << "Received5: " << buffer << std::endl;

	//bytes_received = quicr_client.recv(buffer, 10000);
	//buffer[bytes_received] = '\0';
	//std::cout << "Received6: " << buffer << std::endl;

	//bytes_received = quicr_client.recv(buffer, 10000);
	//buffer[bytes_received] = '\0';
	//std::cout << "Received7: " << buffer << std::endl;

	//bytes_received = quicr_client.recv(buffer, 10000);
	//buffer[bytes_received] = '\0';
	//std::cout << "Received8: " << buffer << std::endl;

#if defined(OS_POSIX)
	auto file_path = base::BasicStringPiece<std::string>("client_file.txt");
#elif defined(OS_WIN)
	auto file_path = base::BasicStringPiece<std::wstring>(L"client_file.txt");
#endif
	CHECK_NE(-1, quicr_client.recv_file(FilePath(file_path)));
	VLOG(1) << "End of main";
}

int main(int argc, char* argv[]) {


  base::CommandLine::Init(argc, argv);
  base::CommandLine* line = base::CommandLine::ForCurrentProcess();
  const base::CommandLine::StringVector& urls = line->GetArgs();

  logging::LoggingSettings settings;
  settings.logging_dest = logging::LOG_TO_SYSTEM_DEBUG_LOG;
  CHECK(logging::InitLogging(settings));

  client2();
  return 0;

  if (line->HasSwitch("h") || line->HasSwitch("help") || urls.empty()) {
    const char* help_str =
        "Usage: quic_client [options] <url>\n"
        "\n"
        "<url> with scheme must be provided (e.g. http://www.google.com)\n\n"
        "Options:\n"
        "-h, --help                  show this help message and exit\n"
        "--host=<host>               specify the IP address of the hostname to "
        "connect to\n"
        "--port=<port>               specify the port to connect to\n"
        "--body=<body>               specify the body to post\n"
        "--body_hex=<body_hex>       specify the body_hex to be printed out\n"
        "--headers=<headers>         specify a semicolon separated list of "
        "key:value pairs to add to request headers\n"
        "--quiet                     specify for a quieter output experience\n"
        "--quic-version=<quic version> specify QUIC version to speak\n"
        "--version_mismatch_ok       if specified a version mismatch in the "
        "handshake is not considered a failure\n"
        "--redirect_is_success       if specified an HTTP response code of 3xx "
        "is considered to be a successful response, otherwise a failure\n"
        "--initial_mtu=<initial_mtu> specify the initial MTU of the connection"
        "\n"
        "--disable-certificate-verification do not verify certificates\n";
    cout << help_str;
    exit(0);
  }
  if (line->HasSwitch("host")) {
    FLAGS_host = line->GetSwitchValueASCII("host");
  }
  if (line->HasSwitch("port")) {
    if (!base::StringToInt(line->GetSwitchValueASCII("port"), &FLAGS_port)) {
      std::cerr << "--port must be an integer\n";
      return 1;
    }
  }
  if (line->HasSwitch("body")) {
    FLAGS_body = line->GetSwitchValueASCII("body");
  }
  if (line->HasSwitch("body_hex")) {
    FLAGS_body_hex = line->GetSwitchValueASCII("body_hex");
  }
  if (line->HasSwitch("headers")) {
    FLAGS_headers = line->GetSwitchValueASCII("headers");
  }
  if (line->HasSwitch("quiet")) {
    FLAGS_quiet = true;
  }
  if (line->HasSwitch("quic-version")) {
    int quic_version;
    if (base::StringToInt(line->GetSwitchValueASCII("quic-version"),
                          &quic_version)) {
      FLAGS_quic_version = quic_version;
    }
  }
  if (line->HasSwitch("version_mismatch_ok")) {
    FLAGS_version_mismatch_ok = true;
  }
  if (line->HasSwitch("redirect_is_success")) {
    FLAGS_redirect_is_success = true;
  }
  if (line->HasSwitch("initial_mtu")) {
    if (!base::StringToInt(line->GetSwitchValueASCII("initial_mtu"),
                           &FLAGS_initial_mtu)) {
      std::cerr << "--initial_mtu must be an integer\n";
      return 1;
    }
  }

  VLOG(1) << "server host: " << FLAGS_host << " port: " << FLAGS_port
          << " body: " << FLAGS_body << " headers: " << FLAGS_headers
          << " quiet: " << FLAGS_quiet
          << " quic-version: " << FLAGS_quic_version
          << " version_mismatch_ok: " << FLAGS_version_mismatch_ok
          << " redirect_is_success: " << FLAGS_redirect_is_success
          << " initial_mtu: " << FLAGS_initial_mtu;

  base::AtExitManager exit_manager;
  //base::MessageLoopForIO message_loop;

  // Determine IP address to connect to from supplied hostname.
  net::IPAddress ip_addr;

  // TODO(rtenneti): GURL's doesn't support default_protocol argument, thus
  // protocol is required in the URL.
  GURL url(urls[0]);
  string host = FLAGS_host;
  if (host.empty()) {
    host = url.host();
  }
  int port = FLAGS_port;
  if (port == 0) {
    port = url.EffectiveIntPort();
  }
  if (!ip_addr.AssignFromIPLiteral(host)) {
    net::AddressList addresses;
    int rv = net::SynchronousHostResolver::Resolve(host, &addresses);
    if (rv != net::OK) {
      LOG(ERROR) << "Unable to resolve '" << host
                 << "' : " << net::ErrorToShortString(rv);
      return 1;
    }
    ip_addr = addresses[0].address();
  }

  string host_port = net::IPAddressToStringWithPort(ip_addr, FLAGS_port);
  VLOG(1) << "Resolved " << host << " to " << host_port << endl;

  // Build the client, and try to connect.
  net::QuicServerId server_id(url.host(), url.EffectiveIntPort(),
                              net::PRIVACY_MODE_DISABLED);
  net::QuicVersionVector versions = net::AllSupportedVersions();
  if (FLAGS_quic_version != -1) {
    versions.clear();
    versions.push_back(static_cast<net::QuicVersion>(FLAGS_quic_version));
  }
  // For secure QUIC we need to verify the cert chain.
  std::unique_ptr<CertVerifier> cert_verifier(CertVerifier::CreateDefault());
  if (line->HasSwitch("disable-certificate-verification")) {
    cert_verifier.reset(new FakeCertVerifier());
  }
  std::unique_ptr<TransportSecurityState> transport_security_state(
      new TransportSecurityState);
  std::unique_ptr<CTVerifier> ct_verifier(new MultiLogCTVerifier());
  std::unique_ptr<CTPolicyEnforcer> ct_policy_enforcer(new CTPolicyEnforcer());
  std::unique_ptr<ProofVerifierChromium> proof_verifier(
      new ProofVerifierChromium(cert_verifier.get(), ct_policy_enforcer.get(),
                                transport_security_state.get(),
                                ct_verifier.get()));
  net::QuicSimpleClient client(net::IPEndPoint(ip_addr, port), server_id,
                               versions, std::move(proof_verifier));
  client.set_initial_max_packet_length(
      FLAGS_initial_mtu != 0 ? FLAGS_initial_mtu : net::kDefaultMaxPacketSize);
  if (!client.Initialize()) {
    cerr << "Failed to initialize client." << endl;
    return 1;
  }
  if (!client.Connect()) {
    net::QuicErrorCode error = client.session()->error();
    if (FLAGS_version_mismatch_ok && error == net::QUIC_INVALID_VERSION) {
      cout << "Server talks QUIC, but none of the versions supported by "
           << "this client: " << QuicVersionVectorToString(versions) << endl;
      // Version mismatch is not deemed a failure.
      return 0;
    }
    cerr << "Failed to connect to " << host_port
         << ". Error: " << net::QuicUtils::ErrorToString(error) << endl;
    return 1;
  }
  cout << "Connected to " << host_port << endl;

  // Construct the string body from flags, if provided.
  string body = FLAGS_body;
  if (!FLAGS_body_hex.empty()) {
    DCHECK(FLAGS_body.empty()) << "Only set one of --body and --body_hex.";
    body = net::QuicUtils::HexDecode(FLAGS_body_hex);
  }

  // Construct a GET or POST request for supplied URL.
  net::HttpRequestInfo request;
  request.method = body.empty() ? "GET" : "POST";
  request.url = url;

  // Append any additional headers supplied on the command line.
  for (const std::string& header :
       base::SplitString(FLAGS_headers, ";", base::KEEP_WHITESPACE,
                         base::SPLIT_WANT_NONEMPTY)) {
    string sp;
    base::TrimWhitespaceASCII(header, base::TRIM_ALL, &sp);
    if (sp.empty()) {
      continue;
    }
    vector<string> kv =
        base::SplitString(sp, ":", base::TRIM_WHITESPACE, base::SPLIT_WANT_ALL);
    CHECK_EQ(2u, kv.size());
    string key;
    base::TrimWhitespaceASCII(kv[0], base::TRIM_ALL, &key);
    string value;
    base::TrimWhitespaceASCII(kv[1], base::TRIM_ALL, &value);
    request.extra_headers.SetHeader(key, value);
  }

  // Make sure to store the response, for later output.
  client.set_store_response(true);

  // Send the request.
  net::SpdyHeaderBlock header_block;
  net::CreateSpdyHeadersFromHttpRequest(request, request.extra_headers,
                                        /*direct=*/true, &header_block);
  client.SendRequestAndWaitForResponse(header_block, body, /*fin=*/true);
  
  // Print request and response details.
  if (!FLAGS_quiet) {
    cout << "Request:" << endl;
    cout << "headers:" << header_block.DebugString();
    if (!FLAGS_body_hex.empty()) {
      // Print the user provided hex, rather than binary body.
      cout << "body:\n"
           << net::QuicUtils::HexDump(net::QuicUtils::HexDecode(FLAGS_body_hex))
           << endl;
    } else {
      cout << "body: " << body << endl;
    }
    cout << endl;
    cout << "Response:" << endl;
    cout << "headers: " << client.latest_response_headers() << endl;
    string response_body = client.latest_response_body();
    if (!FLAGS_body_hex.empty()) {
      // Assume response is binary data.
      cout << "body:\n" << net::QuicUtils::HexDump(response_body) << endl;
    } else {
      cout << "body: " << response_body << endl;
    }
  }

  size_t response_code = client.latest_response_code();
  if (response_code >= 200 && response_code < 300) {
    cout << "Request succeeded (" << response_code << ")." << endl;
    return 0;
  } else if (response_code >= 300 && response_code < 400) {
    if (FLAGS_redirect_is_success) {
      cout << "Request succeeded (redirect " << response_code << ")." << endl;
      return 0;
    } else {
      cout << "Request failed (redirect " << response_code << ")." << endl;
      return 1;
    }
  } else {
    cerr << "Request failed (" << response_code << ")." << endl;
    return 1;
  }
}



std::unique_ptr<net::QuicSimpleClient> quiqos_client2;


extern "C" EXPORT
bool connectServer(char * host, uint16_t port)
{

	//base::MessageLoopForIO message_loop;
	char name[10] = {'a','b','\0'};
	char* argv[1] = {name};
	base::CommandLine::Init(1, argv);

	logging::LoggingSettings settings;
	settings.logging_dest = logging::LOG_TO_SYSTEM_DEBUG_LOG;

	// Determine IP address to connect to from supplied hostname.
	net::IPAddress ip_addr;
	std::string remote_ip(host);

	if (!ip_addr.AssignFromIPLiteral(remote_ip)) {
		LOG(ERROR) << "Unable to resolve '" << remote_ip;
		return false;
	}

	VLOG(1) << "connecting " << remote_ip << " : " << port << endl;

	// Build the client, and try to connect.
	net::QuicServerId server_id(remote_ip, port,
		net::PRIVACY_MODE_DISABLED);
	net::QuicVersionVector versions = net::AllSupportedVersions();

	// For secure QUIC we need to verify the cert chain.
	std::unique_ptr<CertVerifier> cert_verifier(CertVerifier::CreateDefault());
	cert_verifier.reset(new FakeCertVerifier());
	
	std::unique_ptr<TransportSecurityState> transport_security_state(
		new TransportSecurityState);
	std::unique_ptr<CTVerifier> ct_verifier(new MultiLogCTVerifier());
	std::unique_ptr<CTPolicyEnforcer> ct_policy_enforcer(new CTPolicyEnforcer());
	std::unique_ptr<ProofVerifierChromium> proof_verifier(
		new ProofVerifierChromium(cert_verifier.get(), ct_policy_enforcer.get(),
			transport_security_state.get(),
			ct_verifier.get()));
	std::unique_ptr<net::QuicSimpleClient> client(
		new net::QuicSimpleClient(net::IPEndPoint(ip_addr, port), server_id,
		versions, std::move(proof_verifier)));
	client->set_initial_max_packet_length(net::kDefaultMaxPacketSize);
	if (!client->Initialize()) {
		cerr << "Failed to initialize client." << endl;
		return false;
	}
	if (!client->Connect()) {
		LOG(ERROR) << "Failed to connect";
		return false;
	}
	quiqos_client2 = std::move(client);

	return true;
}
#include "quic_client_base.h"
namespace net
{
class SimpleResponseListener : public QuicClientBase::ResponseListener {
public:
	void OnCompleteResponse(QuicStreamId id,
		const net::SpdyHeaderBlock& response_headers,
		const string& response_body) override {
		string debug_string = response_headers.DebugString();
		DVLOG(1) << "response for stream " << id << " " << debug_string << "\n"
			<< response_body;
		responses.push_back(response_body);
	}
	string getFirstResponse()
	{
		if (responses.empty())
		{
			return string();
		}
		auto response = responses.front();
		responses.erase(responses.begin());
		return response;
	}
private:
	vector<string> responses;
};
}

extern "C" EXPORT
size_t sendRequest(char * name, char * output)
{
	// Construct the string body from flags, if provided.
	string body;

	// Construct a GET or POST request for supplied URL.
	net::HttpRequestInfo request;
	request.method = body.empty() ? "GET" : "POST";
	GURL url("http://quiqos/" + std::string(name));
	request.url = url;

	// Make sure to store the response, for later output.
	quiqos_client2->set_store_response(true);
	net::SimpleResponseListener responseListener;
	quiqos_client2->set_response_listener(
		std::unique_ptr<net::QuicClientBase::ResponseListener>(&responseListener));

	// Send the request.
	net::SpdyHeaderBlock header_block;
	net::CreateSpdyHeadersFromHttpRequest(request, request.extra_headers,
		/*direct=*/true, &header_block);

	net::HttpRequestInfo request2;
	request2.method = body.empty() ? "GET" : "POST";
	GURL url2("http://quiqos/" + std::string("data2"));
	request2.url = url2;
	net::SpdyHeaderBlock header_block2;
	net::CreateSpdyHeadersFromHttpRequest(request2, request.extra_headers,
		/*direct=*/true, &header_block2);

	GURL url3("http://quiqos/" + std::string("data3"));
	GURL url4("http://quiqos/" + std::string("data4"));
	GURL url5("http://quiqos/" + std::string("data5"));
	std::vector<std::string> urls = { "http://"+url.GetContent(), "http://"+url2.GetContent(), "http://" + url3.GetContent(), "http://" + url4.GetContent(), "http://" + url5.GetContent() };

	quiqos_client2->SendRequestsAndWaitForResponse(urls);
	string temp = responseListener.getFirstResponse();
	quiqos_client2->WaitForNextEvent();
	temp = responseListener.getFirstResponse();

	// Print request and response details.
	cout << "Request:" << endl;
	cout << "headers:" << header_block.DebugString();
	cout << "body: " << body << endl;
	cout << endl;
	cout << "Response:" << endl;
	cout << "headers: " << quiqos_client2->latest_response_headers() << endl;
	string response_body = quiqos_client2->latest_response_body();
	cout << "body: " << response_body << endl;  //net::QuicUtils::HexDump(response_body) 

	size_t response_code = quiqos_client2->latest_response_code();
	if (response_code >= 200 && response_code < 300) {
		cout << "Request succeeded (" << response_code << ")." << endl;
		memcpy(output, response_body.c_str(), response_body.size());
		return response_body.size();
	}
	else if (response_code >= 300 && response_code < 400) {
		if (FLAGS_redirect_is_success) {
			cout << "Request succeeded (redirect " << response_code << ")." << endl;
			return 0;
		}
		else {
			cout << "Request failed (redirect " << response_code << ")." << endl;
			return 0;
		}
	}
	else {
		cerr << "Request failed (" << response_code << ")." << endl;
		return 0;
	}
}

QuicrClient::QuicrClient(unsigned int flags, size_t max_delay, size_t lost_bytes_delta) : max_delay_(max_delay), lost_bytes_delta_(lost_bytes_delta)
{
	is_fifo_ = (flags & FLAGS_FIFO) != 0;
	lossless_ = (flags & FLAGS_LOSSLESS) != 0;
}

//extern "C" EXPORT
bool QuicrClient::connect(const char * host, uint16_t port)
{
	//base::MessageLoopForIO message_loop;
	char name[10] = { 'a','b','\0' };
	char* argv[1] = { name };
	base::CommandLine::Init(1, argv);

	logging::LoggingSettings settings;
	settings.logging_dest = logging::LOG_TO_SYSTEM_DEBUG_LOG;

	// Determine IP address to connect to from supplied hostname.
	net::IPAddress ip_addr;
	std::string remote_ip(host);

	if (!ip_addr.AssignFromIPLiteral(remote_ip)) {
		LOG(ERROR) << "Unable to resolve '" << remote_ip;
		return false;
	}

	VLOG(1) << "connecting " << remote_ip << " : " << port << endl;

	// Build the client, and try to connect.
	net::QuicServerId server_id(remote_ip, port,
		net::PRIVACY_MODE_DISABLED);
	net::QuicVersionVector versions = net::AllSupportedVersions();

	// For secure QUIC we need to verify the cert chain.
	std::unique_ptr<CertVerifier> cert_verifier(CertVerifier::CreateDefault());
	cert_verifier.reset(new FakeCertVerifier());

	std::unique_ptr<TransportSecurityState> transport_security_state(
		new TransportSecurityState);
	std::unique_ptr<CTVerifier> ct_verifier(new MultiLogCTVerifier());
	std::unique_ptr<CTPolicyEnforcer> ct_policy_enforcer(new CTPolicyEnforcer());
	std::unique_ptr<ProofVerifierChromium> proof_verifier(
		new ProofVerifierChromium(cert_verifier.get(), ct_policy_enforcer.get(),
			transport_security_state.get(),
			ct_verifier.get()));
	std::unique_ptr<net::QuicNormalClient> client(
		new net::QuicNormalClient(net::IPEndPoint(ip_addr, port), server_id,
			versions, std::move(proof_verifier), is_fifo_, lossless_, max_delay_, lost_bytes_delta_));
	client->set_initial_max_packet_length(net::kDefaultMaxPacketSize);
	if (!client->Initialize()) {
		cerr << "Failed to initialize client." << endl;
		return false;
	}
	if (!client->Connect()) {
		LOG(ERROR) << "Failed to connect";
		return false;
	}
	quicr_client = std::move(client);
	quicr_client->WaitForEvents();
	return true;
}

//extern "C" EXPORT
// used for non fifo clients
int QuicrClient::send(const char * data, size_t len)
{
	if (is_fifo_) {
		return -1;
	}
	return this->sendInner(data, len, true);
}

int QuicrClient::send(const char * data, size_t len, bool end_of_message)
{
	if (!is_fifo_) {
		return -1;
	}
	return this->sendInner(data, len, end_of_message);
}

int QuicrClient::sendInner(const char * data, size_t len, bool end_of_message)
{
	if (quicr_client == nullptr) {
		return -1;
	}
	quicr_client->WriteOrBufferData(std::string(data, len), true);
	
	return 0;
}

//extern "C" EXPORT
int QuicrClient::recv(char *buffer, size_t max_len)
{
	if (quicr_client == nullptr) {
		LOG(ERROR) << "quicr_client is nullptr";
		return 0;
	}
	return quicr_client->Recv(buffer, max_len);
}

int QuicrClient::recv_file(const FilePath &file_path)
{
	uint64_t file_len;
	if (-1 == recv((char *)&file_len, sizeof(file_len))) {
		LOG(ERROR) << "Failed to recv file len";
		return -1;
	}

	std::cout << "Receiving file with size = " << file_len;

#define CHUNK_SIZE 0x10000000

	bool first = true;
	char *buffer = new char[CHUNK_SIZE];
	int error_code = 0;

	while (file_len > 0) {
		//char buffer[CHUNK_SIZE];
		int bytes_read = recv(buffer, CHUNK_SIZE);
		if (-1 == bytes_read) {
			LOG(ERROR) << "Failed to receive data from server";
			error_code = -1;
			goto cleanup;
		}
		if (first) {
			first = false;
			// Try to create new file
			if (false == base::WriteFile(file_path, buffer, bytes_read)) {
				LOG(ERROR) << "Can't create file " << file_path.value();
				error_code = -1;
				goto cleanup;
			}
		} else {
			if (false == base::AppendToFile(file_path, buffer, bytes_read)) {
				LOG(ERROR) << "Can't write to file " << file_path.value();
				error_code = -1;
				goto cleanup;
			}
		}
		file_len -= bytes_read;
	}

cleanup:
	delete [] buffer;
	return error_code;
}

//extern "C" EXPORT 
//void flush()
//{
//	//while (quiqos_client->connected() && quiqos_client->WaitForEvents() != 0) {}
//	quiqos_client->WaitForEvents();
//}

connection_status QuicrClient::getStatus()
{
	net::QuicConnection *connection = quicr_client->session()->connection();
	net::QuicConnectionStats stats = connection->GetStats();

	connection_status status{
		stats.packets_sent,
		stats.bytes_sent,
		stats.packets_received,
		stats.bytes_received,
		stats.packets_revived,
		stats.packets_lost,
		stats.min_rtt_us,
		stats.srtt_us,
	//	stats.connection_creation_time,
		connection->sending_fec_configuration(),
		connection->receiving_fec_configuration(),
		connection->current_loss_rate(),
	};
	return status;
}