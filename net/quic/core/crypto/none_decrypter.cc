// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/evp.h>
#include <openssl/tls1.h>

#include <memory>

#include "net/quic/core/crypto/none_decrypter.h"
#include "net/quic/core/quic_bug_tracker.h"
#include "net/quic/core/quic_flags.h"
#include "net/quic/core/quic_utils.h"

using base::StringPiece;
using std::string;
const size_t kKeySize = 32;
const size_t kNoncePrefixSize = 4;

namespace net {

namespace {

// Clear OpenSSL error stack.
void ClearOpenSslErrors() {
  while (ERR_get_error()) {
  }
}

// In debug builds only, log OpenSSL error stack. Then clear OpenSSL error
// stack.
void DLogOpenSslErrors() {
#ifdef NDEBUG
  ClearOpenSslErrors();
#else
  while (uint32_t error = ERR_get_error()) {
    char buf[120];
    ERR_error_string_n(error, buf, arraysize(buf));
    DLOG(ERROR) << "OpenSSL error: " << buf;
  }
#endif
}

}  // namespace

MyDecrypter::MyDecrypter() :
	// aead_alg_(nullptr),
	key_size_(kKeySize),
	auth_tag_size_(kAuthTagSize),
	nonce_prefix_size_(kNoncePrefixSize),
	have_preliminary_key_(false) {}


MyDecrypter::~MyDecrypter() {}

bool MyDecrypter::SetKey(StringPiece key) {
	return true;
}

bool MyDecrypter::SetNoncePrefix(StringPiece nonce_prefix) {
  DCHECK_EQ(nonce_prefix.size(), nonce_prefix_size_);
  if (nonce_prefix.size() != nonce_prefix_size_) {
    return false;
  }
  memcpy(nonce_prefix_, nonce_prefix.data(), nonce_prefix.size());
  return true;
}

bool MyDecrypter::SetPreliminaryKey(StringPiece key) {
  DCHECK(!have_preliminary_key_);
  SetKey(key);
  have_preliminary_key_ = true;

  return true;
}

bool MyDecrypter::SetDiversificationNonce(
    const DiversificationNonce& nonce) {
	
	return true;
}

bool MyDecrypter::DecryptPacket(QuicPathId path_id,
                                      QuicPacketNumber packet_number,
                                      StringPiece associated_data,
                                      StringPiece ciphertext,
                                      char* output,
                                      size_t* output_length,
                                      size_t max_output_length) {
  
  DVLOG(1) << "decrypting!";
 // DVLOG(1) << QuicUtils::HexDump(ciphertext);
  memcpy(output, ciphertext.data(), ciphertext.size());
  *output_length = ciphertext.size();

  return true;
}

StringPiece MyDecrypter::GetKey() const {
  return StringPiece(reinterpret_cast<const char*>(key_), key_size_);
}

StringPiece MyDecrypter::GetNoncePrefix() const {
  if (nonce_prefix_size_ == 0) {
    return StringPiece();
  }
  return StringPiece(reinterpret_cast<const char*>(nonce_prefix_),
                     nonce_prefix_size_);
}

const char* MyDecrypter::cipher_name() const {
	return TLS1_TXT_ECDHE_RSA_WITH_CHACHA20_POLY1305;
}

uint32_t MyDecrypter::cipher_id() const {
	return TLS1_CK_ECDHE_RSA_CHACHA20_POLY1305;
}

}  // namespace net
