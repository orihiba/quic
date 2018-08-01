// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <openssl/err.h>
#include <openssl/evp.h>
#include <string.h>

#include <memory>

#include "net/quic/core/crypto/none_encrypter.h"
#include "net/quic/core/quic_flags.h"
#include "net/quic/core/quic_utils.h"

using base::StringPiece;

namespace net {

namespace {

// The maximum size in bytes of the nonce, including 8 bytes of sequence number.
// ChaCha20 uses only the 8 byte sequence number and AES-GCM uses 12 bytes.
//const size_t kMaxNonceSize = 12;
const size_t kKeySize = 32;
const size_t kNoncePrefixSize = 4;

// In debug builds only, log OpenSSL error stack. Then clear OpenSSL error
// stack.
void DLogOpenSslErrors() {
#ifdef NDEBUG
  while (ERR_get_error()) {
  }
#else
  while (unsigned long error = ERR_get_error()) {
    char buf[120];
    ERR_error_string_n(error, buf, arraysize(buf));
    DLOG(ERROR) << "OpenSSL error: " << buf;
  }
#endif
}

}  // namespace

MyEncrypter::MyEncrypter() : 
//	aead_alg_(nullptr),
	key_size_(kKeySize),
	auth_tag_size_(12),
	nonce_prefix_size_(kNoncePrefixSize)
{
}

//MyEncrypter::MyEncrypter(const EVP_AEAD* aead_alg,
//                                     size_t key_size,
//                                     size_t auth_tag_size,
//                                     size_t nonce_prefix_size)
//    : aead_alg_(aead_alg),
//      key_size_(key_size),
//      auth_tag_size_(auth_tag_size),
//      nonce_prefix_size_(nonce_prefix_size) {
//  DCHECK_LE(key_size_, sizeof(key_));
//  DCHECK_LE(nonce_prefix_size_, sizeof(nonce_prefix_));
//  DCHECK_GE(kMaxNonceSize, nonce_prefix_size_);
//}
//
MyEncrypter::~MyEncrypter() {}

bool MyEncrypter::SetKey(StringPiece key) {
  return true;
}

bool MyEncrypter::SetNoncePrefix(StringPiece nonce_prefix) {
	return true;
}

bool MyEncrypter::Encrypt(StringPiece nonce,
                                StringPiece associated_data,
                                StringPiece plaintext,
                                unsigned char* output) {
  return true;
}

bool MyEncrypter::EncryptPacket(QuicPathId path_id,
                                      QuicPacketNumber packet_number,
                                      StringPiece associated_data,
                                      StringPiece plaintext,
                                      char* output,
                                      size_t* output_length,
                                      size_t max_output_length) {
  
  DVLOG(1) << "encrypting!";
 // DVLOG(1) << QuicUtils::HexDump(plaintext);
  memcpy(output, plaintext.data(), plaintext.size());
  *output_length = plaintext.size();
  
  return true;
}

size_t MyEncrypter::GetKeySize() const {
  return key_size_;
}

size_t MyEncrypter::GetNoncePrefixSize() const {
  return nonce_prefix_size_;
}

size_t MyEncrypter::GetMaxPlaintextSize(size_t ciphertext_size) const {
  return ciphertext_size - auth_tag_size_;
}

size_t MyEncrypter::GetCiphertextSize(size_t plaintext_size) const {
  return plaintext_size + auth_tag_size_;
}

StringPiece MyEncrypter::GetKey() const {
  return StringPiece(reinterpret_cast<const char*>(key_), key_size_);
}

StringPiece MyEncrypter::GetNoncePrefix() const {
  if (nonce_prefix_size_ == 0) {
    return StringPiece();
  }
  return StringPiece(reinterpret_cast<const char*>(nonce_prefix_),
                     nonce_prefix_size_);
}

}  // namespace net
