#pragma once

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/evp.h>


using namespace std;


pair<char*, char*> Generate_Rsa_KeyPair(size_t& lpriv, size_t& lpub) {	//public and private key in PEM format
	char* pri_key;
	char* pub_key;
	size_t pri_len;            // Length of private key
	size_t pub_len;            // Length of public key

	int ret = 0;
	RSA *r = NULL;
	BIGNUM *bne = NULL;
	BIO *bp_public = NULL, *bp_private = NULL;
	int bits = 2048;
	unsigned long e = RSA_F4;

	EVP_PKEY *evp_pbkey = NULL;
	EVP_PKEY *evp_pkey = NULL;

	BIO *pbkeybio = NULL;
	BIO *pkeybio = NULL;

	// 1. generate rsa key
	bne = BN_new();
	ret = BN_set_word(bne, e);

	r = RSA_new();
	ret = RSA_generate_key_ex(r, bits, bne, NULL);

	// 2. save public key
	//bp_public = BIO_new_file("public.pem", "w+");
	bp_public = BIO_new(BIO_s_mem());
	ret = PEM_write_bio_RSAPublicKey(bp_public, r);

	// 3. save private key
	//bp_private = BIO_new_file("private.pem", "w+");
	bp_private = BIO_new(BIO_s_mem());
	ret = PEM_write_bio_RSAPrivateKey(bp_private, r, NULL, NULL, 0, NULL, NULL);

	//4. Get the keys are PEM formatted strings
	pri_len = BIO_pending(bp_private);
	pub_len = BIO_pending(bp_public);

	lpriv = pri_len;
	lpub = pub_len;

	pri_key = new char[pri_len + 1];
	pub_key = new char[pub_len + 1];

	BIO_read(bp_private, pri_key, pri_len);
	BIO_read(bp_public, pub_key, pub_len);

	pri_key[pri_len] = '\0';
	pub_key[pub_len] = '\0';


	BIO_free(pbkeybio);
	BIO_free(pkeybio);


	BIO_free_all(bp_public);
	BIO_free_all(bp_private);
	RSA_free(r);
	BN_free(bne);

	return (make_pair(pub_key, pri_key));
}


std::string base64url_encode(const std::vector<unsigned char>& input) {
	std::string base64;
	int length = 0;
	BIO* bio;
	BIO* b64;
	BUF_MEM* bufferPtr;

	b64 = BIO_new(BIO_f_base64());
	bio = BIO_new(BIO_s_mem());
	BIO_push(b64, bio);
	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL); // No newlines

	BIO_write(b64, input.data(), input.size());
	BIO_flush(b64);
	BIO_get_mem_ptr(b64, &bufferPtr);
	BIO_set_close(b64, BIO_NOCLOSE);
	BIO_flush(b64);
	base64.assign(bufferPtr->data, bufferPtr->length);

	// Replace '+' with '-', '/' with '_', and remove '=' padding
	std::replace(base64.begin(), base64.end(), '+', '-');
	std::replace(base64.begin(), base64.end(), '/', '_');
	base64.erase(std::remove(base64.begin(), base64.end(), '='), base64.end());

	BIO_free_all(b64);
	return base64;
}

// Function to extract n and e from PEM public key and convert to Base64URL
pair<string, string> extract_n_e_from_pem(const std::string& pem) {

	BIO* bio = BIO_new_mem_buf(pem.data(), pem.size());
	RSA* rsa = PEM_read_bio_RSA_PUBKEY(bio, nullptr, nullptr, nullptr);
	BIO_free(bio);

	// Get n and e
	const BIGNUM* n;
	const BIGNUM* e;
	RSA_get0_key(rsa, &n, &e, nullptr);

	// Convert BIGNUM to byte array
	std::vector<unsigned char> n_bytes(BN_num_bytes(n));
	std::vector<unsigned char> e_bytes(BN_num_bytes(e));
	BN_bn2bin(n, n_bytes.data());
	BN_bn2bin(e, e_bytes.data());

	// Encode to Base64URL
	std::string n_base64url = base64url_encode(n_bytes);
	std::string e_base64url = base64url_encode(e_bytes);


	RSA_free(rsa);
	return make_pair(n_base64url.substr(0, n_base64url.size() - 2), e_base64url);
}
