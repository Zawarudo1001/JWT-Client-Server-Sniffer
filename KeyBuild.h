#pragma once

#include <cryptopp-master/stdcpp.h>
#include <base64_url_unpadded.hpp>
#include <cryptopp-master/rsa.h>
#include "cryptopp-master/files.h"
#include "cryptopp-master/base64.h"
#include "cryptopp-master/pem.h"

using namespace cppcodec;
using namespace CryptoPP;

//###################################################################################


std::string RSA_fromBase64(std::string_view nnInBase64UrlUnpadded, std::string_view eeInBase64UrlUnpadded)
{
	auto nnBin = cppcodec::base64_url_unpadded::decode(nnInBase64UrlUnpadded);
	auto eeBin = cppcodec::base64_url_unpadded::decode(eeInBase64UrlUnpadded);
	CryptoPP::Integer nn(nnBin.data(), nnBin.size(), CryptoPP::Integer::UNSIGNED, CryptoPP::BIG_ENDIAN_ORDER);
	CryptoPP::Integer ee(eeBin.data(), eeBin.size(), CryptoPP::Integer::UNSIGNED, CryptoPP::BIG_ENDIAN_ORDER);
	CryptoPP::RSA::PublicKey pubKey;
	pubKey.Initialize(nn, ee);
	std::ostringstream pem;
	CryptoPP::FileSink sink(pem);
	CryptoPP::PEM_Save(sink, pubKey);
	return pem.str();
}


//###################################################################################