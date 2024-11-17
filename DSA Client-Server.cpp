#include <iostream>
#include "UdpClientSocket.hpp"
#include "UdpServerSocket.hpp"
#include <string>
#include <cryptopp-master\cryptlib.h>
#include <cryptopp-master\sha.h>
#include <cryptopp-master\hex.h>
#include <cryptopp-master\dsa.h>
#include <cryptopp-master\osrng.h>
#include "Sniffer.h"
#include <chrono>
#include <thread>
#include "cryptopp-master\base64.h"
#include "cryptopp-master\files.h"
#include <stdio.h>
#include "KeyGen.h"
#include <jwt-cpp/jwt.h>
#include <jwk_generator/jwk_generator.hpp>
#include <jwk_generator/libs/json.hpp>
#include "KeyBuild.h"
#include <thread>
#include <mutex>


using namespace std;
using namespace jwt;
using namespace jwk_generator;

mutex parse_token_lock;


void Client_Handle(int SecureParameter) {
	unsigned char increment = 0;

	UdpClientSocket client_jwt("192.168.194.1", 10002);
	UdpClientSocket client_jwk("192.168.194.1", 10001);

	string client_message = "P = NP";

	while (true) {

		JwkGenerator<RS256> jwk;

		string token = jwt::create()
			.set_issuer("Viacheslav")
			.set_type("JWT")
			.set_payload_claim("message:", jwt::claim(client_message))
			.sign(jwt::algorithm::rs256(jwk.public_to_pem(), jwk.private_to_pem()));

		string jwk_for_jwt = jwk.to_json().dump();

		char* jwt_buffer = new char[token.length()];
		char* jwk_buffer = new char[jwk_for_jwt.length()];

		memcpy(jwt_buffer, token.c_str(), token.length());
		memcpy(jwk_buffer, jwk_for_jwt.c_str(), jwk_for_jwt.length());

		client_jwt.sendData(jwt_buffer, token.length());
		client_jwk.sendData(jwk_buffer, jwk_for_jwt.length());

		cout << "Client:: JWT (size = " << token.length() << ") was sent to server" << endl;
		cout << "Client:: JWK (size = " << jwk_for_jwt.length() << ") was sent to server" << endl;

		this_thread::sleep_for(chrono::milliseconds(1000));
		delete[] jwt_buffer;
		delete[] jwk_buffer;
	}
}


void Recv_JWT(UdpServerSocket &sock, string &jwt) {

	char jwt_buffer[65536];

	while (true) {
		parse_token_lock.lock();

		int recv_bytes = sock.receiveData(jwt_buffer, 65536);

		if (recv_bytes == 0) continue;
		jwt = string(jwt_buffer, recv_bytes);
		parse_token_lock.unlock();
		this_thread::sleep_for(chrono::milliseconds(1));
	}
}

void Recv_JWK(UdpServerSocket &sock, string &jwk) {

	char jwk_buffer[65536];

	while (true) {
		parse_token_lock.lock();

		int recv_bytes = sock.receiveData(jwk_buffer, 65536);
		
		if (recv_bytes == 0) continue;
		jwk = string(jwk_buffer, recv_bytes);
		parse_token_lock.unlock();
		this_thread::sleep_for(chrono::milliseconds(1));
	}
}

void Server_Handle(int SecureParameter) {
	UdpServerSocket JWT_Recv_Socket(10002);
	UdpServerSocket JWK_Recv_Socket(10001);

	string recv_jwt;
	string recv_jwk;

	thread jwk_recv(Recv_JWK, ref(JWK_Recv_Socket), ref(recv_jwk));

	thread jwt_recv(Recv_JWT, ref(JWT_Recv_Socket), ref(recv_jwt));


	while (true) {
		if (recv_jwk.length() != 0 and recv_jwt.length() != 0) {
			parse_token_lock.lock();

			nlohmann::json json = nlohmann::json::parse(recv_jwk);

			std::string exp = json["e"];
			std::string n = json["n"];
			
			cout << "Recieved JWK : " << recv_jwk << endl << endl;
			cout << "Recieved JWT : " << recv_jwt << endl << endl;

			string pem = RSA_fromBase64(n, exp);

			auto decoded = jwt::decode(recv_jwt);

			auto verifier = jwt::verify()
				.allow_algorithm(jwt::algorithm::rs256(pem))
				.with_issuer("Viacheslav");

			try {
				verifier.verify(decoded);
				cout << "Signature is correct!" << endl;
			}
			catch (...) {
				cout << "Wrong signature!" << endl;
			}
			cout << endl;
			parse_token_lock.unlock();
		}
	}
}


/*################################################# Deprecated

void Penetrate_Handle() {
	UdpClientSocket client("192.168.194.1", 10001);
	string client_message;
	string signature;

	while (true) {

		cout << "Enter corrupted message with signature to send it to the server..." << endl;
		getline(cin, client_message);
		getline(cin, signature);

		string data_to_send = signature + client_message;

		char* buffer = new char[signature.length() + client_message.length()];
		memcpy(buffer, signature.c_str(), signature.length());
		memcpy(buffer + signature.length(), client_message.c_str(), client_message.length());

		client.sendData(buffer, signature.length() + client_message.length());
		this_thread::sleep_for(chrono::milliseconds(1000));
		delete[] buffer;
	}
}
/*#################################################*/


int main(int argc, char **argv)
{

	cout << "STARTING UP THE SIMULATION STAND..." << endl;
	if (argc == 3) {
		if (strcmp(argv[1], "-s") == 0) Server_Handle((int)*argv[2] - int('0'));
		if (strcmp(argv[1], "-c") == 0) Client_Handle((int)*argv[2] - int('0'));
	}
	if (argc == 2 and strcmp(argv[1], "-a") == 0) Sniffer_Handle();
	//if (argc == 2 and strcmp(argv[1], "-p") == 0) Penetrate_Handle();

}
