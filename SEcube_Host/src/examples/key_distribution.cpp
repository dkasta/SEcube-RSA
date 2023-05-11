///**
//  ******************************************************************************
//  * File Name          : key_distribution.cpp
//  * Description        : Usage example of RSA cipher.
//  ******************************************************************************
//  *
//  * Copyright � 2016-present Blu5 Group <https://www.blu5group.com>
//  *
//  * This library is free software; you can redistribute it and/or
//  * modify it under the terms of the GNU Lesser General Public
//  * License as published by the Free Software Foundation; either
//  * version 3 of the License, or (at your option) any later version.
//  *
//  * This library is distributed in the hope that it will be useful,
//  * but WITHOUT ANY WARRANTY; without even the implied warranty of
//  * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
//  * Lesser General Public License for more details.
//  *
//  * You should have received a copy of the GNU Lesser General Public
//  * License along with this library; if not, see <https://www.gnu.org/licenses/>.
//  *
//  ******************************************************************************
//  */
//
///*! \file  key_distribution.cpp
// *  \brief This file is an example about how to distribut a symmetric key among more user
// *  \date 20/05/2021
// */
//
//#include "../sources/L1/L1.h"
//#include <chrono>
//#include <memory>
//#include <iostream>
//#include <fstream>
//#include <unistd.h>
//#include <limits.h>
//
//using namespace std;
//
//#define KEY_SIZE (1024 / 8)
//
//int main() {
//	unique_ptr<L0> l0 = make_unique<L0>();
//	unique_ptr<L1> l1 = make_unique<L1>();
//
//
//	cout << "Welcome to SEcube RSA library usage example!" << endl;
//	cout << "Looking for SEcube devices...\n" << endl;
//
//	int numdevices = l0->GetNumberDevices(); // this API checks how many SEcube devices are connected to the PC
//	if(numdevices == 0){
//		cout << "No SEcube devices found! Quit." << endl;
//		return 0;
//	}
//
//	vector<pair<string, string>> devices;
//	int ret = l0->GetDeviceList(devices); // this API fills the vector with pairs including details about the devices (path and serial number)
//	if(ret){
//		cout << "Error while searching for SEcube devices! Quit." << endl;
//		return -1;
//	}
//	cout << "Number of SEcube devices found: " << numdevices << endl;
//	cout << "List of SEcube devices (path, serial number):" << endl;
//	int index = 0;
//	uint8_t empty_serial_number[L0Communication::Size::SERIAL];
//	memset(empty_serial_number, 0, L0Communication::Size::SERIAL);
//	for(pair<string, string> p : devices){
//		if(p.second.empty() || memcmp(p.second.data(), empty_serial_number, L0Communication::Size::SERIAL)==0){
//			cout << index << ") " << p.first << " - serial number not available (please initialize this SEcube)" << endl;
//		} else {
//			cout << index << ") " << p.first << " - " << p.second << endl;
//		}
//		index++;
//	}
//
//	int sel = 0;
//	cout << "\nEnter the number corresponding to the SEcube device that you want to use..." << endl;
//	/* warning: if cin does not wait for input in debug mode with eclipse, open the launch configuration and select
//	 * the "use external console for inferior" checkbox under the debugger tab (see https://stackoverflow.com/questions/44283534/c-debug-mode-in-eclipse-causes-program-to-not-wait-for-cin)*/
//	if(!(cin >> sel)){
//		cout << "Input error...quit." << endl;
//		return -1;
//	}
//
//	if((sel >= 0) && (sel < numdevices)){
//		array<uint8_t, L0Communication::Size::SERIAL> sn;
//		sn.fill(0);
//		if(devices.at(sel).second.length() > L0Communication::Size::SERIAL){
//			cout << "Unexpected error...quit." << endl;
//			return -1;
//		} else {
//			memcpy(sn.data(), devices.at(sel).second.data(), devices.at(sel).second.length());
//		}
//		l1->L1SelectSEcube(sn); // select secube with correct serial number
//		cout << "\nDevice " << devices.at(sel).first << " - " << devices.at(sel).second << " selected." << endl;
//
//		array<uint8_t, 32> pin = {'t','e','s','t'}; // customize this PIN according to the PIN that you set on your SEcube device
//		l1->L1Login(pin, SE3_ACCESS_USER, true); // login to the SEcube
//
//		const size_t plainLen = 16;
//		shared_ptr<uint8_t[]> plainText = make_unique<uint8_t[]>(plainLen);
//		SEcube_ciphertext cipher;
//		shared_ptr<uint8_t[]> deciphered;
//		size_t decipheredLen;
//		const auto keyId = 43;
//		const auto simId = 42;
//		se3Key key = {
//				.id = keyId,
//				.dataSize = KEY_SIZE,
//				.asymmKey = {.type = L1Key::RSAKeyType::SE3_RSA_KEY_GENERIC}
//		};
//
//		bool found;
//		l1->L1FindKey(keyId, found);
//
//		if (found) {
//			try {
//				cout << "Deleting RSA key..." << flush;
//				se3Key keyToDel = {.id = keyId};
//				l1->L1KeyEdit(keyToDel, L1Commands::KeyOpEdit::SE3_KEY_OP_DELETE);
//			} catch (L1Exception& e) {
//				cout << "\t\tFAIL" << endl;
//				return 1;
//			}
//			cout << "\t\tOK" << endl;
//			l1->L1FindKey(keyId, found);
//		}
//
//		l1->L1FindKey(simId, found);
//
//		if (found) {
//			try {
//				cout << "Deleting symmetric key..." << flush;
//				se3Key keyToDel = {.id = simId};
//				l1->L1KeyEdit(keyToDel, L1Commands::KeyOpEdit::SE3_KEY_OP_DELETE);
//			} catch (L1Exception& e) {
//				cout << "\t\tFAIL" << endl;
//				return 1;
//			}
//			cout << "\t\tOK" << endl;
//			l1->L1FindKey(simId, found);
//		}
//
//		cout << endl << endl;
//		cout << "We will use a public key to encrypt the symmetric key." << endl;
//		cout << "The symmetric key is generate by the SEcube and it has ID: " << simId << "." << endl;
//		cout << "The cyphertext of the symmetric key is sent to the owner of public key." << endl;
//		cout << "The owner use his private key to get the symmetric key." << endl << flush;
//		cout << endl << endl;
//
//		cout << "The receiving user generates an asymmetric key for the" << endl << flush;
//		cout << "communication of the symmetric key." << endl;
//
//		cout << "Generating RSA key..." << flush;
//		auto start = chrono::high_resolution_clock::now();
//		try {
//			l1->L1KeyEdit(key, L1Commands::KeyOpEdit::SE3_KEY_OP_ADD_GEN_RSA);
//		} catch (L1Exception& e) {
//			cout << "\t\tFAIL" << endl;
//			return 1;
//		}
//		auto end = chrono::high_resolution_clock::now();
//		auto duration = chrono::duration_cast<chrono::milliseconds>(end - start);
//		cout << "\t\tOK (took " << duration.count() << " ms)" << endl;
//
//		cout << "\n The receiver user asks for public exponent and " << endl << flush;
//		cout << "module to be sent to the transmitter." << endl;
//
//		uint8_t N[256];
//		uint8_t E[256];
//		se3Key keyToGet = {.id = keyId, .asymmKey = {.N = N, .E = E}};
//		cout << "Getting public key..." << flush;
//		try {
//			l1->L1AsymmKeyGet(keyToGet);
//		} catch (L1Exception& e) {
//			cout << " FAIL" << endl;
//			return 1;
//		}
//		cout << "\t\tOK (N=";
//		for (auto i = 0; i < keyToGet.dataSize; i++) {
//			printf("%X", keyToGet.asymmKey.N[i]);
//		}
//		cout << "; E=";
//		for (auto i = 0; i < keyToGet.dataSize; i++) {
//			printf("%X", keyToGet.asymmKey.E[i]);
//		}
//		cout << ")" << endl;
//
//		cout << "\n The transmitter of the symmetrical key then generates " << endl << flush;
//		cout << "the symmetrical key to be sent to the receiver." << endl;
//
//		se3Key key1;
//		key1.id = simId;
//		key1.dataSize = 16;
//		unique_ptr<uint8_t[]> key1data = make_unique<uint8_t[]>(16);
//		start = chrono::high_resolution_clock::now();
//		for(int i=0; i<16; i++){
//			uint8_t x = 65+i;  // ABCDE...
//			key1data[i] = x;
//		}
//		key1.data = key1data.get(); // se3Key only has a pointer to the actual key value, in this case we allocated it with a smart pointer
//		memcpy(plainText.get(), key1.data, key1.dataSize);
//		try{
//			l1->L1KeyEdit(key1, L1Commands::KeyOpEdit::SE3_KEY_OP_ADD); // store the key on the SEcube
//		} catch (...) {
//			cout << "Error creating the keys on the SEcube. Quit." << endl;
//			l1->L1Logout();
//			return -1;
//		}
//		end = chrono::high_resolution_clock::now();
//		duration = chrono::duration_cast<chrono::milliseconds>(end - start);
//		cout << "Generating symmetric key..." << flush;
//		cout << "\tOK (took " << duration.count() << " ms)" << " ID:" << key1.id << flush;
//		cout << " Symmetric key: " << key1.data << flush << endl;
//
//		cout << "\n The transmitter receives public display and form." << endl << flush;
//		cout << "With this information it encrypts the symmetric key in" << endl << flush;
//		cout << "on-the-fly mode." << endl;
//
//		cout << "Encrypting symmetric key..." << flush;
//		start = chrono::high_resolution_clock::now();
//		try {
//			l1->L1Encrypt(plainLen, plainText, cipher,
//					L1Algorithms::Algorithms::RSA, 0, keyToGet, true);
//		} catch (L1Exception& e) {
//			cout << " FAIL" << endl;
//			return 1;
//		}
//		end = chrono::high_resolution_clock::now();
//		duration = chrono::duration_cast<chrono::milliseconds>(end - start);
//		cout << "\t\tOK (took " << duration.count() << " ms) (ciphertext=";
//		for (auto i = 0; i < (int)cipher.ciphertext_size; i++) {
//			printf("%X", cipher.ciphertext[i]);
//		}
//		cout << ")" << endl;
//
//		cout << "\n The receiver receives the ciphertext containing the " << endl << flush;
//		cout << "symmetric key to be used for communication." << endl;
//
//		cout << "Decrypting ciphertext to get key..." << flush;
//		start = chrono::high_resolution_clock::now();
//		try {
//			l1->L1Decrypt(cipher, decipheredLen, deciphered, false);
//		} catch (L1Exception& e) {
//			cout << "\tFAIL" << endl;
//			return 1;
//		}
//		end = chrono::high_resolution_clock::now();
//		duration = chrono::duration_cast<chrono::milliseconds>(end - start);
//		cout << "\tOK (took " << duration.count() <<
//				" ms) (deciphered=";
//		for(int i = 0 ; i < (int)decipheredLen ; ++i ){
//			printf("%c",deciphered[i]);
//		}
//		cout << ")" << endl;
//
//		cout << "\nRSA key distribution demo successfully completed" << endl;
//	} else {
//	cout << "You entered an invalid number. Quit." << endl;
//	}
//	return 0;
//}
