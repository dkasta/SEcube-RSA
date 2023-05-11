/**
  ******************************************************************************
  * File Name          : digital_signature.cpp
  * Description        : Usage example of RSA cipher.
  ******************************************************************************
  *
  * Copyright � 2016-present Blu5 Group <https://www.blu5group.com>
  *
  * This library is free software; you can redistribute it and/or
  * modify it under the terms of the GNU Lesser General Public
  * License as published by the Free Software Foundation; either
  * version 3 of the License, or (at your option) any later version.
  *
  * This library is distributed in the hope that it will be useful,
  * but WITHOUT ANY WARRANTY; without even the implied warranty of
  * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  * Lesser General Public License for more details.
  *
  * You should have received a copy of the GNU Lesser General Public
  * License along with this library; if not, see <https://www.gnu.org/licenses/>.
  *
  ******************************************************************************
  */

/*! \file  digital_signature.cpp
 *  \brief This file is an example about how to sign and verify a document
 *  \date 20/05/2021
 */

#include "../sources/L1/L1.h"
#include <chrono>
#include <memory>
#include <iostream>
#include <fstream>
#include <unistd.h>
#include <limits.h>

using namespace std;

#define KEY_SIZE (1024 / 8)

int main() {
	unique_ptr<L0> l0 = make_unique<L0>();
	unique_ptr<L1> l1 = make_unique<L1>();


	cout << "Welcome to SEcube RSA library usage example!" << endl;
	cout << "Looking for SEcube devices...\n" << endl;

	int numdevices = l0->GetNumberDevices(); // this API checks how many SEcube devices are connected to the PC
	if(numdevices == 0){
		cout << "No SEcube devices found! Quit." << endl;
		return 0;
	}

	vector<pair<string, string>> devices;
	int ret = l0->GetDeviceList(devices); // this API fills the vector with pairs including details about the devices (path and serial number)
	if(ret){
		cout << "Error while searching for SEcube devices! Quit." << endl;
		return -1;
	}
	cout << "Number of SEcube devices found: " << numdevices << endl;
	cout << "List of SEcube devices (path, serial number):" << endl;
	int index = 0;
	uint8_t empty_serial_number[L0Communication::Size::SERIAL];
	memset(empty_serial_number, 0, L0Communication::Size::SERIAL);
	for(pair<string, string> p : devices){
		if(p.second.empty() || memcmp(p.second.data(), empty_serial_number, L0Communication::Size::SERIAL)==0){
			cout << index << ") " << p.first << " - serial number not available (please initialize this SEcube)" << endl;
		} else {
			cout << index << ") " << p.first << " - " << p.second << endl;
		}
		index++;
	}

	int sel = 0;
	cout << "\nEnter the number corresponding to the SEcube device that you want to use..." << endl;
	/* warning: if cin does not wait for input in debug mode with eclipse, open the launch configuration and select
	 * the "use external console for inferior" checkbox under the debugger tab (see https://stackoverflow.com/questions/44283534/c-debug-mode-in-eclipse-causes-program-to-not-wait-for-cin)*/
	if(!(cin >> sel)){
		cout << "Input error...quit." << endl;
		return -1;
	}

	if((sel >= 0) && (sel < numdevices)){
		array<uint8_t, L0Communication::Size::SERIAL> sn;
		sn.fill(0);
		if(devices.at(sel).second.length() > L0Communication::Size::SERIAL){
			cout << "Unexpected error...quit." << endl;
			return -1;
		} else {
			memcpy(sn.data(), devices.at(sel).second.data(), devices.at(sel).second.length());
		}
		l1->L1SelectSEcube(sn); // select secube with correct serial number
		cout << "\nDevice " << devices.at(sel).first << " - " << devices.at(sel).second << " selected." << endl;

		array<uint8_t, 32> pin = {'t','e','s','t'}; // customize this PIN according to the PIN that you set on your SEcube device
		l1->L1Login(pin, SE3_ACCESS_USER, true); // login to the SEcube

		const auto plainTextStr = "Nel mezzo del cammin di nostra vita mi ritrovai per una selva oscura, ché la diritta via era smarrita. "
						"Ahi quanto a dir qual era è cosa dura esta selva selvaggia e aspra e forte che nel pensier rinova la paura! "
						"Tant’è amara che poco è più morte; ma per trattar del ben ch’i’ vi trovai, dirò de l’altre cose ch’i’ v’ ho scorte."
				        "Io non so ben ridir com’i’ v’intrai, tant’era pien di sonno a quel punto che la verace via abbandonai."
				        "Ma poi ch’i’ fui al piè d’un colle giunto, là dove terminava quella valle che m’avea di paura il cor compunto,"
				        "guardai in alto e vidi le sue spalle vestite già de’ raggi del pianeta che mena dritto altrui per ogne calle.";
		const size_t plainLen = (strlen(plainTextStr) + 1);
		shared_ptr<uint8_t[]> plainText = make_unique<uint8_t[]>(plainLen);
		SEcube_ciphertext cipher;
		shared_ptr<uint8_t[]> deciphered;
		const auto keyId = 43;
		se3Key key = {
				.id = keyId,
				.dataSize = KEY_SIZE,
				.asymmKey = {.type = L1Key::RSAKeyType::SE3_RSA_KEY_GENERIC}
		};

		memcpy(plainText.get(), plainTextStr, plainLen);

		cout << endl << endl;
		cout << "Digital signature demo. Sign the hash of the message with the private key." << endl;
		cout << "Another user can verify integrity using an on-the-fly option and the public key." << endl;
		cout << "Public key can be find in a certificate" << endl;
		cout << "Private key should be enabled for signing" << endl;
		cout << endl << endl;

		bool found;
		l1->L1FindKey(keyId, found);

		if (found) {
			try {
				cout << "Deleting RSA key..." << flush;
				se3Key keyToDel = {.id = keyId};
				l1->L1KeyEdit(keyToDel, L1Commands::KeyOpEdit::SE3_KEY_OP_DELETE);
			} catch (L1Exception& e) {
				cout << "\t\tFAIL" << endl;
				return 1;
			}
			cout << "\t\tOK" << endl;
			l1->L1FindKey(keyId, found);
		}

		cout << "Generating RSA key..." << flush;
		auto start = chrono::high_resolution_clock::now();
		try {
			l1->L1KeyEdit(key, L1Commands::KeyOpEdit::SE3_KEY_OP_ADD_GEN_RSA);
		} catch (L1Exception& e) {
			cout << "\t\tFAIL" << endl;
			return 1;
		}
		auto end = chrono::high_resolution_clock::now();
		auto duration = chrono::duration_cast<chrono::milliseconds>(end - start);
		cout << "\t\tOK (took " << duration.count() << " ms)" << endl;

		cout << "\n Getting public exponent and module to be sent with plaintext and signature." << endl;
		cout << "Public key will be embedded in a x.509 certificate." << endl;
		cout << "All this information are needed to verify the signature." << endl << flush;

		uint8_t N[256];
		uint8_t E[256];
		se3Key keyToGet = {.id = keyId, .asymmKey = {.N = N, .E = E}};
		cout << "Getting public key..." << flush;
		try {
			l1->L1AsymmKeyGet(keyToGet);
		} catch (L1Exception& e) {
			cout << " FAIL" << endl;
			return 1;
		}
		cout << "\t\tOK (N=";
		for (auto i = 0; i < keyToGet.dataSize; i++) {
			printf("%X", keyToGet.asymmKey.N[i]);
		}
		cout << "; E=";
		for (auto i = 0; i < keyToGet.dataSize; i++) {
			printf("%X", keyToGet.asymmKey.E[i]);
		}
		cout << ")" << endl;

		cout << "Signing plaintext..." << flush;

		shared_ptr<uint8_t[]> sign;
		size_t signLen;
		start = chrono::high_resolution_clock::now();
		try {
			l1->L1Sign(plainLen, plainText, key, false, signLen, sign);
		} catch (L1Exception& e) {
			cout << "\t\tFAIL" << endl;
			return 1;
		}
		end = chrono::high_resolution_clock::now();
		duration = chrono::duration_cast<chrono::milliseconds>(end - start);
		cout << "\t\tOK (took " << duration.count() << " ms) (signature=";
		for (auto i = 0; i < KEY_SIZE; i++) {
			printf("%X", sign[i]);
		}
		cout << ")" << endl;

		SEcube_certificate_info info = {
						.cert_id = 13,
						.issuer_key_id = keyId,
						.subject_key_id = keyId,
						.serial_str = "01234567890123456789",
						.not_before = "20190202171300",
						.not_after = "20250202171300",
						.issuer_name = "C=IT,O=PoliTO,CN=PoliTO CA",
						.subject_name = "C=IT,O=PoliTO,CN=PoliTO CA"
		};

		cout << "Generating X.509 certificate..." << flush;
		start = chrono::high_resolution_clock::now();
		try {
			l1->L1CertificateEdit(L1Commands::CertOpEdit::SE3_CERT_OP_ADD, info);
		} catch (L1Exception& e) {
			cout << "\tFAIL" << endl;
			return 1;
		}
		end = chrono::high_resolution_clock::now();
		duration = chrono::duration_cast<chrono::milliseconds>(end - start);
		cout << "\tOK (took " << duration.count() << " ms)" << endl;

		string cert;
		cout << "Getting X.509 certificate..." << flush;
		start = chrono::high_resolution_clock::now();
		try {
			l1->L1CertificateGet(13, cert);
		} catch (L1Exception& e) {
			cout << "\tFAIL" << endl;
			return 1;
		}
		end = chrono::high_resolution_clock::now();
		duration = chrono::duration_cast<chrono::milliseconds>(end - start);

		cout << "\n After sending all the information to receiver." << endl;
		cout << "The receiver verify the signature on-the-fly." << endl << flush;

		bool verified;
		cout << "Verifying signature (OTF)..." << flush;
		start = chrono::high_resolution_clock::now();
		try {
			l1->L1Verify(plainLen, plainText, keyToGet, true, signLen,
					sign, verified);
		} catch (L1Exception& e) {
			cout << "\tFAIL" << endl;
			return 1;
		}
		end = chrono::high_resolution_clock::now();
		duration = chrono::duration_cast<chrono::milliseconds>(end - start);
		cout << "\tOK (took " << duration.count() << " ms) (verified="
				<< verified << ")" << endl;

		cout << "Deleting X.509 certificate..." << flush;
		start = chrono::high_resolution_clock::now();
		try {
			l1->L1CertificateEdit(L1Commands::CertOpEdit::SE3_CERT_OP_DELETE, info);
		} catch (L1Exception& e) {
			cout << "\tFAIL" << endl;
			return 1;
		}
		end = chrono::high_resolution_clock::now();
		duration = chrono::duration_cast<chrono::milliseconds>(end - start);
		cout << "\tOK (took " << duration.count() << " ms)" << endl;

		cout << "\nDigital signature successfully completed" << endl;
	} else {
	cout << "You entered an invalid number. Quit." << endl;
	}
	return 0;
}
