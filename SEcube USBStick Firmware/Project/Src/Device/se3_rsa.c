#include <se3_rsa.h>
#include "se3c1def.h"
#include "se3_flash.h"
#include "se3_rsa_keys.h"
#include "rsa.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/pk.h"
#include "mbedtls/rsa.h"
#include "mbedtls/bignum.h"
#include "se3_rand.h"
#include "se3_x509.h"
#include "se3_keys.h"
#include <string.h>

#define SE3_RSA_X509_BUFF_SIZE 2048

/**
 * \brief import an RSA context reading key data from flash.
 *
 * \param[in] id		the ID associated with the key to be imported.
 * \param[in, out] ctx	the initialized RSA context to store the parameters in.
 * \param[out] key_type	the type of the imported key.
 *
 * \return 				SE3_RET_SUCCESS in case of success; error code otherwise.
 */
static uint16_t se3_rsa_context_read(int id, rsa_context *ctx, uint8_t *key_type)
{
	se3_rsa_flash_key key;
	se3_flash_it it;
	uint8_t N[SE3_RSA_MAX_KEY_SIZE_BYTES];
	uint8_t D[SE3_RSA_MAX_KEY_SIZE_BYTES];
	uint8_t E[SE3_RSA_MAX_KEY_SIZE_BYTES];

	key.N = N;
	key.D = D;
	key.E = E;

	if (!se3_rsa_key_find(id, &it))
		return SE3_ERR_KEY_NOT_FOUND;

	se3_rsa_key_read(&it, &key);

	*key_type = key.type;

	if (key.public_only)
		key.D = NULL;

	return rsa_import(ctx, key.key_size, key.N, key.D, key.E);
}

/**
 * \brief export an RSA key from context and store it to flash.
 *
 * \param[in] id			the ID to associate the key with.
 * \param[in] public_only	the boolean value specifying whether the key
 * 							is public only (1) or not (0).
 * 	\param[in] key_type		the type of the key.
 * 	\param[in] ctx			the context from which the key has to be exported.
 *
 * \return 					SE3_RET_SUCCESS in case of success; error code otherwise.
 */
static uint16_t se3_rsa_context_write(int id, const uint8_t public_only,
		const uint8_t key_type, rsa_context *ctx)
{
	se3_rsa_flash_key key;
	se3_flash_it it;
	int ret;

	key.id = id;
	key.key_size = rsa_get_len(ctx);
	key.type = key_type;
	key.public_only = public_only;

	key.N = malloc(key.key_size * sizeof(*(key.N)));
	key.E = malloc(key.key_size * sizeof(*(key.E)));
	if (public_only) {
		key.D = NULL;
	} else {
		key.D = malloc(key.key_size * sizeof(*(key.D)));
	}

	do {
		if ((ret = rsa_export(ctx, key.N, key.key_size, key.D,
				key.key_size, key.E, key.key_size)) != SE3_RET_SUCCESS) {
			break;
		}

		se3_flash_it_init(&it);
		if (!se3_rsa_key_new(&it, &key))
			ret = SE3_ERR_MEMORY;
	} while (0);

	free(key.N);
	free(key.E);
	free(key.D);

	return ret;
}

uint16_t se3_rsa_keygen(uint16_t req_size, const uint8_t* req,
		uint16_t* resp_size, uint8_t* resp)
{
	rsa_context ctx;
	uint32_t key_id;
	uint16_t key_size;
	uint8_t key_type;
	se3_flash_it it;
	uint16_t ret = SE3_RET_SUCCESS;

	*resp_size = 0;
	do {
		if (req_size != SE3_RSA_KEYGEN_REQ_SIZE) {
			ret = SE3_ERR_INPUT;
			break;
		}

		// parse input buffer
		memcpy(&key_id, req, sizeof(key_id));
		req += sizeof(key_id);
		memcpy(&key_size, req, sizeof(key_size));
		req += sizeof(key_size);
		memcpy(&key_type, req, sizeof(key_type));

		if (se3_rsa_key_find(key_id, &it)) {
			ret = SE3_ERR_KEY_DUPLICATE;
			break;
		}

		ret = SE3_ERR_KEY_SIZE;
		for (int i = 0; i < SE3_RSA_VALID_KEY_SIZES_N; i++) {
			if ((key_size * 8) == SE3_RSA_VALID_KEY_SIZES[i]) {
				ret = SE3_RET_SUCCESS;
				break;
			}
		}

		if (ret != SE3_RET_SUCCESS)
			break;

		rsa_init(&ctx);

		if ((ret = rsa_gen_key(&ctx, (key_size * 8), SE3_RSA_EXPONENT)) != SE3_RET_SUCCESS)
			break;

		if ((ret = se3_rsa_context_write(key_id, 0, key_type, &ctx)) != SE3_RET_SUCCESS)
			break;

		// fill output buffer
		memcpy(resp, SE3_RESP_SUCCESS, strlen(SE3_RESP_SUCCESS));
		*resp_size = strlen(SE3_RESP_SUCCESS);
	} while (0);

	rsa_free(&ctx);

	return ret;
}

uint16_t se3_rsa_keyadd(uint16_t req_size, const uint8_t* req,
		uint16_t* resp_size, uint8_t* resp)
{
	rsa_context ctx;
	se3_rsa_flash_key key;
	uint16_t key_data_size;
	se3_flash_it it;
	uint16_t ret = SE3_RET_SUCCESS;

	// parse input buffer
	memcpy(&(key.id), req, sizeof(key.id));
	req += sizeof(key.id);
	memcpy(&(key.key_size), req, sizeof(key.key_size));
	req += sizeof(key.key_size);
	memcpy(&(key.type), req, sizeof(key.type));
	req += sizeof(key.type);
	key.N = req;
	req += key.key_size;
	key.E = req;
	req += key.key_size;
	key.D = req;

	*resp_size = 0;
	do {
		key_data_size = (req_size - sizeof(key.id) -
				sizeof(key.type) - sizeof(key.key_size));
		if (key_data_size == (2 * key.key_size)) {
			key.public_only = true;
			key.D = NULL;
		} else if (key_data_size == (3 * key.key_size)) {
			key.public_only = false;
		} else {
			ret = SE3_ERR_INPUT;
			break;
		}

		if (se3_rsa_key_find(key.id, &it)) {
			ret = SE3_ERR_KEY_DUPLICATE;
			break;
		}

		rsa_init(&ctx);

		if ((ret = rsa_import(&ctx, key.key_size, key.N, key.D, key.E)) != SE3_RET_SUCCESS)
			break;

		if ((ret = se3_rsa_context_write(key.id, key.public_only, key.type, &ctx)) != SE3_RET_SUCCESS)
			break;

		// fill output buffer
		memcpy(resp, SE3_RESP_SUCCESS, strlen(SE3_RESP_SUCCESS));
		*resp_size = strlen(SE3_RESP_SUCCESS);
	} while (0);

	rsa_free(&ctx);

	return ret;
}

uint16_t se3_rsa_keyget(uint16_t req_size, const uint8_t* req,
		uint16_t* resp_size, uint8_t* resp)
{
	uint16_t ret = SE3_RET_SUCCESS;
	uint32_t id;
	se3_flash_it it;
	se3_rsa_flash_key key;
	uint8_t N[SE3_RSA_MAX_KEY_SIZE_BYTES];
	uint8_t D[SE3_RSA_MAX_KEY_SIZE_BYTES];
	uint8_t E[SE3_RSA_MAX_KEY_SIZE_BYTES];

	*resp_size = 0;
	do {
		if (req_size != SE3_RSA_KEYGET_REQ_SIZE) {
			ret = SE3_ERR_INPUT;
			break;
		}

		// parse input buffer
		memcpy(&id, req, sizeof(id));

		if (!se3_rsa_key_find(id, &it)) {
			ret = SE3_ERR_KEY_NOT_FOUND;
			break;
		}

		// read key from flash
		key.N = N;
		key.D = D;
		key.E = E;
		se3_rsa_key_read(&it, &key);

		// fill output buffer
		memcpy(resp, N, key.key_size);
		resp += key.key_size;
		*resp_size += key.key_size;
		memcpy(resp, E, key.key_size);
		*resp_size += key.key_size;
	} while (0);

	return ret;
}

uint16_t se3_rsa_operate(uint16_t req_size, const uint8_t* req,
		uint16_t* resp_size, uint8_t* resp)
{
	uint8_t operation;
	uint8_t public_key;
	uint8_t on_the_fly;
	uint16_t key_size;
	uint8_t *N;
	uint8_t *E;
	uint8_t *D;
	uint32_t id;
	uint32_t sim_id;
	size_t length_in;
	rsa_context ctx;
	uint8_t key_type;
	const unsigned char *text;
	const unsigned char *signature;
	uint16_t ret = SE3_RET_SUCCESS;
	se3_flash_it it;
	se3_flash_key plain;
	uint8_t data[16];

	// parse input buffer
	memcpy(&operation, req, sizeof(operation));
	req += sizeof(operation);
	public_key = ((operation == SE3_RSA_ENCRYPT) || (operation == SE3_RSA_VERIFY));
	memcpy(&on_the_fly, req, sizeof(on_the_fly));
	req += sizeof(on_the_fly);

	*resp_size = 0;
	do {
		if (on_the_fly) {
			memcpy(&key_size, req, sizeof(key_size));
			req += sizeof(key_size);
			N = req;
			req += key_size;
			E = req;
			req += key_size;
			if (public_key) {
				D = NULL;
			} else {
				D = req;
				req += key_size;
			}

			length_in = (req_size - (sizeof(operation) + sizeof(on_the_fly) +
						sizeof(key_size) + ((2 + (!public_key)) * key_size)));

			if ((ret = rsa_import(&ctx, key_size, N, D, E)) != SE3_RET_SUCCESS)
				break;
		} else {
			memcpy(&id, req, sizeof(id));
			req += sizeof(id);

			length_in = (req_size - (sizeof(operation) + sizeof(on_the_fly) + sizeof(id)));

			// read keys associated with id from flash
			if ((ret = se3_rsa_context_read(id, &ctx, &key_type)) != 0)
				break;

			if (((key_type == SE3_RSA_KEY_CRYPT) &&
						((operation == SE3_RSA_SIGN) || (operation == SE3_RSA_VERIFY))) ||
					((key_type == SE3_RSA_KEY_SIGN) &&
					 ((operation == SE3_RSA_ENCRYPT) || (operation == SE3_RSA_DECRYPT)))) {
				ret = SE3_ERR_INPUT;
				break;
			}
		}

		if (length_in <= 0) {
			ret = SE3_ERR_INPUT;
			break;
		}

		text = req;

		switch (operation) {
			case SE3_RSA_ENCRYPT:
				ret = rsa_encrypt(&ctx, text, length_in, resp);
				*resp_size = rsa_get_len(&ctx);
				break;
			case SE3_RSA_DECRYPT:
				ret = rsa_decrypt(&ctx, text, resp, (size_t *)resp_size,
						length_in);
				break;
			case SE3_RSA_SIGN:
				ret = rsa_sign(&ctx, text, length_in, resp);
				*resp_size = rsa_get_len(&ctx);
				break;
			case SE3_RSA_VERIFY:
				length_in -= rsa_get_len(&ctx);

				if (length_in <= 0) {
					ret = SE3_ERR_INPUT;
					break;
				}

				signature = (text + length_in);
				ret = rsa_verify(&ctx, text, length_in, signature);
				*resp_size = (ret == 0);
				break;
			default:
				ret = SE3_ERR_UNKNOWN_OP;
		}
	} while (0);

	rsa_free(&ctx);

	return ret;
}

uint16_t se3_rsa_x509_cert_gen(uint16_t req_size, const uint8_t* req,
		uint16_t* resp_size, uint8_t* resp)
{
	uint8_t *req_ptr;
	uint32_t cert_id;
	uint32_t issuer_key_id;
	uint32_t subject_key_id;
	const char *serial_str;
	const char *not_before;
	const char *not_after;
	uint16_t issuer_name_len;
	const char *issuer_name;
	uint16_t subject_name_len;
	const char *subject_name;
	mbedtls_x509write_cert crt;
	mbedtls_pk_context subject_key;
	mbedtls_pk_context issuer_key;
	mbedtls_rsa_context *subject_rsa_key;
	mbedtls_rsa_context *issuer_rsa_key;
	uint8_t key_type;
	mbedtls_mpi serial;
	unsigned char cert_buff[SE3_RSA_X509_BUFF_SIZE];
	se3_flash_x509 cert;
	se3_flash_it it;
	uint16_t ret = SE3_RET_SUCCESS;

	req_ptr = req;

	// parse input buffer
	memcpy(&cert_id, req_ptr, sizeof(cert_id));
	req_ptr += sizeof(cert_id);
	memcpy(&issuer_key_id, req_ptr, sizeof(issuer_key_id));
	req_ptr += sizeof(issuer_key_id);
	memcpy(&subject_key_id, req_ptr, sizeof(subject_key_id));
	req_ptr += sizeof(subject_key_id);
	serial_str = (char *)req_ptr;
	req_ptr += SE3_RSA_X509_SERIAL_SIZE + 1;
	not_before = (char *)req_ptr;
	req_ptr += SE3_RSA_X509_DATE_SIZE + 1;
	not_after = (char *)req_ptr;
	req_ptr += SE3_RSA_X509_DATE_SIZE + 1;
	memcpy(&issuer_name_len, req_ptr, sizeof(issuer_name_len));
	req_ptr += sizeof(issuer_name_len);
	issuer_name = (char *)req_ptr;
	req_ptr += issuer_name_len + 1;
	memcpy(&subject_name_len, req_ptr, sizeof(subject_name_len));
	req_ptr += sizeof(subject_name_len);
	subject_name = (char *)req_ptr;
	req_ptr += subject_name_len + 1;

	*resp_size = 0;
	do {
		if (req_size != (req_ptr - req)) {
			ret = SE3_ERR_INPUT;
			break;
		}

		// read RSA keys from flash
		mbedtls_pk_init(&subject_key);
		if ((ret = mbedtls_pk_setup(&subject_key, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA))) != SE3_RET_SUCCESS)
			break;
		subject_rsa_key = mbedtls_pk_rsa(subject_key);
		if ((ret = (subject_rsa_key == NULL)) != SE3_RET_SUCCESS)
			break;
		if ((ret = se3_rsa_context_read(subject_key_id, subject_rsa_key, &key_type)) != SE3_RET_SUCCESS)
			break;

		mbedtls_pk_init(&issuer_key);
		if ((ret = mbedtls_pk_setup(&issuer_key, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA))) != SE3_RET_SUCCESS)
			break;
		issuer_rsa_key = mbedtls_pk_rsa(issuer_key);
		if ((ret = (issuer_rsa_key == NULL)) != SE3_RET_SUCCESS)
			break;
		if ((ret = se3_rsa_context_read(issuer_key_id, issuer_rsa_key, &key_type)) != SE3_RET_SUCCESS)
			break;

		// set certificate parameters
		mbedtls_x509write_crt_init(&crt);
		mbedtls_mpi_init(&serial);
		if ((ret = mbedtls_mpi_read_string(&serial, 16, serial_str)) != SE3_RET_SUCCESS)
			break;
		if ((ret = mbedtls_x509write_crt_set_serial(&crt, &serial)) != SE3_RET_SUCCESS)
			break;
		if ((ret = mbedtls_x509write_crt_set_validity(&crt, not_before, not_after)) != SE3_RET_SUCCESS)
			break;
		if ((ret = mbedtls_x509write_crt_set_issuer_name(&crt, issuer_name)) != SE3_RET_SUCCESS)
			break;
		if ((ret = mbedtls_x509write_crt_set_subject_name(&crt, subject_name)) != SE3_RET_SUCCESS)
			break;
		mbedtls_x509write_crt_set_subject_key(&crt, &subject_key);
		mbedtls_x509write_crt_set_issuer_key(&crt, &issuer_key);
		mbedtls_x509write_crt_set_md_alg(&crt, MBEDTLS_MD_SHA256);

		// generate certificate string
		if ((ret = mbedtls_x509write_crt_pem(&crt, cert_buff, SE3_RSA_X509_BUFF_SIZE, se3_rand_mbedtls, NULL)) != SE3_RET_SUCCESS)
			break;

		// write certificate to flash
		cert.id = cert_id;
		cert.data_size = strlen((char *)cert_buff);
		cert.data = cert_buff;
		se3_flash_it_init(&it);
		if (!se3_x509_new(&it, &cert)) {
			ret = SE3_ERR_MEMORY;
			break;
		}

		memcpy(resp, SE3_RESP_SUCCESS, strlen(SE3_RESP_SUCCESS));
		*resp_size = strlen(SE3_RESP_SUCCESS);
	} while (0);

	mbedtls_mpi_free(&serial);
	mbedtls_x509write_crt_free(&crt);
	rsa_free(subject_rsa_key);
	mbedtls_pk_free(&subject_key);
	rsa_free(issuer_rsa_key);
	mbedtls_pk_free(&issuer_key);

	return ret;
}

uint16_t se3_rsa_x509_cert_find(uint16_t req_size, const uint8_t* req,
		uint16_t* resp_size, uint8_t* resp)
{
	uint32_t cert_id;
	se3_flash_it it;
	uint16_t ret = SE3_RET_SUCCESS;

	*resp_size = 0;
	do {
		if (req_size != SE3_RSA_X509_CERT_REQ_SIZE) {
			ret = SE3_ERR_INPUT;
			break;
		}

		// parse input buffer
		memcpy(&cert_id, req, sizeof(cert_id));

		*resp = se3_x509_find(cert_id, &it);
		*resp_size = 1;
	} while (0);

	return ret;
}

uint16_t se3_rsa_x509_cert_get(uint16_t req_size, const uint8_t* req,
		uint16_t* resp_size, uint8_t* resp)
{
	uint32_t cert_id;
	se3_flash_x509 cert;
	se3_flash_it it;
	uint16_t ret = SE3_RET_SUCCESS;

	*resp_size = 0;
	do {
		if (req_size != SE3_RSA_X509_CERT_REQ_SIZE) {
			ret = SE3_ERR_INPUT;
			break;
		}

		// parse input buffer
		memcpy(&cert_id, req, sizeof(cert_id));
		req += sizeof(cert_id);

		if ((ret = (!se3_x509_find(cert_id, &it))) != SE3_RET_SUCCESS)
			break;

		cert.data = resp;
		se3_x509_read(&it, &cert);

		*resp_size = strlen((char *)cert.data);
	} while (0);

	return ret;
}

uint16_t se3_rsa_x509_cert_delete(uint16_t req_size, const uint8_t* req,
		uint16_t* resp_size, uint8_t* resp)
{
	uint32_t cert_id;
	se3_flash_it it;
	uint16_t ret = SE3_RET_SUCCESS;

	// parse input buffer
	memcpy(&cert_id, req, sizeof(cert_id));
	req += sizeof(cert_id);

	*resp_size = 0;
	do {
		if ((ret = !se3_x509_find(cert_id, &it)) != SE3_RET_SUCCESS)
			break;

		if ((ret = !se3_flash_it_delete(&it)) != SE3_RET_SUCCESS)
			break;

		memcpy(resp, SE3_RESP_SUCCESS, strlen(SE3_RESP_SUCCESS));
		*resp_size = strlen(SE3_RESP_SUCCESS);
	} while (false);

	return ret;
}

uint16_t se3_rsa_x509_cert_list(uint16_t req_size, const uint8_t* req,
		uint16_t* resp_size, uint8_t* resp)
{
	uint16_t ret = SE3_RET_SUCCESS;

	*resp_size = 0;
	do {
		if (req_size != 0) {
			ret = SE3_ERR_INPUT;
			break;
		}

		*resp_size = (se3_x509_list((uint32_t *)resp) * sizeof(uint32_t));
	} while (0);

	return ret;
}
