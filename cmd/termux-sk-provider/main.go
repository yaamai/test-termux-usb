package main

//#include <stddef.h>
//#include <stdint.h>
//typedef struct sk_option_s {
//	char *name;
//	char *value;
//	uint8_t required;
//} sk_option;
//typedef struct sk_enroll_response_s {
//	uint8_t *public_key;
//	size_t public_key_len;
//	uint8_t *key_handle;
//	size_t key_handle_len;
//	uint8_t *signature;
//	size_t signature_len;
//	uint8_t *attestation_cert;
//	size_t attestation_cert_len;
//} sk_enroll_response;

import "C"

//export ssh_sk_enroll
func ssh_sk_enroll(alg C.int, challenge *C.uint8_t, challenge_len C.size_t, application *C.char, flags C.uint8_t, pin *C.char, opts *C.sk_option, enroll_response *C.sk_enroll_response) int {
} 

func main() {}
    
//int sk_enroll(uint32_t alg, const uint8_t *challenge, size_t challenge_len,
//    const char *application, uint8_t flags, const char *pin,
//    struct sk_option **options, struct sk_enroll_response **enroll_response);
// int ssh_sk_sign(int alg, const uint8_t *message, size_t message_len,
//     const char *application,
//     const uint8_t *key_handle, size_t key_handle_len,
//     uint8_t flags, const char *pin, struct sk_option **opts,
//     struct sk_sign_response **sign_response);
// int ssh_sk_load_resident_keys(const char *pin, struct sk_option **opts,
//     struct sk_resident_key ***rks, size_t *nrks);
