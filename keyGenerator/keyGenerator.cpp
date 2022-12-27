#include <iostream>
#include <openssl/pem.h>
#include <openssl/applink.c> // importante si no no se ejecuta bien (no openssl applink)
// hay que poner _CRT_SECURE_NO_WARNINGS; en preprocessor definitions
int main()
{
    EVP_PKEY* pkey = EVP_RSA_gen(2048);
    FILE* file_privatekey;
    FILE* file_publickey;
    
    file_privatekey = fopen("privatekey.pem", "wb");
    PEM_write_PrivateKey(file_privatekey, pkey, NULL, NULL, 0, NULL, NULL); // si se quiere encriptar la clave, pasar EVP_des_ede3_cbc() en 3, password en 4 y longitud del pw en 5
    fclose(file_privatekey);
    
    file_publickey = fopen("publickey.pem", "wb");
    PEM_write_PUBKEY(file_publickey, pkey);
    fclose(file_publickey);

    
    X509* x509 = X509_new();

    // serial number a 1 (algunas conexiones no aceptan con 0)
    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);

    // fecha de validez
    X509_gmtime_adj(X509_getm_notBefore(x509), 0);
    X509_gmtime_adj(X509_getm_notAfter(x509), 31536000L); // 1 año

    // clave con la que se firma
    X509_set_pubkey(x509, pkey);
    
    // nombre del issuer
    X509_NAME* name = X509_get_subject_name(x509);

    // datos de organizacion
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (unsigned char*)"ES", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (unsigned char*)"Empresa", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char*)"localhost", -1, -1, 0);
    
    X509_set_issuer_name(x509, name);

    // firma
    X509_sign(x509, pkey, EVP_sha256());

    FILE* file_certificate;
    file_certificate = fopen("certificate.pem", "wb");
    PEM_write_X509(file_certificate, x509);  
    fclose(file_certificate);
    
    EVP_PKEY_free(pkey);
    X509_free(x509);

    return 0;
}