#include <string.h>
#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/pem.h>

// generate public key (sm2) based on openssl hexstr

int main()
{
    
    char* x_hex = "A0:34:FF:1A:69:8F:90:86:FA:2C:05:1B:DB:E0:86:4F:55:82:B7:96:AC:8F:4C:A3:1D:68:81:6E:A1:02:B5:EB";
    char* y_hex = "3C:EC:B8:73:D4:32:96:56:C0:9E:25:BD:EA:8B:1D:FC:F6:E5:77:81:17:B6:F9:80:B5:EA:F3:E3:43:A9:29:CC";
    unsigned char* x_buffer = NULL;
    unsigned char* y_buffer = NULL;
    BIGNUM* x = NULL;
    BIGNUM* y = NULL;
    FILE* fp = NULL;

    EC_GROUP *ec_group = NULL;
    EC_KEY* ec_key = NULL;
    EVP_PKEY* evp_key = NULL;

    long y_len = 1024, x_len = 1024;

    ec_group = EC_GROUP_new_by_curve_name(NID_sm2);
    if (ec_group == NULL)
    {
        goto end;
    }

    x_buffer = OPENSSL_hexstr2buf(x_hex, &x_len);
    y_buffer = OPENSSL_hexstr2buf(y_hex, &y_len);

    if (x_buffer == NULL || y_buffer == NULL)
        goto end;

    x = BN_bin2bn(x_buffer, x_len, NULL);
    y = BN_bin2bn(y_buffer, y_len, NULL);
    if (NULL == x || NULL == y)
    {
        goto end;
    }

    if ((ec_key = EC_KEY_new()) == NULL) {
        goto end;
    }

    if ((evp_key = EVP_PKEY_new()) == NULL)
    {
        goto end;
    }

    if (!EC_KEY_set_group(ec_key, ec_group) ||
        !EC_KEY_set_public_key_affine_coordinates(ec_key, x, y) ||
        !EVP_PKEY_set1_EC_KEY(evp_key, ec_key) ||
        !EVP_PKEY_set_alias_type(evp_key, EVP_PKEY_SM2))
    {
        goto end;
    }

    fp = fopen("key.pem", "w+");
    if (NULL == fp)
    {
        goto end;
    }

    PEM_write_PUBKEY(fp, evp_key);

end:
    OPENSSL_free(x_buffer);
    OPENSSL_free(y_buffer);
    BN_clear(x);
    BN_clear(y);
    EC_KEY_free(ec_key);
    EVP_PKEY_free(evp_key);
    if (fp) fclose(fp);
    return 0;
}