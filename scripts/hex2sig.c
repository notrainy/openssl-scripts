#include <string.h>
#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/pem.h>

// hex code to sm2 signature (der format)

int main()
{
    int ret = 1;
    BIGNUM* r = NULL, *s = NULL;
    ECDSA_SIG* pstSig = NULL;
    unsigned char *der = NULL;
    int derlen = -1;
    FILE* fp = NULL;
    
    
    char* r_hex = "c1d09cd1078010b9b79457596a68525909d536c1ad777ab156261d34681659c1";
    char* s_hex = "fcd0e9995fea33ee3663643ee80ec664ef8c05d48d97fc4be5da3a84f3bab13c";

    if (!BN_hex2bn(&r, r_hex))
    {
        goto end;
    }
    if (!BN_hex2bn(&s, s_hex))
    {
        goto end;
    }
    if (NULL == r || NULL == s)
    {
        goto end;
    }

    pstSig = ECDSA_SIG_new();
    if (NULL == pstSig)
    {
        goto end;
    }

    if (!ECDSA_SIG_set0(pstSig, r, s))
    {
        goto end;
    }

    if ((derlen = i2d_ECDSA_SIG(pstSig, &der)) < 0)
    {
        goto end;
    }

    // write
    fp = fopen("sig.bin", "w+");
    if (NULL == fp)
    {
        goto end;
    }

    (void)fwrite(der, derlen, 1, fp);

    ret = 0;
end:
    OPENSSL_free(der);
    ECDSA_SIG_free(pstSig);
    if (fp) fclose(fp);
    if (ret == 1)
    {
        printf("failed\n");
    }
    else
    {
        printf("success\n");
    }


    return 0;
}