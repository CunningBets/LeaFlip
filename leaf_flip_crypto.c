#include "leaf_flip.h"

#include <mbedtls/bignum.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/ecp.h>
#include <mbedtls/sha256.h>

void mbedtls_ct_memcpy_if(unsigned char condition, unsigned char *dest, const unsigned char *src, size_t len)
{
    unsigned char mask = (condition != 0) ? 0xFF : 0x00;
    volatile unsigned char *volatile_dest = dest;
    for (size_t i = 0; i < len; i++)
    {
        volatile_dest[i] = (unsigned char)((volatile_dest[i] & ~mask) | (src[i] & mask));
    }
}

#define ASN1_CONSTRUCTED 0x20
#define ASN1_SEQUENCE 0x30
#define ASN1_SET 0x31
#define ASN1_OID 0x06
#define ASN1_BIT_STRING 0x03

static const uint8_t leaf_root_public_key[LEAF_FLIP_PUBLIC_KEY_SIZE] = {
    0x04,
    0x2D,
    0x27,
    0x81,
    0xBE,
    0x41,
    0xC2,
    0x27,
    0x58,
    0xA6,
    0x13,
    0x81,
    0x0F,
    0x67,
    0xEC,
    0x78,
    0xDF,
    0x11,
    0x76,
    0xC4,
    0x76,
    0x5B,
    0x21,
    0x2B,
    0x49,
    0x21,
    0x8C,
    0x6C,
    0x58,
    0x40,
    0x8A,
    0x5A,
    0xDA,
    0x3D,
    0x99,
    0x73,
    0x20,
    0x9D,
    0x82,
    0x28,
    0x91,
    0x3A,
    0x88,
    0x16,
    0x97,
    0x3C,
    0xFE,
    0x5C,
    0x9E,
    0xBF,
    0xD8,
    0xC6,
    0x69,
    0x75,
    0x32,
    0xCD,
    0xD5,
    0xB5,
    0x3E,
    0xE1,
    0x34,
    0xD2,
    0xF1,
    0x1B,
    0x3C,
};

typedef struct
{
    uint8_t tag;
    const uint8_t *raw;
    size_t raw_len;
    const uint8_t *value;
    size_t value_len;
} DerTlv;

typedef struct
{
    const uint8_t *tbs;
    size_t tbs_len;
    const uint8_t *cert_signature_der;
    size_t cert_signature_der_len;
} LeafFlipCertParts;

static bool der_next(const uint8_t **cursor, const uint8_t *end, DerTlv *tlv)
{
    const uint8_t *start = *cursor;
    if (start >= end)
        return false;
    uint8_t tag = *(*cursor)++;
    if (*cursor >= end)
        return false;

    uint8_t len_byte = *(*cursor)++;
    size_t len = 0;
    if ((len_byte & 0x80) == 0)
    {
        len = len_byte;
    }
    else
    {
        size_t len_len = len_byte & 0x7F;
        if (len_len == 0 || len_len > 3 || (size_t)(end - *cursor) < len_len)
            return false;
        for (size_t i = 0; i < len_len; i++)
        {
            len = (len << 8) | *(*cursor)++;
        }
    }
    if ((size_t)(end - *cursor) < len)
        return false;

    tlv->tag = tag;
    tlv->raw = start;
    tlv->value = *cursor;
    tlv->value_len = len;
    *cursor += len;
    tlv->raw_len = *cursor - start;
    return true;
}

static bool oid_is_serial_number(const DerTlv *oid)
{
    static const uint8_t serial_oid[] = {0x55, 0x04, 0x05};
    return oid->tag == ASN1_OID && oid->value_len == sizeof(serial_oid) &&
           memcmp(oid->value, serial_oid, sizeof(serial_oid)) == 0;
}

static bool oid_is_common_name(const DerTlv *oid)
{
    static const uint8_t cn_oid[] = {0x55, 0x04, 0x03};
    return oid->tag == ASN1_OID && oid->value_len == sizeof(cn_oid) &&
           memcmp(oid->value, cn_oid, sizeof(cn_oid)) == 0;
}

static void copy_printable_value(char *out, size_t out_size, const DerTlv *value)
{
    size_t copy_len = MIN(value->value_len, out_size - 1);
    memcpy(out, value->value, copy_len);
    out[copy_len] = '\0';
}

static bool parse_name(
    const DerTlv *name,
    char *open_id,
    size_t open_id_size,
    char *cn,
    size_t cn_size)
{
    if (open_id && open_id_size)
        open_id[0] = '\0';
    if (cn && cn_size)
        cn[0] = '\0';
    const uint8_t *rdn_cursor = name->value;
    const uint8_t *name_end = name->value + name->value_len;
    while (rdn_cursor < name_end)
    {
        DerTlv rdn;
        if (!der_next(&rdn_cursor, name_end, &rdn) || rdn.tag != ASN1_SET)
            return false;
        const uint8_t *attr_cursor = rdn.value;
        const uint8_t *rdn_end = rdn.value + rdn.value_len;
        while (attr_cursor < rdn_end)
        {
            DerTlv attr;
            if (!der_next(&attr_cursor, rdn_end, &attr) || attr.tag != ASN1_SEQUENCE)
                return false;
            const uint8_t *field_cursor = attr.value;
            const uint8_t *attr_end = attr.value + attr.value_len;
            DerTlv oid;
            DerTlv value;
            if (!der_next(&field_cursor, attr_end, &oid))
                return false;
            if (!der_next(&field_cursor, attr_end, &value))
                return false;
            if (open_id && open_id_size && oid_is_serial_number(&oid))
            {
                copy_printable_value(open_id, open_id_size, &value);
            }
            else if (cn && cn_size && oid_is_common_name(&oid))
            {
                copy_printable_value(cn, cn_size, &value);
            }
        }
    }
    return true;
}

static bool parse_spki_public_key(const DerTlv *spki, uint8_t public_key[LEAF_FLIP_PUBLIC_KEY_SIZE])
{
    const uint8_t *cursor = spki->value;
    const uint8_t *end = spki->value + spki->value_len;
    DerTlv algorithm;
    DerTlv bit_string;
    if (!der_next(&cursor, end, &algorithm) || algorithm.tag != ASN1_SEQUENCE)
        return false;
    if (!der_next(&cursor, end, &bit_string) || bit_string.tag != ASN1_BIT_STRING)
        return false;
    if (bit_string.value_len != LEAF_FLIP_PUBLIC_KEY_SIZE + 1 || bit_string.value[0] != 0x00)
    {
        return false;
    }
    memcpy(public_key, bit_string.value + 1, LEAF_FLIP_PUBLIC_KEY_SIZE);
    return public_key[0] == 0x04;
}

static bool parse_tbs_certificate(const DerTlv *tbs, LeafFlipResult *result)
{
    const uint8_t *cursor = tbs->value;
    const uint8_t *end = tbs->value + tbs->value_len;
    DerTlv field;

    /* Optional explicit version [0] */
    if (!der_next(&cursor, end, &field))
        return false;
    if (field.tag == (ASN1_CONSTRUCTED | 0x80))
    {
        if (!der_next(&cursor, end, &field))
            return false;
    }
    /* field is now serial number; advance past signature alg */
    if (!der_next(&cursor, end, &field))
        return false;
    /* issuer */
    if (!der_next(&cursor, end, &field) || field.tag != ASN1_SEQUENCE)
        return false;
    parse_name(&field, NULL, 0, result->issuer_cn, sizeof(result->issuer_cn));
    /* validity */
    if (!der_next(&cursor, end, &field))
        return false;
    /* subject */
    if (!der_next(&cursor, end, &field) || field.tag != ASN1_SEQUENCE)
        return false;
    if (!parse_name(&field, result->open_id, sizeof(result->open_id), result->subject_cn, sizeof(result->subject_cn)))
        return false;
    if (result->open_id[0] == '\0')
        return false;
    /* SPKI */
    if (!der_next(&cursor, end, &field) || field.tag != ASN1_SEQUENCE)
        return false;
    return parse_spki_public_key(&field, result->public_key);
}

static bool parse_certificate(
    const uint8_t *cert,
    size_t cert_len,
    LeafFlipResult *result,
    LeafFlipCertParts *parts)
{
    const uint8_t *cursor = cert;
    const uint8_t *end = cert + cert_len;
    DerTlv cert_seq;
    DerTlv tbs;
    DerTlv sig_alg;
    DerTlv sig_value;

    if (!der_next(&cursor, end, &cert_seq) || cert_seq.tag != ASN1_SEQUENCE)
        return false;
    cursor = cert_seq.value;
    end = cert_seq.value + cert_seq.value_len;
    if (!der_next(&cursor, end, &tbs) || tbs.tag != ASN1_SEQUENCE)
    {
        return false;
    }
    if (!der_next(&cursor, end, &sig_alg) || sig_alg.tag != ASN1_SEQUENCE)
    {
        return false;
    }
    if (!der_next(&cursor, end, &sig_value) || sig_value.tag != ASN1_BIT_STRING)
    {
        return false;
    }
    if (sig_value.value_len < 2 || sig_value.value[0] != 0x00)
        return false;

    parts->tbs = tbs.raw;
    parts->tbs_len = tbs.raw_len;
    parts->cert_signature_der = sig_value.value + 1;
    parts->cert_signature_der_len = sig_value.value_len - 1;

    return parse_tbs_certificate(&tbs, result);
}

static bool verify_signature_values(
    const uint8_t public_key[LEAF_FLIP_PUBLIC_KEY_SIZE],
    const uint8_t *message,
    size_t message_len,
    const uint8_t *r_value,
    size_t r_len,
    const uint8_t *s_value,
    size_t s_len)
{
    bool verified = false;
    uint8_t hash[32];
    mbedtls_ecp_group group;
    mbedtls_ecp_point q;
    mbedtls_mpi r;
    mbedtls_mpi s;
    mbedtls_ecp_group_init(&group);
    mbedtls_ecp_point_init(&q);
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);
    mbedtls_sha256(message, message_len, hash, 0);
    do
    {
        if (mbedtls_ecp_group_load(&group, MBEDTLS_ECP_DP_SECP256R1) != 0)
            break;
        if (mbedtls_ecp_point_read_binary(&group, &q, public_key, LEAF_FLIP_PUBLIC_KEY_SIZE) != 0)
            break;
        if (mbedtls_mpi_read_binary(&r, r_value, r_len) != 0)
            break;
        if (mbedtls_mpi_read_binary(&s, s_value, s_len) != 0)
            break;
        verified = mbedtls_ecdsa_verify(&group, hash, sizeof(hash), &q, &r, &s) == 0;
    } while (false);
    mbedtls_mpi_free(&s);
    mbedtls_mpi_free(&r);
    mbedtls_ecp_point_free(&q);
    mbedtls_ecp_group_free(&group);
    return verified;
}

static bool verify_raw_signature(
    const uint8_t public_key[LEAF_FLIP_PUBLIC_KEY_SIZE],
    const uint8_t *message,
    size_t message_len,
    const uint8_t signature[LEAF_FLIP_SIGNATURE_SIZE])
{
    return verify_signature_values(public_key, message, message_len, signature, 32, signature + 32, 32);
}

static bool verify_der_signature(
    const uint8_t public_key[LEAF_FLIP_PUBLIC_KEY_SIZE],
    const uint8_t *message,
    size_t message_len,
    const uint8_t *signature_der,
    size_t signature_der_len)
{
    const uint8_t *cursor = signature_der;
    const uint8_t *end = signature_der + signature_der_len;
    DerTlv sig_seq;
    DerTlv r;
    DerTlv s;
    if (!der_next(&cursor, end, &sig_seq) || sig_seq.tag != ASN1_SEQUENCE)
        return false;
    cursor = sig_seq.value;
    end = sig_seq.value + sig_seq.value_len;
    if (!der_next(&cursor, end, &r) || r.tag != 0x02)
        return false;
    if (!der_next(&cursor, end, &s) || s.tag != 0x02)
        return false;
    return verify_signature_values(
        public_key, message, message_len, r.value, r.value_len, s.value, s.value_len);
}

bool leaf_flip_parse_and_verify_certificate(LeafFlipApp *app)
{
    LeafFlipCertParts parts;
    memset(&parts, 0, sizeof(parts));
    if (!parse_certificate(app->result.cert, app->result.cert_len, &app->result, &parts))
    {
        leaf_flip_set_error(app, "Certificate parse failed");
        return false;
    }
    app->result.root_verified = verify_der_signature(
        leaf_root_public_key, parts.tbs, parts.tbs_len, parts.cert_signature_der, parts.cert_signature_der_len);
    if (!app->result.root_verified)
    {
        leaf_flip_set_error(app, "Root signature check failed");
        return false;
    }
    return true;
}

bool leaf_flip_verify_card_signature(LeafFlipApp *app)
{
    uint8_t message[36];
    message[0] = 0xF0;
    message[1] = 0xF0;
    message[2] = 0x80;
    message[3] = 0x00;
    memcpy(message + 4, app->result.card_random, LEAF_FLIP_RANDOM_SIZE);
    memcpy(message + 20, app->result.challenge, LEAF_FLIP_RANDOM_SIZE);
    app->result.card_verified = verify_raw_signature(
        app->result.public_key, message, sizeof(message), app->result.signature);
    if (!app->result.card_verified)
    {
        leaf_flip_set_error(app, "Card signature check failed");
        return false;
    }
    return true;
}

bool leaf_flip_reparse_loaded(LeafFlipApp *app)
{
    LeafFlipCertParts parts;
    memset(&parts, 0, sizeof(parts));
    if (app->result.cert_len == 0)
        return false;
    if (!parse_certificate(app->result.cert, app->result.cert_len, &app->result, &parts))
        return false;
    app->result.root_verified = verify_der_signature(
        leaf_root_public_key, parts.tbs, parts.tbs_len, parts.cert_signature_der, parts.cert_signature_der_len);

    uint8_t message[36];
    message[0] = 0xF0;
    message[1] = 0xF0;
    message[2] = 0x80;
    message[3] = 0x00;
    memcpy(message + 4, app->result.card_random, LEAF_FLIP_RANDOM_SIZE);
    memcpy(message + 20, app->result.challenge, LEAF_FLIP_RANDOM_SIZE);
    app->result.card_verified = verify_raw_signature(
        app->result.public_key, message, sizeof(message), app->result.signature);
    return true;
}
