#include "leaf_flip.h"

#define TAG "LeafFlipSave"

static void leaf_flip_hex_to_string(FuriString *out, const uint8_t *data, size_t len)
{
    furi_string_reset(out);
    for (size_t i = 0; i < len; i++)
    {
        furi_string_cat_printf(out, "%02X", data[i]);
    }
}

bool leaf_flip_save_result(LeafFlipApp *app, const char *filename)
{
    LeafFlipResult *result = &app->result;
    if (!app->result_loaded || result->open_id[0] == '\0' || result->cert_len == 0)
    {
        return false;
    }

    if (!storage_simply_mkdir(app->storage, LEAF_FLIP_APP_FOLDER))
    {
        FURI_LOG_W(TAG, "mkdir %s failed (may already exist)", LEAF_FLIP_APP_FOLDER);
    }

    bool saved = false;
    FlipperFormat *file = flipper_format_file_alloc(app->storage);
    FuriString *path = furi_string_alloc();
    FuriString *value = furi_string_alloc();

    do
    {
        furi_string_printf(path, "%s/%s%s", LEAF_FLIP_APP_FOLDER, filename, LEAF_FLIP_FILE_EXT);
        if (!flipper_format_file_open_always(file, furi_string_get_cstr(path)))
            break;
        if (!flipper_format_write_header_cstr(file, LEAF_FLIP_FILE_HEADER, 1))
            break;

        furi_string_set_str(value, result->open_id);
        if (!flipper_format_write_string(file, "Open ID", value))
            break;
        furi_string_set_str(value, result->subject_cn);
        if (!flipper_format_write_string(file, "Subject CN", value))
            break;
        furi_string_set_str(value, result->issuer_cn);
        if (!flipper_format_write_string(file, "Issuer CN", value))
            break;
        leaf_flip_hex_to_string(value, result->uid, result->uid_len);
        if (!flipper_format_write_string(file, "CSN", value))
            break;
        if (!flipper_format_write_hex(file, "Public Key", result->public_key, LEAF_FLIP_PUBLIC_KEY_SIZE))
            break;
        if (!flipper_format_write_hex(file, "Challenge", result->challenge, LEAF_FLIP_RANDOM_SIZE))
            break;
        if (!flipper_format_write_hex(file, "Card Random", result->card_random, LEAF_FLIP_RANDOM_SIZE))
            break;
        if (!flipper_format_write_hex(file, "Signature", result->signature, LEAF_FLIP_SIGNATURE_SIZE))
            break;
        if (!flipper_format_write_hex(file, "Auth Response", result->auth_response, result->auth_response_len))
            break;
        if (!flipper_format_write_hex(file, "Certificate", result->cert, result->cert_len))
            break;
        saved = true;
    } while (false);

    if (!saved)
    {
        FURI_LOG_E(TAG, "Save failed: %s", furi_string_get_cstr(path));
    }
    else
    {
        FURI_LOG_I(TAG, "Saved to %s", furi_string_get_cstr(path));
    }

    furi_string_free(value);
    furi_string_free(path);
    flipper_format_free(file);
    return saved;
}

bool leaf_flip_load_result(LeafFlipApp *app, const char *path)
{
    LeafFlipResult *result = &app->result;
    memset(result, 0, sizeof(*result));

    bool ok = false;
    FlipperFormat *file = flipper_format_file_alloc(app->storage);
    FuriString *value = furi_string_alloc();
    uint32_t version = 0;

    do
    {
        if (!flipper_format_file_open_existing(file, path))
            break;
        if (!flipper_format_read_header(file, value, &version))
            break;
        if (strcmp(furi_string_get_cstr(value), LEAF_FLIP_FILE_HEADER) != 0)
            break;

        /* Required fields */
        if (!flipper_format_read_string(file, "Open ID", value))
            break;
        strncpy(result->open_id, furi_string_get_cstr(value), sizeof(result->open_id) - 1);

        /* Optional readable fields (continue if missing for forward compat) */
        if (flipper_format_read_string(file, "Subject CN", value))
            strncpy(result->subject_cn, furi_string_get_cstr(value), sizeof(result->subject_cn) - 1);
        if (flipper_format_read_string(file, "Issuer CN", value))
            strncpy(result->issuer_cn, furi_string_get_cstr(value), sizeof(result->issuer_cn) - 1);

        if (flipper_format_read_string(file, "CSN", value))
        {
            const char *hex = furi_string_get_cstr(value);
            size_t hex_len = strlen(hex);
            result->uid_len = MIN(hex_len / 2, (size_t)LEAF_FLIP_UID_MAX);
            for (size_t i = 0; i < result->uid_len; i++)
            {
                unsigned int byte = 0;
                sscanf(hex + i * 2, "%2x", &byte);
                result->uid[i] = (uint8_t)byte;
            }
        }

        flipper_format_read_hex(file, "Public Key", result->public_key, LEAF_FLIP_PUBLIC_KEY_SIZE);
        flipper_format_read_hex(file, "Challenge", result->challenge, LEAF_FLIP_RANDOM_SIZE);
        flipper_format_read_hex(file, "Card Random", result->card_random, LEAF_FLIP_RANDOM_SIZE);
        flipper_format_read_hex(file, "Signature", result->signature, LEAF_FLIP_SIGNATURE_SIZE);

        uint32_t auth_len = 0;
        if (flipper_format_get_value_count(file, "Auth Response", &auth_len) && auth_len <= LEAF_FLIP_AUTH_RESP_MAX)
        {
            if (flipper_format_read_hex(file, "Auth Response", result->auth_response, auth_len))
            {
                result->auth_response_len = auth_len;
            }
        }

        uint32_t cert_len = 0;
        if (!flipper_format_get_value_count(file, "Certificate", &cert_len))
            break;
        if (cert_len == 0 || cert_len > LEAF_FLIP_CERT_MAX)
            break;
        if (!flipper_format_read_hex(file, "Certificate", result->cert, cert_len))
            break;
        result->cert_len = cert_len;

        ok = true;
    } while (false);

    flipper_format_free(file);
    furi_string_free(value);

    if (ok)
    {
        leaf_flip_reparse_loaded(app);
        app->result_loaded = true;
    }
    else
    {
        memset(result, 0, sizeof(*result));
    }
    return ok;
}
