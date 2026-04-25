#include "leaf_flip.h"

#define LEAF_FLIP_FILE_HEADER "LeafFlip Result"

static void leaf_flip_write_hex_string(FuriString *out, const uint8_t *data, size_t len)
{
    furi_string_reset(out);
    for (size_t i = 0; i < len; i++)
    {
        furi_string_cat_printf(out, "%02X", data[i]);
    }
}

bool leaf_flip_save_result(LeafFlipApp *app)
{
    LeafFlipResult *result = &app->result;
    if (!(result->root_verified && result->card_verified) || result->open_id[0] == '\0')
    {
        return false;
    }

    bool saved = false;
    FlipperFormat *file = flipper_format_file_alloc(app->storage);
    FuriString *path = furi_string_alloc();
    FuriString *value = furi_string_alloc();

    do
    {
        furi_string_printf(path, "%s/leaf_%s.txt", STORAGE_APP_DATA_PATH_PREFIX, result->open_id);
        if (!flipper_format_file_open_always(file, furi_string_get_cstr(path)))
            break;
        if (!flipper_format_write_header_cstr(file, LEAF_FLIP_FILE_HEADER, 1))
            break;

        furi_string_set_str(value, result->open_id);
        if (!flipper_format_write_string(file, "Open ID", value))
            break;

        leaf_flip_write_hex_string(value, result->uid, result->uid_len);
        if (!flipper_format_write_string(file, "CSN", value))
            break;

        if (!flipper_format_write_hex(file, "Public Key", result->public_key, LEAF_FLIP_PUBLIC_KEY_SIZE))
        {
            break;
        }
        if (!flipper_format_write_hex(file, "Challenge", result->challenge, LEAF_FLIP_RANDOM_SIZE))
        {
            break;
        }
        if (!flipper_format_write_hex(file, "Card Random", result->card_random, LEAF_FLIP_RANDOM_SIZE))
        {
            break;
        }
        if (!flipper_format_write_hex(file, "Response", result->auth_response, result->auth_response_len))
        {
            break;
        }
        if (!flipper_format_write_hex(file, "Signature", result->signature, LEAF_FLIP_SIGNATURE_SIZE))
        {
            break;
        }
        saved = true;
    } while (false);

    furi_string_free(value);
    furi_string_free(path);
    flipper_format_free(file);
    return saved;
}
