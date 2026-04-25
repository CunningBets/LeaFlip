#include "../leaf_flip.h"

static void
    leaf_flip_append_hex_line(FuriString* out, const char* label, const uint8_t* data, size_t len) {
    furi_string_cat_printf(out, "%s:\n", label);
    for(size_t i = 0; i < len; i++)
        furi_string_cat_printf(out, "%02X", data[i]);
    furi_string_cat(out, "\n\n");
}

void leaf_flip_show_info(LeafFlipApp* app) {
    LeafFlipResult* r = &app->result;
    furi_string_reset(app->text);
    furi_string_cat_printf(app->text, "Open ID:\n%s\n\n", r->open_id);
    if(r->subject_cn[0]) furi_string_cat_printf(app->text, "Subject CN:\n%s\n\n", r->subject_cn);
    if(r->issuer_cn[0]) furi_string_cat_printf(app->text, "Issuer CN:\n%s\n\n", r->issuer_cn);
    furi_string_cat_printf(app->text, "Root cert: %s\n", r->root_verified ? "PASS" : "FAIL");
    furi_string_cat_printf(app->text, "Card auth: %s\n\n", r->card_verified ? "PASS" : "FAIL");
    furi_string_cat_printf(app->text, "Cert size: %u bytes\n\n", (unsigned)r->cert_len);
    if(r->uid_len) leaf_flip_append_hex_line(app->text, "CSN", r->uid, r->uid_len);
    leaf_flip_append_hex_line(app->text, "Public Key", r->public_key, LEAF_FLIP_PUBLIC_KEY_SIZE);
    leaf_flip_append_hex_line(app->text, "Challenge", r->challenge, LEAF_FLIP_RANDOM_SIZE);
    leaf_flip_append_hex_line(app->text, "Card Random", r->card_random, LEAF_FLIP_RANDOM_SIZE);
    leaf_flip_append_hex_line(app->text, "Signature", r->signature, LEAF_FLIP_SIGNATURE_SIZE);
    if(r->auth_response_len)
        leaf_flip_append_hex_line(
            app->text, "Auth Response", r->auth_response, r->auth_response_len);

    text_box_reset(app->text_box);
    text_box_set_font(app->text_box, TextBoxFontText);
    text_box_set_text(app->text_box, furi_string_get_cstr(app->text));
    app->text_mode = LeafFlipTextModeInfo;
    app->current_view = LeafFlipViewTextBox;
    view_dispatcher_switch_to_view(app->view_dispatcher, LeafFlipViewTextBox);
}
