#include "../leaf_flip.h"

void leaf_flip_show_about(LeafFlipApp* app) {
    furi_string_reset(app->text);
    furi_string_cat(
        app->text,
        "LEAF Verified\n"
        "Open Application\n"
        "\n"
        "Cards carry an X.509\n"
        "certificate signed by\n"
        "the LEAF Root CA. The\n"
        "12-digit Open ID is\n"
        "encoded in the Subject.\n"
        "\n"
        "On scan this app:\n"
        " 1. Selects the LEAF AID\n"
        " 2. Reads the certificate\n"
        " 3. Verifies vs Root CA\n"
        " 4. Sends a 16-byte\n"
        "    challenge\n"
        " 5. Verifies card ECDSA\n"
        "    P-256 signature\n"
        "\n"
        "Only the card with the\n"
        "matching private key can\n"
        "sign the challenge.\n"
        "The Root CA proves it\n"
        "was issued by LEAF.\n"
        "Both checks must pass.");
    text_box_reset(app->text_box);
    text_box_set_font(app->text_box, TextBoxFontText);
    text_box_set_text(app->text_box, furi_string_get_cstr(app->text));
    app->text_mode = LeafFlipTextModeAbout;
    app->current_view = LeafFlipViewTextBox;
    view_dispatcher_switch_to_view(app->view_dispatcher, LeafFlipViewTextBox);
}
