#include "../leaf_flip.h"

void leaf_flip_show_message(LeafFlipApp* app, const char* header, const char* body) {
    furi_string_reset(app->text);
    if(header && header[0]) furi_string_cat_printf(app->text, "%s\n\n", header);
    if(body && body[0]) furi_string_cat(app->text, body);
    text_box_reset(app->text_box);
    text_box_set_font(app->text_box, TextBoxFontText);
    text_box_set_text(app->text_box, furi_string_get_cstr(app->text));
    app->text_mode = LeafFlipTextModeMessage;
    app->current_view = LeafFlipViewTextBox;
    view_dispatcher_switch_to_view(app->view_dispatcher, LeafFlipViewTextBox);
}

void leaf_flip_show_error(LeafFlipApp* app) {
    furi_string_reset(app->text);
    furi_string_cat(app->text, "Read failed\n\n");
    if(app->stage) furi_string_cat_printf(app->text, "Stage: %s\n", app->stage);
    furi_string_cat(app->text, app->error[0] ? app->error : "Unknown error");
    if(app->last_sw) furi_string_cat_printf(app->text, "\nSW=%04X", app->last_sw);
    text_box_reset(app->text_box);
    text_box_set_font(app->text_box, TextBoxFontText);
    text_box_set_text(app->text_box, furi_string_get_cstr(app->text));
    app->text_mode = LeafFlipTextModeMessage;
    app->current_view = LeafFlipViewTextBox;
    view_dispatcher_switch_to_view(app->view_dispatcher, LeafFlipViewTextBox);
    notification_message(app->notifications, &sequence_error);
}
