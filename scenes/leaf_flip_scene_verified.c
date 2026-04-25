#include "../leaf_flip.h"

static void
    leaf_flip_verified_button_callback(GuiButtonType type, InputType input, void* context) {
    LeafFlipApp* app = context;
    if(input != InputTypeShort) return;
    if(type == GuiButtonTypeLeft)
        leaf_flip_start_scan(app);
    else if(type == GuiButtonTypeRight)
        leaf_flip_show_more_menu(app);
}

void leaf_flip_show_verified(LeafFlipApp* app) {
    widget_reset(app->verified_widget);
    widget_add_string_element(
        app->verified_widget, 64, 6, AlignCenter, AlignTop, FontPrimary, "VERIFIED");
    widget_add_string_element(
        app->verified_widget, 64, 24, AlignCenter, AlignTop, FontSecondary, "Open ID");
    widget_add_string_element(
        app->verified_widget, 64, 36, AlignCenter, AlignTop, FontPrimary, app->result.open_id);
    widget_add_button_element(
        app->verified_widget, GuiButtonTypeLeft, "Retry", leaf_flip_verified_button_callback, app);
    widget_add_button_element(
        app->verified_widget, GuiButtonTypeRight, "More", leaf_flip_verified_button_callback, app);
    app->current_view = LeafFlipViewVerified;
    view_dispatcher_switch_to_view(app->view_dispatcher, LeafFlipViewVerified);
    notification_message(app->notifications, &sequence_success);
}
