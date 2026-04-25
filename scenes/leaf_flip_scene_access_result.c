#include "../leaf_flip.h"

static void leaf_flip_access_button_callback(GuiButtonType type, InputType input, void* context) {
    LeafFlipApp* app = context;
    if(input != InputTypeShort) return;
    if(type == GuiButtonTypeLeft) leaf_flip_start_access_scan(app);
}

void leaf_flip_show_access_result(
    LeafFlipApp* app,
    bool granted,
    const char* label,
    const char* reason) {
    widget_reset(app->verified_widget);
    if(granted) {
        widget_add_string_element(
            app->verified_widget, 64, 2, AlignCenter, AlignTop, FontPrimary, "GRANTED");
        widget_add_string_element(
            app->verified_widget, 64, 14, AlignCenter, AlignTop, FontBigNumbers, "+");
        if(label && label[0])
            widget_add_string_element(
                app->verified_widget, 64, 38, AlignCenter, AlignTop, FontSecondary, label);
    } else {
        widget_add_string_element(
            app->verified_widget, 64, 2, AlignCenter, AlignTop, FontPrimary, "DENIED");
        widget_add_string_element(
            app->verified_widget, 64, 14, AlignCenter, AlignTop, FontBigNumbers, "-");
        if(reason && reason[0])
            widget_add_string_element(
                app->verified_widget, 64, 38, AlignCenter, AlignTop, FontSecondary, reason);
        else if(label && label[0])
            widget_add_string_element(
                app->verified_widget, 64, 38, AlignCenter, AlignTop, FontSecondary, label);
    }
    widget_add_button_element(
        app->verified_widget, GuiButtonTypeLeft, "Scan", leaf_flip_access_button_callback, app);
    app->current_view = LeafFlipViewVerified;
    view_dispatcher_switch_to_view(app->view_dispatcher, LeafFlipViewVerified);
    notification_message(app->notifications, granted ? &sequence_success : &sequence_error);
}
