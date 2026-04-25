#include "../leaf_flip.h"

static const char* const step_labels[LeafFlipStepCount] = {
    "Select",
    "Read cert",
    "Verify cert",
    "Auth challenge",
    "Verify card sig",
};

void leaf_flip_update_progress(LeafFlipApp* app) {
    widget_reset(app->progress_widget);
    widget_add_string_element(
        app->progress_widget, 64, 4, AlignCenter, AlignTop, FontPrimary, "Reading...");
    int completed = app->progress_step;
    for(int i = 0; i < LeafFlipStepCount; i++) {
        char line[40];
        const char* mark = (i <= completed) ? "[x]" : "[ ]";
        snprintf(line, sizeof(line), "%s%s", mark, step_labels[i]);
        widget_add_string_element(
            app->progress_widget, 4, 15 + i * 10, AlignLeft, AlignTop, FontKeyboard, line);
    }
}

void leaf_flip_show_progress(LeafFlipApp* app) {
    app->progress_step = -1;
    leaf_flip_update_progress(app);
    app->current_view = LeafFlipViewProgress;
    view_dispatcher_switch_to_view(app->view_dispatcher, LeafFlipViewProgress);
}
