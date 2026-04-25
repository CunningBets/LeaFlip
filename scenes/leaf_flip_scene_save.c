#include "../leaf_flip.h"

static void leaf_flip_filename_callback(void* context) {
    LeafFlipApp* app = context;
    if(app->filename[0] == '\0') {
        leaf_flip_show_message(app, "Save cancelled", "Filename was empty.");
        return;
    }
    bool ok = leaf_flip_save_result(app, app->filename);
    if(ok) {
        FuriString* body = furi_string_alloc();
        furi_string_printf(
            body, "Saved to:\n%s/%s%s", LEAF_FLIP_APP_FOLDER, app->filename, LEAF_FLIP_FILE_EXT);
        leaf_flip_show_message(app, "Saved", furi_string_get_cstr(body));
        furi_string_free(body);
    } else {
        leaf_flip_show_message(app, "Save failed", "Could not write file.");
    }
}

void leaf_flip_show_save_dialog(LeafFlipApp* app) {
    if(!app->result_loaded) {
        leaf_flip_show_message(app, "Nothing to save", "Read or load a card first.");
        return;
    }
    snprintf(app->filename, sizeof(app->filename), "leaf_%s", app->result.open_id);
    text_input_reset(app->text_input);
    text_input_set_header_text(app->text_input, "Save as");
    text_input_set_result_callback(
        app->text_input,
        leaf_flip_filename_callback,
        app,
        app->filename,
        sizeof(app->filename),
        false);
    app->current_view = LeafFlipViewFilename;
    view_dispatcher_switch_to_view(app->view_dispatcher, LeafFlipViewFilename);
}
