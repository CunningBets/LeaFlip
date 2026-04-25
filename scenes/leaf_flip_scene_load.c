#include "../leaf_flip.h"

void leaf_flip_load_from_file(LeafFlipApp* app) {
    storage_simply_mkdir(app->storage, LEAF_FLIP_APP_FOLDER);

    FuriString* path = furi_string_alloc_set(LEAF_FLIP_APP_FOLDER);
    DialogsFileBrowserOptions opts;
    dialog_file_browser_set_basic_options(&opts, LEAF_FLIP_FILE_EXT, NULL);
    opts.base_path = LEAF_FLIP_APP_FOLDER;

    bool picked = dialog_file_browser_show(app->dialogs, path, path, &opts);
    if(picked) {
        popup_reset(app->popup);
        popup_set_header(app->popup, "Loading...", 64, 14, AlignCenter, AlignTop);
        popup_set_text(app->popup, "Parsing saved read", 64, 36, AlignCenter, AlignTop);
        app->current_view = LeafFlipViewScanPopup;
        view_dispatcher_switch_to_view(app->view_dispatcher, LeafFlipViewScanPopup);

        if(leaf_flip_load_result(app, furi_string_get_cstr(path))) {
            app->info_from_more = false;
            leaf_flip_show_info(app);
        } else {
            leaf_flip_show_message(app, "Load failed", "Could not parse file.");
        }
    } else {
        leaf_flip_show_main_menu(app);
    }
    furi_string_free(path);
}
