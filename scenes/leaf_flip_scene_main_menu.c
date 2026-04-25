#include "../leaf_flip.h"

#define MAIN_IDX_ACCESS 0
#define MAIN_IDX_READ   1
#define MAIN_IDX_SAVED  2
#define MAIN_IDX_ABOUT  3

static void leaf_flip_main_menu_callback(void* context, uint32_t index) {
    LeafFlipApp* app = context;
    switch(index) {
    case MAIN_IDX_ACCESS:
        leaf_flip_start_access_scan(app);
        break;
    case MAIN_IDX_READ:
        leaf_flip_start_scan(app);
        break;
    case MAIN_IDX_SAVED:
        leaf_flip_load_from_file(app);
        break;
    case MAIN_IDX_ABOUT:
        leaf_flip_show_about(app);
        break;
    }
}

void leaf_flip_show_main_menu(LeafFlipApp* app) {
    submenu_reset(app->main_menu);
    /* No header — cleaner look */
    if(leaf_flip_access_list_exists(app)) {
        submenu_add_item(
            app->main_menu, "Access Verifier", MAIN_IDX_ACCESS, leaf_flip_main_menu_callback, app);
    }
    submenu_add_item(
        app->main_menu, "Read LEAF card", MAIN_IDX_READ, leaf_flip_main_menu_callback, app);
    submenu_add_item(app->main_menu, "Saved", MAIN_IDX_SAVED, leaf_flip_main_menu_callback, app);
    submenu_add_item(app->main_menu, "About", MAIN_IDX_ABOUT, leaf_flip_main_menu_callback, app);
    app->current_view = LeafFlipViewMainMenu;
    view_dispatcher_switch_to_view(app->view_dispatcher, LeafFlipViewMainMenu);
}
