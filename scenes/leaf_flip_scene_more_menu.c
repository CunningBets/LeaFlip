#include "../leaf_flip.h"

#define MORE_IDX_SAVE          0
#define MORE_IDX_INFO          1
#define MORE_IDX_ACCESS_TOGGLE 2

static void leaf_flip_more_menu_callback(void* context, uint32_t index) {
    LeafFlipApp* app = context;
    if(index == MORE_IDX_SAVE) {
        leaf_flip_show_save_dialog(app);
    } else if(index == MORE_IDX_INFO) {
        app->info_from_more = true;
        leaf_flip_show_info(app);
    } else if(index == MORE_IDX_ACCESS_TOGGLE) {
        bool listed = leaf_flip_access_list_lookup(app, app->result.open_id, NULL, 0);
        if(listed) {
            if(leaf_flip_access_list_remove(app, app->result.open_id))
                leaf_flip_show_message(app, "Removed", "Open ID removed from access list.");
            else
                leaf_flip_show_message(app, "Failed", "Could not update access list.");
        } else {
            if(leaf_flip_access_list_add(app, app->result.open_id, NULL))
                leaf_flip_show_message(
                    app,
                    "Added",
                    "Open ID added to access list.\n\n"
                    "Edit access_list.txt on the\nSD card to set an alias.");
            else
                leaf_flip_show_message(app, "Failed", "Could not update access list.");
        }
    }
}

void leaf_flip_show_more_menu(LeafFlipApp* app) {
    submenu_reset(app->more_menu);
    submenu_set_header(app->more_menu, "More");
    submenu_add_item(app->more_menu, "Save", MORE_IDX_SAVE, leaf_flip_more_menu_callback, app);
    submenu_add_item(app->more_menu, "Info", MORE_IDX_INFO, leaf_flip_more_menu_callback, app);
    if(app->result.open_id[0] != '\0') {
        bool listed = leaf_flip_access_list_lookup(app, app->result.open_id, NULL, 0);
        submenu_add_item(
            app->more_menu,
            listed ? "Remove from access list" : "Add to access list",
            MORE_IDX_ACCESS_TOGGLE,
            leaf_flip_more_menu_callback,
            app);
    }
    app->current_view = LeafFlipViewMoreMenu;
    view_dispatcher_switch_to_view(app->view_dispatcher, LeafFlipViewMoreMenu);
}
