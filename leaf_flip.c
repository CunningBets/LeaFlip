#include "leaf_flip.h"

#define TAG "LeafFlip"

static LeafFlipReader *active_reader = NULL;

static const NotificationSequence leaf_flip_blink_start = {
    &message_blink_start_10,
    &message_blink_set_color_blue,
    &message_do_not_reset,
    NULL,
};

static const NotificationSequence leaf_flip_blink_stop = {
    &message_blink_stop,
    NULL,
};

/* ===== Utilities ===== */

void leaf_flip_set_error(LeafFlipApp *app, const char *format, ...)
{
    va_list args;
    va_start(args, format);
    vsnprintf(app->error, sizeof(app->error), format, args);
    va_end(args);
    FURI_LOG_E(TAG, "%s", app->error);
}

void leaf_flip_signal_progress(LeafFlipApp *app, LeafFlipStep step)
{
    app->progress_step = (int)step;
    view_dispatcher_send_custom_event(app->view_dispatcher, LeafFlipEventProgress);
}

/* ===== NFC lifecycle ===== */

static void leaf_flip_stop_poller(LeafFlipApp *app)
{
    if (app->poller)
    {
        nfc_poller_stop(app->poller);
        nfc_poller_free(app->poller);
        app->poller = NULL;
    }
}

void leaf_flip_stop_nfc(LeafFlipApp *app)
{
    leaf_flip_stop_poller(app);
    if (active_reader)
    {
        bit_buffer_free(active_reader->tx);
        bit_buffer_free(active_reader->rx);
        free(active_reader);
        active_reader = NULL;
    }
    if (app->scanner)
    {
        nfc_scanner_stop(app->scanner);
        nfc_scanner_free(app->scanner);
        app->scanner = NULL;
    }
    notification_message(app->notifications, &leaf_flip_blink_stop);
}

static void leaf_flip_scan_callback(NfcScannerEvent event, void *context)
{
    LeafFlipApp *app = context;
    if (event.type == NfcScannerEventTypeDetected && event.data.protocols)
    {
        for (size_t i = 0; i < event.data.protocol_num; i++)
        {
            if (event.data.protocols[i] == NfcProtocolIso14443_4a ||
                event.data.protocols[i] == NfcProtocolMfDesfire)
            {
                view_dispatcher_send_custom_event(
                    app->view_dispatcher, LeafFlipEventDetected);
                break;
            }
        }
    }
}

void leaf_flip_start_scan(LeafFlipApp *app)
{
    memset(&app->result, 0, sizeof(app->result));
    app->result_loaded = false;
    app->mode = LeafFlipModeRead;
    app->progress_step = -1;
    app->last_sw = 0;
    app->stage = "Scan";
    app->error[0] = '\0';

    popup_reset(app->popup);
    popup_set_header(app->popup, "Scan LEAF card", 64, 14, AlignCenter, AlignTop);
    popup_set_text(app->popup, "Hold card near\nNFC antenna", 64, 36, AlignCenter, AlignTop);
    app->current_view = LeafFlipViewScanPopup;
    view_dispatcher_switch_to_view(app->view_dispatcher, LeafFlipViewScanPopup);

    app->scanner = nfc_scanner_alloc(app->nfc);
    nfc_scanner_start(app->scanner, leaf_flip_scan_callback, app);
    notification_message(app->notifications, &leaf_flip_blink_start);
}

void leaf_flip_start_access_scan(LeafFlipApp *app)
{
    memset(&app->result, 0, sizeof(app->result));
    app->result_loaded = false;
    app->mode = LeafFlipModeAccess;
    app->progress_step = -1;
    app->last_sw = 0;
    app->stage = "Scan";
    app->error[0] = '\0';

    popup_reset(app->popup);
    popup_set_header(app->popup, "Access Verifier", 64, 14, AlignCenter, AlignTop);
    popup_set_text(app->popup, "Hold card near\nNFC antenna", 64, 36, AlignCenter, AlignTop);
    app->current_view = LeafFlipViewScanPopup;
    view_dispatcher_switch_to_view(app->view_dispatcher, LeafFlipViewScanPopup);

    app->scanner = nfc_scanner_alloc(app->nfc);
    nfc_scanner_start(app->scanner, leaf_flip_scan_callback, app);
    notification_message(app->notifications, &leaf_flip_blink_start);
}

/* ===== Event dispatch ===== */

static void leaf_flip_handle_access_result(LeafFlipApp *app)
{
    char alias[LEAF_FLIP_ALIAS_MAX] = {0};
    bool listed = leaf_flip_access_list_lookup(
        app, app->result.open_id, alias, sizeof(alias));
    if (!listed)
    {
        leaf_flip_show_access_result(
            app, false, app->result.open_id, "Not in access list");
        return;
    }
    const char *label = (alias[0] != '\0') ? alias : app->result.open_id;
    const char *sub   = (alias[0] != '\0') ? app->result.open_id : NULL;
    leaf_flip_show_access_result(app, true, label, sub);
}

static bool leaf_flip_custom_event_callback(void *context, uint32_t event)
{
    LeafFlipApp *app = context;
    if (event == LeafFlipEventDetected)
    {
        if (app->scanner)
        {
            nfc_scanner_stop(app->scanner);
            nfc_scanner_free(app->scanner);
            app->scanner = NULL;
        }
        leaf_flip_show_progress(app);
        app->poller = nfc_poller_alloc(app->nfc, NfcProtocolIso14443_4a);
        active_reader = malloc(sizeof(LeafFlipReader));
        memset(active_reader, 0, sizeof(LeafFlipReader));
        active_reader->app = app;
        active_reader->tx = bit_buffer_alloc(LEAF_FLIP_APDU_MAX);
        active_reader->rx = bit_buffer_alloc(LEAF_FLIP_APDU_MAX);
        nfc_poller_start(app->poller, leaf_flip_poller_callback, active_reader);
        return true;
    }
    else if (event == LeafFlipEventProgress)
    {
        if (app->current_view == LeafFlipViewProgress)
            leaf_flip_update_progress(app);
        return true;
    }
    else if (event == LeafFlipEventSuccess)
    {
        leaf_flip_stop_nfc(app);
        app->result_loaded = true;
        if (app->mode == LeafFlipModeAccess)
            leaf_flip_handle_access_result(app);
        else
            leaf_flip_show_verified(app);
        return true;
    }
    else if (event == LeafFlipEventError)
    {
        leaf_flip_stop_nfc(app);
        if (app->mode == LeafFlipModeAccess)
        {
            const char *reason = app->error[0] ? app->error : "Card not verified";
            leaf_flip_show_access_result(app, false, NULL, reason);
        }
        else
        {
            leaf_flip_show_error(app);
        }
        return true;
    }
    return false;
}

static bool leaf_flip_back_event_callback(void *context)
{
    LeafFlipApp *app = context;
    switch (app->current_view)
    {
    case LeafFlipViewMainMenu:
        return false; /* exit app */
    case LeafFlipViewScanPopup:
    case LeafFlipViewProgress:
        leaf_flip_stop_nfc(app);
        leaf_flip_show_main_menu(app);
        return true;
    case LeafFlipViewVerified:
        if (app->mode == LeafFlipModeAccess)
            leaf_flip_start_access_scan(app);
        else
            leaf_flip_show_main_menu(app);
        return true;
    case LeafFlipViewMoreMenu:
        leaf_flip_show_verified(app);
        return true;
    case LeafFlipViewTextBox:
        if (app->text_mode == LeafFlipTextModeInfo)
        {
            if (app->info_from_more)
                leaf_flip_show_more_menu(app);
            else
                leaf_flip_show_main_menu(app);
        }
        else if (app->text_mode == LeafFlipTextModeAbout)
        {
            leaf_flip_show_main_menu(app);
        }
        else /* Message */
        {
            if (app->result_loaded)
                leaf_flip_show_more_menu(app);
            else
                leaf_flip_show_main_menu(app);
        }
        return true;
    case LeafFlipViewFilename:
        if (app->result_loaded)
            leaf_flip_show_more_menu(app);
        else
            leaf_flip_show_main_menu(app);
        return true;
    }
    return false;
}

/* ===== App lifecycle ===== */

static LeafFlipApp *leaf_flip_alloc(void)
{
    LeafFlipApp *app = malloc(sizeof(LeafFlipApp));
    memset(app, 0, sizeof(LeafFlipApp));
    app->info_from_more = true;

    app->view_dispatcher = view_dispatcher_alloc();
    view_dispatcher_set_event_callback_context(app->view_dispatcher, app);
    view_dispatcher_set_custom_event_callback(
        app->view_dispatcher, leaf_flip_custom_event_callback);
    view_dispatcher_set_navigation_event_callback(
        app->view_dispatcher, leaf_flip_back_event_callback);

    app->gui = furi_record_open(RECORD_GUI);
    view_dispatcher_attach_to_gui(
        app->view_dispatcher, app->gui, ViewDispatcherTypeFullscreen);
    app->notifications = furi_record_open(RECORD_NOTIFICATION);
    app->storage = furi_record_open(RECORD_STORAGE);
    app->dialogs = furi_record_open(RECORD_DIALOGS);

    app->main_menu = submenu_alloc();
    view_dispatcher_add_view(
        app->view_dispatcher, LeafFlipViewMainMenu, submenu_get_view(app->main_menu));
    app->more_menu = submenu_alloc();
    view_dispatcher_add_view(
        app->view_dispatcher, LeafFlipViewMoreMenu, submenu_get_view(app->more_menu));
    app->popup = popup_alloc();
    view_dispatcher_add_view(
        app->view_dispatcher, LeafFlipViewScanPopup, popup_get_view(app->popup));
    app->progress_widget = widget_alloc();
    view_dispatcher_add_view(
        app->view_dispatcher, LeafFlipViewProgress,
        widget_get_view(app->progress_widget));
    app->verified_widget = widget_alloc();
    view_dispatcher_add_view(
        app->view_dispatcher, LeafFlipViewVerified,
        widget_get_view(app->verified_widget));
    app->text_box = text_box_alloc();
    view_dispatcher_add_view(
        app->view_dispatcher, LeafFlipViewTextBox, text_box_get_view(app->text_box));
    app->text_input = text_input_alloc();
    view_dispatcher_add_view(
        app->view_dispatcher, LeafFlipViewFilename,
        text_input_get_view(app->text_input));
    app->text = furi_string_alloc();

    app->nfc = nfc_alloc();
    app->nfc_device = nfc_device_alloc();

    return app;
}

static void leaf_flip_free(LeafFlipApp *app)
{
    leaf_flip_stop_nfc(app);
    nfc_free(app->nfc);

    view_dispatcher_remove_view(app->view_dispatcher, LeafFlipViewFilename);
    text_input_free(app->text_input);
    view_dispatcher_remove_view(app->view_dispatcher, LeafFlipViewTextBox);
    text_box_free(app->text_box);
    view_dispatcher_remove_view(app->view_dispatcher, LeafFlipViewVerified);
    widget_free(app->verified_widget);
    view_dispatcher_remove_view(app->view_dispatcher, LeafFlipViewProgress);
    widget_free(app->progress_widget);
    view_dispatcher_remove_view(app->view_dispatcher, LeafFlipViewScanPopup);
    popup_free(app->popup);
    view_dispatcher_remove_view(app->view_dispatcher, LeafFlipViewMoreMenu);
    submenu_free(app->more_menu);
    view_dispatcher_remove_view(app->view_dispatcher, LeafFlipViewMainMenu);
    submenu_free(app->main_menu);

    furi_string_free(app->text);
    view_dispatcher_free(app->view_dispatcher);
    furi_record_close(RECORD_DIALOGS);
    furi_record_close(RECORD_STORAGE);
    furi_record_close(RECORD_NOTIFICATION);
    furi_record_close(RECORD_GUI);
    free(app);
}

int32_t leaf_flip_app(void *p)
{
    UNUSED(p);
    LeafFlipApp *app = leaf_flip_alloc();
    leaf_flip_show_main_menu(app);
    view_dispatcher_run(app->view_dispatcher);
    leaf_flip_free(app);
    return 0;
}
