#include "leaf_flip.h"

#define TAG "LeafFlip"

static LeafFlipReader *active_reader = NULL;

static void leaf_flip_stop_poller(LeafFlipApp *app)
{
    if (app->poller)
    {
        nfc_poller_stop(app->poller);
        nfc_poller_free(app->poller);
        app->poller = NULL;
    }
}

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

void leaf_flip_set_error(LeafFlipApp *app, const char *format, ...)
{
    va_list args;
    va_start(args, format);
    vsnprintf(app->error, sizeof(app->error), format, args);
    va_end(args);
    FURI_LOG_E(TAG, "%s", app->error);
}

static void leaf_flip_stop_nfc(LeafFlipApp *app)
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
            FURI_LOG_D(TAG, "Detected protocol %u", event.data.protocols[i]);
            if (event.data.protocols[i] == NfcProtocolIso14443_4a ||
                event.data.protocols[i] == NfcProtocolMfDesfire)
            {
                view_dispatcher_send_custom_event(app->view_dispatcher, LeafFlipEventDetected);
                break;
            }
        }
    }
}

static void leaf_flip_start_scan(LeafFlipApp *app)
{
    memset(&app->result, 0, sizeof(app->result));
    app->last_sw = 0;
    app->stage = "Scan";
    app->error[0] = '\0';
    popup_reset(app->popup);
    popup_set_header(app->popup, "Scan LEAF card", 64, 18, AlignCenter, AlignTop);
    popup_set_text(app->popup, "Hold card near NFC\nantenna", 64, 38, AlignCenter, AlignTop);
    app->current_view = LeafFlipViewPopup;
    view_dispatcher_switch_to_view(app->view_dispatcher, LeafFlipViewPopup);

    app->scanner = nfc_scanner_alloc(app->nfc);
    nfc_scanner_start(app->scanner, leaf_flip_scan_callback, app);
    notification_message(app->notifications, &leaf_flip_blink_start);
}

static void leaf_flip_menu_callback(void *context, uint32_t index)
{
    LeafFlipApp *app = context;
    if (index == 0)
    {
        leaf_flip_start_scan(app);
    }
    else if (index == 1)
    {
        bool saved = leaf_flip_save_result(app);
        furi_string_reset(app->text);
        if (saved)
        {
            furi_string_cat(app->text, "Saved\n\napps_data/leaf_flip result file written.");
        }
        else
        {
            furi_string_cat(app->text, "Nothing saved\n\nScan and verify a card first.");
        }
        text_box_set_text(app->text_box, furi_string_get_cstr(app->text));
        app->current_view = LeafFlipViewTextBox;
        view_dispatcher_switch_to_view(app->view_dispatcher, LeafFlipViewTextBox);
    }
}

void leaf_flip_show_menu(LeafFlipApp *app)
{
    submenu_reset(app->submenu);
    submenu_set_header(app->submenu, "LeafFlip");
    submenu_add_item(app->submenu, "Scan LEAF card", 0, leaf_flip_menu_callback, app);
    submenu_add_item(app->submenu, "Save last result", 1, leaf_flip_menu_callback, app);
    app->current_view = LeafFlipViewMenu;
    view_dispatcher_switch_to_view(app->view_dispatcher, LeafFlipViewMenu);
}

void leaf_flip_show_result(LeafFlipApp *app)
{
    LeafFlipResult *result = &app->result;
    furi_string_reset(app->text);
    furi_string_cat_printf(app->text, "Open ID\n%s\n\n", result->open_id);
    furi_string_cat_printf(app->text, "Root cert: %s\n", result->root_verified ? "PASS" : "FAIL");
    furi_string_cat_printf(app->text, "Card auth: %s\n", result->card_verified ? "PASS" : "FAIL");
    furi_string_cat_printf(app->text, "Certificate: %u bytes\n", (unsigned)result->cert_len);
    if (result->uid_len)
    {
        furi_string_cat(app->text, "CSN: ");
        for (size_t i = 0; i < result->uid_len; i++)
        {
            furi_string_cat_printf(app->text, "%02X", result->uid[i]);
        }
        furi_string_cat(app->text, "\n");
    }
    furi_string_cat(app->text, "\nUse Back, then Save last result to store details.");
    text_box_set_font(app->text_box, TextBoxFontText);
    text_box_set_text(app->text_box, furi_string_get_cstr(app->text));
    notification_message(app->notifications, &sequence_success);
    app->current_view = LeafFlipViewTextBox;
    view_dispatcher_switch_to_view(app->view_dispatcher, LeafFlipViewTextBox);
}

void leaf_flip_show_error(LeafFlipApp *app)
{
    furi_string_reset(app->text);
    furi_string_cat(app->text, "Read failed\n\n");
    if (app->stage)
    {
        furi_string_cat_printf(app->text, "Stage: %s\n", app->stage);
    }
    furi_string_cat(app->text, app->error[0] ? app->error : "Unknown error");
    if (app->last_sw)
    {
        furi_string_cat_printf(app->text, "\nSW=%04X", app->last_sw);
    }
    text_box_set_font(app->text_box, TextBoxFontText);
    text_box_set_text(app->text_box, furi_string_get_cstr(app->text));
    notification_message(app->notifications, &sequence_error);
    app->current_view = LeafFlipViewTextBox;
    view_dispatcher_switch_to_view(app->view_dispatcher, LeafFlipViewTextBox);
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
        popup_reset(app->popup);
        popup_set_header(app->popup, "Reading", 64, 18, AlignCenter, AlignTop);
        popup_set_text(app->popup, "SELECT\nREAD\nVERIFY\nAUTH", 64, 34, AlignCenter, AlignTop);
        app->current_view = LeafFlipViewPopup;
        app->poller = nfc_poller_alloc(app->nfc, NfcProtocolIso14443_4a);
        active_reader = malloc(sizeof(LeafFlipReader));
        memset(active_reader, 0, sizeof(LeafFlipReader));
        active_reader->app = app;
        active_reader->tx = bit_buffer_alloc(LEAF_FLIP_APDU_MAX);
        active_reader->rx = bit_buffer_alloc(LEAF_FLIP_APDU_MAX);
        nfc_poller_start(app->poller, leaf_flip_poller_callback, active_reader);
        return true;
    }
    else if (event == LeafFlipEventSuccess)
    {
        leaf_flip_stop_nfc(app);
        leaf_flip_show_result(app);
        return true;
    }
    else if (event == LeafFlipEventError)
    {
        leaf_flip_stop_nfc(app);
        leaf_flip_show_error(app);
        return true;
    }
    return false;
}

static bool leaf_flip_back_event_callback(void *context)
{
    LeafFlipApp *app = context;
    if (app->current_view == LeafFlipViewMenu)
    {
        return false;
    }
    leaf_flip_stop_nfc(app);
    leaf_flip_show_menu(app);
    return true;
}

static LeafFlipApp *leaf_flip_alloc(void)
{
    LeafFlipApp *app = malloc(sizeof(LeafFlipApp));
    memset(app, 0, sizeof(LeafFlipApp));

    app->view_dispatcher = view_dispatcher_alloc();
    view_dispatcher_set_event_callback_context(app->view_dispatcher, app);
    view_dispatcher_set_custom_event_callback(app->view_dispatcher, leaf_flip_custom_event_callback);
    view_dispatcher_set_navigation_event_callback(app->view_dispatcher, leaf_flip_back_event_callback);

    app->gui = furi_record_open(RECORD_GUI);
    view_dispatcher_attach_to_gui(app->view_dispatcher, app->gui, ViewDispatcherTypeFullscreen);
    app->notifications = furi_record_open(RECORD_NOTIFICATION);
    app->storage = furi_record_open(RECORD_STORAGE);
    app->dialogs = furi_record_open(RECORD_DIALOGS);

    app->submenu = submenu_alloc();
    view_dispatcher_add_view(app->view_dispatcher, LeafFlipViewMenu, submenu_get_view(app->submenu));
    app->popup = popup_alloc();
    view_dispatcher_add_view(app->view_dispatcher, LeafFlipViewPopup, popup_get_view(app->popup));
    app->text_box = text_box_alloc();
    view_dispatcher_add_view(
        app->view_dispatcher, LeafFlipViewTextBox, text_box_get_view(app->text_box));
    app->text = furi_string_alloc();

    app->nfc = nfc_alloc();
    app->nfc_device = nfc_device_alloc();

    return app;
}

static void leaf_flip_free(LeafFlipApp *app)
{
    leaf_flip_stop_nfc(app);
    nfc_device_free(app->nfc_device);
    nfc_free(app->nfc);
    view_dispatcher_remove_view(app->view_dispatcher, LeafFlipViewMenu);
    submenu_free(app->submenu);
    view_dispatcher_remove_view(app->view_dispatcher, LeafFlipViewPopup);
    popup_free(app->popup);
    view_dispatcher_remove_view(app->view_dispatcher, LeafFlipViewTextBox);
    text_box_free(app->text_box);
    furi_string_free(app->text);
    view_dispatcher_free(app->view_dispatcher);
    furi_record_close(RECORD_STORAGE);
    furi_record_close(RECORD_DIALOGS);
    furi_record_close(RECORD_NOTIFICATION);
    furi_record_close(RECORD_GUI);
    free(app);
}

int32_t leaf_flip_app(void *p)
{
    UNUSED(p);
    LeafFlipApp *app = leaf_flip_alloc();
    leaf_flip_show_menu(app);
    view_dispatcher_run(app->view_dispatcher);
    leaf_flip_free(app);
    return 0;
}
