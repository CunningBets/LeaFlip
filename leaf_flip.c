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

/* ---- Forward decls ---- */
static void leaf_flip_start_scan(LeafFlipApp *app);
static void leaf_flip_stop_nfc(LeafFlipApp *app);
static void leaf_flip_load_from_file(LeafFlipApp *app);

/* Tracks where to return after viewing Info ("More" path vs "Load" path) */
static bool info_from_more = true;

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
            if (event.data.protocols[i] == NfcProtocolIso14443_4a ||
                event.data.protocols[i] == NfcProtocolMfDesfire)
            {
                view_dispatcher_send_custom_event(app->view_dispatcher, LeafFlipEventDetected);
                break;
            }
        }
    }
}

/* ===== Views ===== */

/* --- Main menu --- */

static void leaf_flip_main_menu_callback(void *context, uint32_t index)
{
    LeafFlipApp *app = context;
    if (index == 0)
    {
        leaf_flip_start_scan(app);
    }
    else if (index == 1)
    {
        leaf_flip_load_from_file(app);
    }
}

void leaf_flip_show_main_menu(LeafFlipApp *app)
{
    submenu_reset(app->main_menu);
    submenu_set_header(app->main_menu, "LeafFlip");
    submenu_add_item(app->main_menu, "Read LEAF card", 0, leaf_flip_main_menu_callback, app);
    submenu_add_item(app->main_menu, "Load past read", 1, leaf_flip_main_menu_callback, app);
    app->current_view = LeafFlipViewMainMenu;
    view_dispatcher_switch_to_view(app->view_dispatcher, LeafFlipViewMainMenu);
}

/* --- Scan popup --- */

static void leaf_flip_start_scan(LeafFlipApp *app)
{
    memset(&app->result, 0, sizeof(app->result));
    app->result_loaded = false;
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

/* --- Progress checklist --- */

static const char *const step_labels[LeafFlipStepCount] = {
    "Select",
    "Read certificate",
    "Verify cert chain",
    "Internal Auth",
    "Verify card sig",
};

void leaf_flip_update_progress(LeafFlipApp *app)
{
    widget_reset(app->progress_widget);
    widget_add_string_element(
        app->progress_widget, 64, 4, AlignCenter, AlignTop, FontPrimary, "Reading...");
    int completed = app->progress_step;
    for (int i = 0; i < LeafFlipStepCount; i++)
    {
        char line[40];
        const char *mark = (i <= completed) ? "[x]" : "[ ]";
        snprintf(line, sizeof(line), "%s %s", mark, step_labels[i]);
        widget_add_string_element(
            app->progress_widget, 4, 20 + i * 9, AlignLeft, AlignTop, FontSecondary, line);
    }
}

void leaf_flip_show_progress(LeafFlipApp *app)
{
    app->progress_step = -1;
    leaf_flip_update_progress(app);
    app->current_view = LeafFlipViewProgress;
    view_dispatcher_switch_to_view(app->view_dispatcher, LeafFlipViewProgress);
}

/* --- Verified screen --- */

static void leaf_flip_verified_button_callback(GuiButtonType type, InputType input, void *context)
{
    LeafFlipApp *app = context;
    if (input != InputTypeShort)
        return;
    if (type == GuiButtonTypeLeft)
    {
        leaf_flip_start_scan(app);
    }
    else if (type == GuiButtonTypeRight)
    {
        leaf_flip_show_more_menu(app);
    }
}

void leaf_flip_show_verified(LeafFlipApp *app)
{
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

/* --- More menu --- */

static void leaf_flip_more_menu_callback(void *context, uint32_t index)
{
    LeafFlipApp *app = context;
    if (index == 0)
    {
        leaf_flip_show_save_dialog(app);
    }
    else if (index == 1)
    {
        info_from_more = true;
        leaf_flip_show_info(app);
    }
}

void leaf_flip_show_more_menu(LeafFlipApp *app)
{
    submenu_reset(app->more_menu);
    submenu_set_header(app->more_menu, "More");
    submenu_add_item(app->more_menu, "Save", 0, leaf_flip_more_menu_callback, app);
    submenu_add_item(app->more_menu, "Info", 1, leaf_flip_more_menu_callback, app);
    app->current_view = LeafFlipViewMoreMenu;
    view_dispatcher_switch_to_view(app->view_dispatcher, LeafFlipViewMoreMenu);
}

/* --- Info text box --- */

static void leaf_flip_append_hex_line(FuriString *out, const char *label, const uint8_t *data, size_t len)
{
    furi_string_cat_printf(out, "%s:\n", label);
    for (size_t i = 0; i < len; i++)
    {
        furi_string_cat_printf(out, "%02X", data[i]);
    }
    furi_string_cat(out, "\n\n");
}

void leaf_flip_show_info(LeafFlipApp *app)
{
    LeafFlipResult *r = &app->result;
    furi_string_reset(app->text);
    furi_string_cat_printf(app->text, "Open ID:\n%s\n\n", r->open_id);
    if (r->subject_cn[0])
        furi_string_cat_printf(app->text, "Subject CN:\n%s\n\n", r->subject_cn);
    if (r->issuer_cn[0])
        furi_string_cat_printf(app->text, "Issuer CN:\n%s\n\n", r->issuer_cn);
    furi_string_cat_printf(
        app->text, "Root cert: %s\n", r->root_verified ? "PASS" : "FAIL");
    furi_string_cat_printf(
        app->text, "Card auth: %s\n\n", r->card_verified ? "PASS" : "FAIL");
    furi_string_cat_printf(app->text, "Cert size: %u bytes\n\n", (unsigned)r->cert_len);
    if (r->uid_len)
        leaf_flip_append_hex_line(app->text, "CSN", r->uid, r->uid_len);
    leaf_flip_append_hex_line(app->text, "Public Key", r->public_key, LEAF_FLIP_PUBLIC_KEY_SIZE);
    leaf_flip_append_hex_line(app->text, "Challenge", r->challenge, LEAF_FLIP_RANDOM_SIZE);
    leaf_flip_append_hex_line(app->text, "Card Random", r->card_random, LEAF_FLIP_RANDOM_SIZE);
    leaf_flip_append_hex_line(app->text, "Signature", r->signature, LEAF_FLIP_SIGNATURE_SIZE);
    if (r->auth_response_len)
        leaf_flip_append_hex_line(app->text, "Auth Response", r->auth_response, r->auth_response_len);

    text_box_reset(app->text_box);
    text_box_set_font(app->text_box, TextBoxFontText);
    text_box_set_text(app->text_box, furi_string_get_cstr(app->text));
    app->text_mode = LeafFlipTextModeInfo;
    app->current_view = LeafFlipViewTextBox;
    view_dispatcher_switch_to_view(app->view_dispatcher, LeafFlipViewTextBox);
}

/* --- Message text box --- */

void leaf_flip_show_message(LeafFlipApp *app, const char *header, const char *body)
{
    furi_string_reset(app->text);
    if (header && header[0])
        furi_string_cat_printf(app->text, "%s\n\n", header);
    if (body && body[0])
        furi_string_cat(app->text, body);
    text_box_reset(app->text_box);
    text_box_set_font(app->text_box, TextBoxFontText);
    text_box_set_text(app->text_box, furi_string_get_cstr(app->text));
    app->text_mode = LeafFlipTextModeMessage;
    app->current_view = LeafFlipViewTextBox;
    view_dispatcher_switch_to_view(app->view_dispatcher, LeafFlipViewTextBox);
}

void leaf_flip_show_error(LeafFlipApp *app)
{
    furi_string_reset(app->text);
    furi_string_cat(app->text, "Read failed\n\n");
    if (app->stage)
        furi_string_cat_printf(app->text, "Stage: %s\n", app->stage);
    furi_string_cat(app->text, app->error[0] ? app->error : "Unknown error");
    if (app->last_sw)
        furi_string_cat_printf(app->text, "\nSW=%04X", app->last_sw);
    text_box_reset(app->text_box);
    text_box_set_font(app->text_box, TextBoxFontText);
    text_box_set_text(app->text_box, furi_string_get_cstr(app->text));
    app->text_mode = LeafFlipTextModeMessage;
    app->current_view = LeafFlipViewTextBox;
    view_dispatcher_switch_to_view(app->view_dispatcher, LeafFlipViewTextBox
    app->text_mode = LeafFlipTextModeMessage;
    app->current_view = LeafFlipViewTextBox;
    view_dispatcher_switch_to_view(app->view_dispatcher, LeafFlipViewTextBox);
    notification_message(app->notifications, &sequence_error);
}

/* --- Save dialog (filename input) --- */

static void leaf_flip_filename_callback(void *context)
{
    LeafFlipApp *app = context;
    if (app->filename[0] == '\0')
    {
        leaf_flip_show_message(app, "Save cancelled", "Filename was empty.");
        return;
    }
    bool ok = leaf_flip_save_result(app, app->filename);
    if (ok)
    {
        FuriString *body = furi_string_alloc();
        furi_string_printf(
            body, "Saved to:\n%s/%s%s", LEAF_FLIP_APP_FOLDER, app->filename, LEAF_FLIP_FILE_EXT);
        leaf_flip_show_message(app, "Saved", furi_string_get_cstr(body));
        furi_string_free(body);
    }
    else
    {
        leaf_flip_show_message(app, "Save failed", "Could not write file.");
    }
}

void leaf_flip_show_save_dialog(LeafFlipApp *app)
{
    if (!app->result_loaded)
    {
        leaf_flip_show_message(app, "Nothing to save", "Read or load a card first.");
        return;
    }

    /* Default filename: leaf_<openid> */
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

/* --- Load past read --- */

static void leaf_flip_load_from_file(LeafFlipApp *app)
{
    storage_simply_mkdir(app->storage, LEAF_FLIP_APP_FOLDER);

    FuriString *path = furi_string_alloc_set(LEAF_FLIP_APP_FOLDER);
    DialogsFileBrowserOptions opts;
    dialog_file_browser_set_basic_options(&opts, LEAF_FLIP_FILE_EXT, NULL);
    opts.base_path = LEAF_FLIP_APP_FOLDER;

    bool picked = dialog_file_browser_show(app->dialogs, path, path, &opts);
    if (picked)
    {
        if (leaf_flip_load_result(app, furi_string_get_cstr(path)))
        {
            info_from_more = false;
            leaf_flip_show_info(app);
        }
        else
        {
            leaf_flip_show_message(app, "Load failed", "Could not parse file.");
        }
    }
    else
    {
        leaf_flip_show_main_menu(app);
    }
    furi_string_free(path);
}

/* ===== ViewDispatcher callbacks ===== */

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
        {
            leaf_flip_update_progress(app);
        }
        return true;
    }
    else if (event == LeafFlipEventSuccess)
    {
        leaf_flip_stop_nfc(app);
        app->result_loaded = true;
        leaf_flip_show_verified(app);
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
        leaf_flip_show_main_menu(app);
        return true;
    case LeafFlipViewTextBox:
        if (app->text_mode == LeafFlipTextModeInfo)
        {
            if (info_from_more)
                leaf_flip_show_more_menu(app);
            else
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
    case LeafFlipViewFilenamhow_more_menu(app);
            else
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

    app->view_dispatcher = view_dispatcher_alloc();
    view_dispatcher_set_event_callback_context(app->view_dispatcher, app);
    view_dispatcher_set_custom_event_callback(app->view_dispatcher, leaf_flip_custom_event_callback);
    view_dispatcher_set_navigation_event_callback(app->view_dispatcher, leaf_flip_back_event_callback);

    app->gui = furi_record_open(RECORD_GUI);
    view_dispatcher_attach_to_gui(app->view_dispatcher, app->gui, ViewDispatcherTypeFullscreen);
    app->notifications = furi_record_open(RECORD_NOTIFICATION);
    app->storage = furi_record_open(RECORD_STORAGE);
    app->dialogs = furi_record_open(RECORD_DIALOGS);

    app->main_menu = submenu_alloc();
    view_dispatcher_add_view(
        app->view_dispatcher, LeafFlipViewMainMenu, submenu_get_view(app->main_menu));
    app->more_menu = submenu_alloc();
    view_dispatcher_add_view(
        app->view_dispatcher, LeafFlipViewTextBoxs, widget_get_view(app->progress_widget));
    app->verified_widget = widget_alloc();
    view_dispatcher_add_view(
        app->view_dispatcher, LeafFlipViewVerified, widget_get_view(app->verified_widget));
    app->text_box = text_box_alloc();
    view_dispatcher_add_view(
        app->view_dispatcher, LeafFlipViewTextBox, text_box_get_view(app->text_box));
    app->text_input = text_input_alloc();
    view_dispatcher_add_view(
        app->view_dispatcher, LeafFlipViewFilename, text_input_get_view(app->text_input));
    app->text = furi_string_alloc();

    app->nfc = nfc_alloc();
    app->nfc_device = nfc_device_alloc();

    return app;
}

static void leaf_flip_free(LeafFlipApp *app)
{
    leaf_flip_stop_nfc(app);
    TextBox
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
