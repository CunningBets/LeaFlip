#pragma once

#include <furi.h>
#include <furi_hal.h>
#include <gui/gui.h>
#include <gui/view_dispatcher.h>
#include <gui/modules/popup.h>
#include <gui/modules/submenu.h>
#include <gui/modules/text_box.h>
#include <gui/modules/text_input.h>
#include <gui/modules/widget.h>
#include <notification/notification_messages.h>
#include <storage/storage.h>
#include <dialogs/dialogs.h>
#include <toolbox/path.h>
#include <lib/flipper_format/flipper_format.h>

#include <lib/nfc/nfc.h>
#include <nfc/nfc_device.h>
#include <nfc/nfc_poller.h>
#include <nfc/nfc_scanner.h>
#include <lib/nfc/protocols/nfc_generic_event.h>
#include <lib/nfc/protocols/iso14443_4a/iso14443_4a.h>
#include <lib/nfc/protocols/iso14443_4a/iso14443_4a_poller.h>

#define LEAF_FLIP_CERT_MAX 2048
#define LEAF_FLIP_APDU_MAX 384
#define LEAF_FLIP_OPEN_ID_SIZE 13
#define LEAF_FLIP_UID_MAX 10
#define LEAF_FLIP_PUBLIC_KEY_SIZE 65
#define LEAF_FLIP_RANDOM_SIZE 16
#define LEAF_FLIP_SIGNATURE_SIZE 64
#define LEAF_FLIP_AUTH_RESP_MAX 96
#define LEAF_FLIP_FILENAME_MAX 64

#define LEAF_FLIP_APP_FOLDER EXT_PATH("apps_data/leaf_flip")
#define LEAF_FLIP_FILE_EXT ".lvr"
#define LEAF_FLIP_FILE_HEADER "LeafFlip Result"

typedef enum
{
    LeafFlipViewMainMenu,
    LeafFlipViewScanPopup,
    LeafFlipViewProgress,
    LeafFlipViewVerified,
    LeafFlipViewMoreMenu,
    LeafFlipViewTextBox,
    LeafFlipViewFilename,
} LeafFlipView;

typedef enum
{
    LeafFlipStepSelect = 0,
    LeafFlipStepRead,
    LeafFlipStepCertVerified,
    LeafFlipStepAuth,
    LeafFlipStepCardVerified,
    LeafFlipStepCount,
} LeafFlipStep;

typedef enum
{
    LeafFlipEventDetected = 100,
    LeafFlipEventSuccess,
    LeafFlipEventError,
    LeafFlipEventProgress,
} LeafFlipEvent;

typedef struct
{
    uint8_t cert[LEAF_FLIP_CERT_MAX];
    size_t cert_len;
    char open_id[LEAF_FLIP_OPEN_ID_SIZE];
    char subject_cn[64];
    char issuer_cn[64];
    uint8_t uid[LEAF_FLIP_UID_MAX];
    size_t uid_len;
    uint8_t public_key[LEAF_FLIP_PUBLIC_KEY_SIZE];
    uint8_t challenge[LEAF_FLIP_RANDOM_SIZE];
    uint8_t card_random[LEAF_FLIP_RANDOM_SIZE];
    uint8_t signature[LEAF_FLIP_SIGNATURE_SIZE];
    uint8_t auth_response[LEAF_FLIP_AUTH_RESP_MAX];
    size_t auth_response_len;
    bool root_verified;
    bool card_verified;
} LeafFlipResult;

typedef struct LeafFlipApp LeafFlipApp;

struct LeafFlipApp
{
    ViewDispatcher *view_dispatcher;
    Gui *gui;
    NotificationApp *notifications;
    Storage *storage;
    DialogsApp *dialogs;

    Submenu *main_menu;
    Submenu *more_menu;
    Popup *popup;
    Widget *progress_widget;
    Widget *verified_widget;
    TextBox *text_box;
    TextInput *text_input;
    FuriString *text;

    Nfc *nfc;
    NfcScanner *scanner;
    NfcPoller *poller;
    NfcDevice *nfc_device;

    LeafFlipView current_view;
    enum
    {
        LeafFlipTextModeNone,
        LeafFlipTextModeInfo,
        LeafFlipTextModeMessage
    } text_mode;
    LeafFlipResult result;
    bool result_loaded;
    int progress_step;
    uint16_t last_sw;
    const char *stage;
    char error[96];
    char filename[LEAF_FLIP_FILENAME_MAX];
};

typedef struct
{
    LeafFlipApp *app;
    Iso14443_4aPoller *poller;
    BitBuffer *tx;
    BitBuffer *rx;
} LeafFlipReader;

NfcCommand leaf_flip_poller_callback(NfcGenericEvent event, void *context);

bool leaf_flip_save_result(LeafFlipApp *app, const char *filename);
bool leaf_flip_load_result(LeafFlipApp *app, const char *path);
bool leaf_flip_reparse_loaded(LeafFlipApp *app);

void leaf_flip_show_main_menu(LeafFlipApp *app);
void leaf_flip_show_progress(LeafFlipApp *app);
void leaf_flip_update_progress(LeafFlipApp *app);
void leaf_flip_show_verified(LeafFlipApp *app);
void leaf_flip_show_more_menu(LeafFlipApp *app);
void leaf_flip_show_info(LeafFlipApp *app);
void leaf_flip_show_message(LeafFlipApp *app, const char *header, const char *body);
void leaf_flip_show_save_dialog(LeafFlipApp *app);
void leaf_flip_show_error(LeafFlipApp *app);
void leaf_flip_set_error(LeafFlipApp *app, const char *format, ...);
void leaf_flip_signal_progress(LeafFlipApp *app, LeafFlipStep step);
