#pragma once

#include <furi.h>
#include <furi_hal.h>
#include <gui/gui.h>
#include <gui/view_dispatcher.h>
#include <gui/modules/popup.h>
#include <gui/modules/submenu.h>
#include <gui/modules/text_box.h>
#include <notification/notification_messages.h>
#include <storage/storage.h>
#include <dialogs/dialogs.h>
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

typedef enum
{
    LeafFlipViewMenu,
    LeafFlipViewPopup,
    LeafFlipViewTextBox,
} LeafFlipView;

typedef enum
{
    LeafFlipEventDetected = 100,
    LeafFlipEventSuccess,
    LeafFlipEventError,
} LeafFlipEvent;

typedef struct
{
    uint8_t cert[LEAF_FLIP_CERT_MAX];
    size_t cert_len;
    char open_id[LEAF_FLIP_OPEN_ID_SIZE];
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
    Submenu *submenu;
    Popup *popup;
    TextBox *text_box;
    FuriString *text;

    Nfc *nfc;
    NfcScanner *scanner;
    NfcPoller *poller;
    NfcDevice *nfc_device;

    LeafFlipView current_view;
    LeafFlipResult result;
    uint16_t last_sw;
    const char *stage;
    char error[96];
};

typedef struct
{
    LeafFlipApp *app;
    Iso14443_4aPoller *poller;
    BitBuffer *tx;
    BitBuffer *rx;
} LeafFlipReader;

NfcCommand leaf_flip_poller_callback(NfcGenericEvent event, void *context);
bool leaf_flip_save_result(LeafFlipApp *app);
void leaf_flip_show_menu(LeafFlipApp *app);
void leaf_flip_show_result(LeafFlipApp *app);
void leaf_flip_show_error(LeafFlipApp *app);
void leaf_flip_set_error(LeafFlipApp *app, const char *format, ...);
