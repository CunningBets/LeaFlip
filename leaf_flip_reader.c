#include "leaf_flip.h"

#define TAG "LeafFlipReader"

bool leaf_flip_parse_and_verify_certificate(LeafFlipApp *app);
bool leaf_flip_verify_card_signature(LeafFlipApp *app);

static const uint8_t select_app_apdu[] = {0x90, 0x5A, 0x00, 0x00, 0x03, 0xD6, 0x1C, 0xF5, 0x00};
static const uint8_t get_additional_frame_apdu[] = {0x90, 0xAF, 0x00, 0x00, 0x00};

static bool leaf_flip_sw_success(uint16_t sw)
{
    return sw == 0x9000 || sw == 0x9100;
}

static void leaf_flip_log_buffer(const char *prefix, const uint8_t *data, size_t len)
{
    char hex[3 * 64 + 4];
    size_t shown = len > 64 ? 64 : len;
    size_t pos = 0;
    for (size_t i = 0; i < shown && pos + 4 < sizeof(hex); i++)
    {
        pos += snprintf(hex + pos, sizeof(hex) - pos, "%02X ", data[i]);
    }
    if (len > shown && pos + 4 < sizeof(hex))
    {
        snprintf(hex + pos, sizeof(hex) - pos, "...");
    }
    FURI_LOG_I(TAG, "%s [%u]: %s", prefix, (unsigned)len, hex);
}

static bool leaf_flip_transmit(
    LeafFlipReader *reader,
    const uint8_t *apdu,
    size_t apdu_len,
    uint8_t *out,
    size_t out_capacity,
    size_t *out_len,
    uint16_t *sw)
{
    reader->app->last_sw = 0;
    *sw = 0;

    Iso14443_4aError error = Iso14443_4aErrorNone;
    for (uint8_t attempt = 0; attempt < 3; attempt++)
    {
        bit_buffer_reset(reader->tx);
        bit_buffer_reset(reader->rx);
        bit_buffer_append_bytes(reader->tx, apdu, apdu_len);

        leaf_flip_log_buffer(">> TX", apdu, apdu_len);
        error = iso14443_4a_poller_send_block(reader->poller, reader->tx, reader->rx);
        if (error == Iso14443_4aErrorNone)
        {
            break;
        }
        FURI_LOG_W(TAG, "send_block err=%u attempt=%u cmd=%02X", error, attempt, apdu[1]);
        if (error == Iso14443_4aErrorTimeout || error == Iso14443_4aErrorNotPresent)
        {
            break;
        }
        furi_delay_ms(20);
    }

    if (error != Iso14443_4aErrorNone)
    {
        leaf_flip_set_error(
            reader->app, "NFC tx err=%u cmd=%02X len=%u", error, apdu[1], (unsigned)apdu_len);
        return false;
    }

    size_t rx_len = bit_buffer_get_size_bytes(reader->rx);
    const uint8_t *rx = bit_buffer_get_data(reader->rx);
    leaf_flip_log_buffer("<< RX", rx, rx_len);
    if (rx_len < 2)
    {
        leaf_flip_set_error(reader->app, "Short card response (%u)", (unsigned)rx_len);
        return false;
    }
    *sw = ((uint16_t)rx[rx_len - 2] << 8) | rx[rx_len - 1];
    reader->app->last_sw = *sw;
    size_t data_len = rx_len - 2;
    if (data_len > out_capacity)
    {
        leaf_flip_set_error(reader->app, "Response too large");
        return false;
    }
    memcpy(out, rx, data_len);
    *out_len = data_len;
    return true;
}

static void leaf_flip_build_read_apdu(uint8_t file_no, uint32_t offset, uint32_t len, uint8_t apdu[13])
{
    apdu[0] = 0x90;
    apdu[1] = 0xAD;
    apdu[2] = 0x00;
    apdu[3] = 0x00;
    apdu[4] = 0x07;
    apdu[5] = file_no;
    apdu[6] = offset & 0xFF;
    apdu[7] = (offset >> 8) & 0xFF;
    apdu[8] = (offset >> 16) & 0xFF;
    apdu[9] = len & 0xFF;
    apdu[10] = (len >> 8) & 0xFF;
    apdu[11] = (len >> 16) & 0xFF;
    apdu[12] = 0x00;
}

static bool leaf_flip_read_request(
    LeafFlipReader *reader,
    uint32_t offset,
    uint32_t len,
    uint8_t *out,
    size_t out_capacity,
    size_t *out_len,
    uint16_t *final_sw)
{
    uint8_t apdu[13];
    uint8_t chunk[LEAF_FLIP_APDU_MAX];
    size_t chunk_len = 0;
    uint16_t sw = 0;
    *out_len = 0;

    leaf_flip_build_read_apdu(0x02, offset, len, apdu);
    if (!leaf_flip_transmit(reader, apdu, sizeof(apdu), chunk, sizeof(chunk), &chunk_len, &sw))
    {
        return false;
    }

    while (true)
    {
        if (*out_len + chunk_len > out_capacity)
        {
            leaf_flip_set_error(reader->app, "Certificate buffer full");
            return false;
        }
        memcpy(out + *out_len, chunk, chunk_len);
        *out_len += chunk_len;
        if (sw != 0x91AF)
            break;
        if (!leaf_flip_transmit(
                reader,
                get_additional_frame_apdu,
                sizeof(get_additional_frame_apdu),
                chunk,
                sizeof(chunk),
                &chunk_len,
                &sw))
        {
            return false;
        }
    }
    *final_sw = sw;
    return true;
}

static bool leaf_flip_der_total_length(const uint8_t *head, size_t head_len, size_t *total_len)
{
    if (head_len < 2 || head[0] != 0x30)
        return false;
    if ((head[1] & 0x80) == 0)
    {
        *total_len = 2 + head[1];
        return true;
    }
    uint8_t len_len = head[1] & 0x7F;
    if (len_len == 0 || len_len > 3 || head_len < (size_t)(2 + len_len))
        return false;
    size_t body_len = 0;
    for (size_t i = 0; i < len_len; i++)
    {
        body_len = (body_len << 8) | head[2 + i];
    }
    *total_len = 2 + len_len + body_len;
    return true;
}

static bool leaf_flip_read_certificate(LeafFlipReader *reader)
{
    LeafFlipResult *result = &reader->app->result;
    size_t chunk_len = 0;
    uint16_t sw = 0;
    if (!leaf_flip_read_request(reader, 0, 8, result->cert, sizeof(result->cert), &chunk_len, &sw))
    {
        return false;
    }
    if (!leaf_flip_sw_success(sw))
    {
        leaf_flip_set_error(reader->app, "Read cert header failed");
        return false;
    }

    size_t total_len = 0;
    if (!leaf_flip_der_total_length(result->cert, chunk_len, &total_len) ||
        total_len > sizeof(result->cert))
    {
        leaf_flip_set_error(reader->app, "Bad certificate length");
        return false;
    }

    result->cert_len = chunk_len;
    while (result->cert_len < total_len)
    {
        size_t remaining = total_len - result->cert_len;
        /* Cap per-frame length so the response (data + SW) stays under the
         * card's max frame size. Many DESFire/DUOX cards advertise a 256 byte
         * FSC; 0xFF data + 2 SW = 257 bytes overflows. 0x40 is a safe value
         * that works with the smallest reasonable FSC and avoids ISO14443-4
         * I-block chaining we do not implement here. */
        uint32_t request_len = MIN(remaining, (size_t)0x40);
        if (!leaf_flip_read_request(
                reader,
                result->cert_len,
                request_len,
                result->cert + result->cert_len,
                sizeof(result->cert) - result->cert_len,
                &chunk_len,
                &sw))
        {
            return false;
        }
        if (!leaf_flip_sw_success(sw))
        {
            leaf_flip_set_error(reader->app, "Read cert failed at %u", (unsigned)result->cert_len);
            return false;
        }
        result->cert_len += chunk_len;
        if (chunk_len == 0)
            break;
    }
    return result->cert_len == total_len;
}

static bool leaf_flip_parse_auth_response(LeafFlipApp *app)
{
    const uint8_t *cursor = app->result.auth_response;
    const uint8_t *end = app->result.auth_response + app->result.auth_response_len;
    if (cursor >= end || *cursor++ != 0x7C || cursor >= end)
    {
        leaf_flip_set_error(app, "Bad auth response");
        return false;
    }

    size_t total_len = *cursor++;
    if (total_len & 0x80)
    {
        leaf_flip_set_error(app, "Long auth TLV unsupported");
        return false;
    }
    if ((size_t)(end - cursor) < total_len)
    {
        leaf_flip_set_error(app, "Truncated auth response");
        return false;
    }
    end = cursor + total_len;

    bool have_random = false;
    bool have_signature = false;
    while (cursor + 2 <= end)
    {
        uint8_t tag = *cursor++;
        uint8_t len = *cursor++;
        if ((size_t)(end - cursor) < len)
            break;
        if (tag == 0x81 && len == LEAF_FLIP_RANDOM_SIZE)
        {
            memcpy(app->result.card_random, cursor, LEAF_FLIP_RANDOM_SIZE);
            have_random = true;
        }
        else if (tag == 0x82 && (len == LEAF_FLIP_SIGNATURE_SIZE || len == 0x44))
        {
            memcpy(app->result.signature, cursor + len - LEAF_FLIP_SIGNATURE_SIZE, LEAF_FLIP_SIGNATURE_SIZE);
            have_signature = true;
        }
        cursor += len;
    }
    if (!(have_random && have_signature))
    {
        leaf_flip_set_error(app, "Missing auth TLVs");
        return false;
    }
    return true;
}

static bool leaf_flip_authenticate(LeafFlipReader *reader)
{
    static const uint8_t prefix[] = {0x00, 0x88, 0x00, 0x00, 0x16, 0x80, 0x00, 0x7C, 0x12, 0x81, 0x10};
    uint8_t apdu[sizeof(prefix) + LEAF_FLIP_RANDOM_SIZE + 1];
    uint16_t sw = 0;

    furi_hal_random_fill_buf(reader->app->result.challenge, LEAF_FLIP_RANDOM_SIZE);
    memcpy(apdu, prefix, sizeof(prefix));
    memcpy(apdu + sizeof(prefix), reader->app->result.challenge, LEAF_FLIP_RANDOM_SIZE);
    apdu[sizeof(apdu) - 1] = 0x00; /* Le */

    /* Try case-4 APDU (with Le=0x00). Some cards reject with 67 00 (wrong
     * length); if so, retry as case-3 (no Le). If the card replies 6C XX it
     * is hinting the exact Le it wants — retry with that. */
    if (!leaf_flip_transmit(
            reader,
            apdu,
            sizeof(apdu),
            reader->app->result.auth_response,
            sizeof(reader->app->result.auth_response),
            &reader->app->result.auth_response_len,
            &sw))
    {
        return false;
    }

    if ((sw & 0xFF00) == 0x6C00)
    {
        apdu[sizeof(apdu) - 1] = sw & 0xFF;
        if (!leaf_flip_transmit(
                reader,
                apdu,
                sizeof(apdu),
                reader->app->result.auth_response,
                sizeof(reader->app->result.auth_response),
                &reader->app->result.auth_response_len,
                &sw))
        {
            return false;
        }
    }
    else if (sw == 0x6700)
    {
        /* Retry without Le (case-3). */
        if (!leaf_flip_transmit(
                reader,
                apdu,
                sizeof(apdu) - 1,
                reader->app->result.auth_response,
                sizeof(reader->app->result.auth_response),
                &reader->app->result.auth_response_len,
                &sw))
        {
            return false;
        }
    }

    if (!leaf_flip_sw_success(sw))
    {
        leaf_flip_set_error(reader->app, "Internal Authenticate failed (SW=%04X)", sw);
        return false;
    }
    return leaf_flip_parse_auth_response(reader->app);
}

static NfcCommand leaf_flip_run_flow(LeafFlipReader *reader)
{
    LeafFlipApp *app = reader->app;
    uint8_t response[LEAF_FLIP_APDU_MAX];
    size_t response_len = 0;
    uint16_t sw = 0;

    bool ok = false;
    do
    {
        const Iso14443_4aData *data = nfc_poller_get_data(app->poller);
        size_t uid_len = 0;
        const uint8_t *uid = iso14443_4a_get_uid(data, &uid_len);
        if (uid && uid_len <= LEAF_FLIP_UID_MAX)
        {
            memcpy(app->result.uid, uid, uid_len);
            app->result.uid_len = uid_len;
        }

        app->stage = "SELECT";
        if (!leaf_flip_transmit(
                reader, select_app_apdu, sizeof(select_app_apdu), response, sizeof(response), &response_len, &sw))
        {
            break;
        }
        if (!(leaf_flip_sw_success(sw) || (sw == 0x9000 && response_len == 1 && response[0] == 0x00)))
        {
            leaf_flip_set_error(app, "Select Open Application failed");
            break;
        }
        leaf_flip_signal_progress(app, LeafFlipStepSelect);
        if (!app->result.root_verified)
        {
            app->stage = "READ certificate";
            if (!leaf_flip_read_certificate(reader))
                break;
            leaf_flip_signal_progress(app, LeafFlipStepRead);
            app->stage = "VERIFY certificate";
            if (!leaf_flip_parse_and_verify_certificate(app))
                break;
            leaf_flip_signal_progress(app, LeafFlipStepCertVerified);
        }
        else
        {
            leaf_flip_signal_progress(app, LeafFlipStepRead);
            leaf_flip_signal_progress(app, LeafFlipStepCertVerified);
        }
        app->stage = "AUTH challenge";
        if (!leaf_flip_authenticate(reader))
            break;
        leaf_flip_signal_progress(app, LeafFlipStepAuth);
        app->stage = "VERIFY card";
        if (!leaf_flip_verify_card_signature(app))
            break;
        leaf_flip_signal_progress(app, LeafFlipStepCardVerified);
        ok = true;
    } while (false);

    view_dispatcher_send_custom_event(app->view_dispatcher, ok ? LeafFlipEventSuccess : LeafFlipEventError);
    return NfcCommandStop;
}

NfcCommand leaf_flip_poller_callback(NfcGenericEvent event, void *context)
{
    LeafFlipReader *reader = context;
    NfcCommand ret = NfcCommandContinue;
    furi_assert(event.protocol == NfcProtocolIso14443_4a);
    const Iso14443_4aPollerEvent *iso_event = event.event_data;
    reader->poller = event.instance;

    if (iso_event->type == Iso14443_4aPollerEventTypeReady)
    {
        nfc_device_set_data(reader->app->nfc_device, NfcProtocolIso14443_4a, nfc_poller_get_data(reader->app->poller));
        ret = leaf_flip_run_flow(reader);
        furi_thread_set_current_priority(FuriThreadPriorityLowest);
    }
    else if (iso_event->type == Iso14443_4aPollerEventTypeError)
    {
        Iso14443_4aPollerEventData *data = iso_event->data;
        if (data->error == Iso14443_4aErrorProtocol)
        {
            leaf_flip_set_error(reader->app, "ISO14443-4A protocol error");
            view_dispatcher_send_custom_event(reader->app->view_dispatcher, LeafFlipEventError);
            ret = NfcCommandStop;
        }
    }
    return ret;
}
