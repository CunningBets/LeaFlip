#include "leaf_flip.h"

#define TAG "LeafFlipAccess"

/*
 * Access list file format (LEAF_FLIP_ACCESS_LIST_PATH):
 *   - Plain text, one entry per line
 *   - Each line: <OPEN_ID>[<whitespace><ALIAS>]
 *   - OPEN_ID is the 12-digit decimal Open ID from the card certificate
 *   - ALIAS is optional human-readable label (rest of line, trimmed)
 *   - Lines starting with '#' or blank lines are ignored
 *
 * Example:
 *   # LeafFlip access list
 *   123456789012 Alice
 *   234567890123 Bob (door 2)
 *   345678901234
 */

bool leaf_flip_access_list_exists(LeafFlipApp *app)
{
    return storage_file_exists(app->storage, LEAF_FLIP_ACCESS_LIST_PATH);
}

/* Trim whitespace in-place. Returns the trimmed string (may equal s+offset). */
static char *trim_ws(char *s)
{
    while (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n')
        s++;
    char *end = s + strlen(s);
    while (end > s && (end[-1] == ' ' || end[-1] == '\t' || end[-1] == '\r' || end[-1] == '\n'))
        end--;
    *end = '\0';
    return s;
}

/* Parse one line into open_id and alias (alias may be empty). open_id_out and
 * alias_out are caller-provided buffers. Returns true if line had a valid id. */
static bool parse_line(
    const char *line,
    char *open_id_out, size_t open_id_size,
    char *alias_out, size_t alias_size)
{
    /* Make a mutable copy */
    char buf[160];
    strncpy(buf, line, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    char *trimmed = trim_ws(buf);
    if (trimmed[0] == '\0' || trimmed[0] == '#')
        return false;

    /* Split at first whitespace */
    char *space = trimmed;
    while (*space && *space != ' ' && *space != '\t')
        space++;
    char *alias_part = NULL;
    if (*space)
    {
        *space = '\0';
        alias_part = trim_ws(space + 1);
    }

    if (trimmed[0] == '\0')
        return false;
    strncpy(open_id_out, trimmed, open_id_size - 1);
    open_id_out[open_id_size - 1] = '\0';
    if (alias_out && alias_size)
    {
        if (alias_part)
        {
            strncpy(alias_out, alias_part, alias_size - 1);
            alias_out[alias_size - 1] = '\0';
        }
        else
        {
            alias_out[0] = '\0';
        }
    }
    return true;
}

/* Iterate the access list, calling cb for each entry. cb returns true to stop.
 * Returns the value of cb (true means "found/handled"). */
typedef bool (*AccessLineCb)(const char *open_id, const char *alias, void *ctx);

static bool foreach_line(LeafFlipApp *app, AccessLineCb cb, void *ctx)
{
    File *file = storage_file_alloc(app->storage);
    bool stopped = false;
    if (storage_file_open(file, LEAF_FLIP_ACCESS_LIST_PATH, FSAM_READ, FSOM_OPEN_EXISTING))
    {
        char line[160];
        size_t pos = 0;
        char ch;
        while (storage_file_read(file, &ch, 1) == 1)
        {
            if (ch == '\n' || pos == sizeof(line) - 1)
            {
                line[pos] = '\0';
                char open_id[LEAF_FLIP_OPEN_ID_SIZE];
                char alias[LEAF_FLIP_ALIAS_MAX];
                if (parse_line(line, open_id, sizeof(open_id), alias, sizeof(alias)))
                {
                    if (cb(open_id, alias, ctx))
                    {
                        stopped = true;
                        break;
                    }
                }
                pos = 0;
            }
            else
            {
                line[pos++] = ch;
            }
        }
        if (!stopped && pos > 0)
        {
            line[pos] = '\0';
            char open_id[LEAF_FLIP_OPEN_ID_SIZE];
            char alias[LEAF_FLIP_ALIAS_MAX];
            if (parse_line(line, open_id, sizeof(open_id), alias, sizeof(alias)))
            {
                if (cb(open_id, alias, ctx))
                    stopped = true;
            }
        }
    }
    storage_file_close(file);
    storage_file_free(file);
    return stopped;
}

typedef struct
{
    const char *target;
    char *alias_out;
    size_t alias_size;
    bool found;
} LookupCtx;

static bool lookup_cb(const char *open_id, const char *alias, void *ctx)
{
    LookupCtx *l = ctx;
    if (strcmp(open_id, l->target) == 0)
    {
        if (l->alias_out && l->alias_size)
        {
            strncpy(l->alias_out, alias, l->alias_size - 1);
            l->alias_out[l->alias_size - 1] = '\0';
        }
        l->found = true;
        return true;
    }
    return false;
}

bool leaf_flip_access_list_lookup(
    LeafFlipApp *app, const char *open_id, char *alias_out, size_t alias_out_size)
{
    if (!leaf_flip_access_list_exists(app))
        return false;
    LookupCtx ctx = {open_id, alias_out, alias_out_size, false};
    foreach_line(app, lookup_cb, &ctx);
    return ctx.found;
}

bool leaf_flip_access_list_add(LeafFlipApp *app, const char *open_id, const char *alias)
{
    if (!open_id || open_id[0] == '\0')
        return false;
    /* Skip if already present */
    if (leaf_flip_access_list_lookup(app, open_id, NULL, 0))
        return true;

    storage_simply_mkdir(app->storage, LEAF_FLIP_APP_FOLDER);

    File *file = storage_file_alloc(app->storage);
    bool ok = false;
    if (storage_file_open(file, LEAF_FLIP_ACCESS_LIST_PATH, FSAM_WRITE, FSOM_OPEN_APPEND))
    {
        char line[160];
        int n;
        if (alias && alias[0])
            n = snprintf(line, sizeof(line), "%s %s\n", open_id, alias);
        else
            n = snprintf(line, sizeof(line), "%s\n", open_id);
        if (n > 0 && storage_file_write(file, line, n) == (size_t)n)
            ok = true;
    }
    storage_file_close(file);
    storage_file_free(file);
    return ok;
}

bool leaf_flip_access_list_remove(LeafFlipApp *app, const char *open_id)
{
    if (!leaf_flip_access_list_exists(app))
        return false;

    /* Read whole file, write back without matching lines */
    File *in = storage_file_alloc(app->storage);
    if (!storage_file_open(in, LEAF_FLIP_ACCESS_LIST_PATH, FSAM_READ, FSOM_OPEN_EXISTING))
    {
        storage_file_free(in);
        return false;
    }

    /* Buffer entire file (cap reasonable size). */
    uint64_t size = storage_file_size(in);
    if (size > 16384)
    {
        storage_file_close(in);
        storage_file_free(in);
        return false;
    }
    char *buf = malloc((size_t)size + 1);
    size_t read = storage_file_read(in, buf, (size_t)size);
    buf[read] = '\0';
    storage_file_close(in);
    storage_file_free(in);

    /* Build output skipping lines whose open_id matches */
    FuriString *out = furi_string_alloc();
    bool removed = false;
    char *p = buf;
    while (p && *p)
    {
        char *eol = strchr(p, '\n');
        size_t llen = eol ? (size_t)(eol - p) : strlen(p);
        char line[160];
        size_t copy = MIN(llen, sizeof(line) - 1);
        memcpy(line, p, copy);
        line[copy] = '\0';

        char open_id_buf[LEAF_FLIP_OPEN_ID_SIZE];
        char alias_buf[LEAF_FLIP_ALIAS_MAX];
        bool drop = false;
        if (parse_line(line, open_id_buf, sizeof(open_id_buf), alias_buf, sizeof(alias_buf)))
        {
            if (strcmp(open_id_buf, open_id) == 0)
            {
                drop = true;
                removed = true;
            }
        }
        if (!drop)
        {
            furi_string_cat_str(out, line);
            furi_string_cat_str(out, "\n");
        }
        if (!eol)
            break;
        p = eol + 1;
    }
    free(buf);

    if (removed)
    {
        File *of = storage_file_alloc(app->storage);
        if (storage_file_open(of, LEAF_FLIP_ACCESS_LIST_PATH, FSAM_WRITE, FSOM_CREATE_ALWAYS))
        {
            const char *s = furi_string_get_cstr(out);
            size_t len = furi_string_size(out);
            storage_file_write(of, s, len);
        }
        storage_file_close(of);
        storage_file_free(of);
    }

    furi_string_free(out);
    return removed;
}
