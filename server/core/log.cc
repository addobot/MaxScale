/*
 * Copyright (c) 2016 MariaDB Corporation Ab
 *
 * Use of this software is governed by the Business Source License included
 * in the LICENSE.TXT file and at www.mariadb.com/bsl11.
 *
 * Change Date: 2024-08-24
 *
 * On the date above, in accordance with the Business Source License, use
 * of this software will be governed by version 2 or later of the General
 * Public License.
 */

#include <maxscale/log.hh>

#include <sys/time.h>
#include <syslog.h>

#include <atomic>
#include <cinttypes>
#include <fstream>

#ifdef HAVE_SYSTEMD
#include <systemd/sd-journal.h>
#endif

#include <maxbase/log.hh>
#include <maxbase/logger.hh>

#include <maxscale/cn_strings.hh>
#include <maxscale/config.hh>
#include <maxscale/json_api.hh>
#include <maxscale/session.hh>
#include <maxbase/string.hh>

namespace
{

struct ThisUnit
{
    std::atomic<int> rotation_count {0};
};
ThisUnit this_unit;

const char* LOGFILE_NAME = "maxscale.log";

size_t mxs_get_context(char* buffer, size_t len)
{
    mxb_assert(len >= 20);      // Needed for "9223372036854775807"

    uint64_t session_id = session_get_current_id();

    if (session_id != 0)
    {
        len = snprintf(buffer, len, "%" PRIu64, session_id);
    }
    else
    {
        len = 0;
    }

    return len;
}

void mxs_log_in_memory(const char* msg, size_t len)
{
    MXS_SESSION* session = session_get_current();
    if (session)
    {
        session_append_log(session, msg);
    }
}
}

bool mxs_log_init(const char* ident, const char* logdir, mxs_log_target_t target)
{
    mxb::Logger::set_ident("MariaDB MaxScale");

    return mxb_log_init(ident, logdir, LOGFILE_NAME, target, mxs_get_context, mxs_log_in_memory);
}

namespace
{

struct Cursors
{
    std::string first;
    std::string last;
    std::string current;
    std::string next;
    std::string previous;
};

std::pair<json_t*, Cursors> get_syslog_data(const std::string& cursor)
{
    json_t* arr = json_array();
    Cursors cursors;

#ifdef HAVE_SYSTEMD

    sd_journal* j;
    int rc = sd_journal_open(&j, SD_JOURNAL_LOCAL_ONLY);

    auto get_cursor = [j]() {
            char* c;
            sd_journal_get_cursor(j, &c);
            std::string cur = c;
            MXS_FREE(c);
            return cur;
        };

    if (rc < 0)
    {
        MXS_ERROR("Failed to open system journal: %s", mxs_strerror(-rc));
    }
    else
    {
        sd_journal_add_match(j, "_COMM=maxscale", 0);
        sd_journal_seek_head(j);
        sd_journal_next(j);
        cursors.first = get_cursor();

        if (cursor.empty())
        {
            sd_journal_seek_tail(j);
            sd_journal_previous_skip(j, 100);
            cursors.previous = get_cursor();
            sd_journal_seek_tail(j);
            sd_journal_previous_skip(j, 50);
        }
        else
        {
            sd_journal_seek_cursor(j, cursor.c_str());
            sd_journal_previous_skip(j, 50);
            cursors.previous = get_cursor();
            sd_journal_seek_cursor(j, cursor.c_str());
        }

        for (int i = 0; i < 50 && sd_journal_next(j) > 0; i++)
        {
            if (cursors.current.empty())
            {
                cursors.current = get_cursor();
            }

            const void* data;
            size_t length;
            json_t* obj = json_object();

            json_object_set_new(obj, "id", json_string(get_cursor().c_str()));

            while (sd_journal_enumerate_data(j, &data, &length) > 0)
            {
                std::string s((const char*)data, length);
                auto pos = s.find_first_of('=');
                auto key = s.substr(0, pos);

                if (key.front() == '_' || strncmp(key.c_str(), "SYSLOG", 6) == 0)
                {
                    // Ignore auto-generated entries
                    continue;
                }

                auto value = s.substr(pos + 1);

                if (!value.empty())
                {
                    if (key == "PRIORITY")
                    {
                        // Convert the numeric priority value to the string value
                        value = mxb_log_level_to_string(atoi(value.c_str()));
                    }

                    std::transform(key.begin(), key.end(), key.begin(), ::tolower);
                    json_object_set_new(obj, key.c_str(), json_string(value.c_str()));
                }
            }

            json_array_append_new(arr, obj);
        }

        if (sd_journal_next(j) > 0)
        {
            cursors.next = get_cursor();
        }

        sd_journal_seek_tail(j);
        sd_journal_previous(j);
        cursors.last = get_cursor();
    }

    sd_journal_close(j);
#endif

    return {arr, cursors};
}

std::pair<json_t*, Cursors> get_maxlog_data(const std::string& cursor)
{
    Cursors cursors;
    json_t* arr = json_array();
    int n = 0;
    int end = 0;
    std::ifstream file(mxb_log_get_filename());

    if (file.good())
    {
        end = std::count(std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>(), '\n');
        file.seekg(std::ios_base::beg);

        if (cursor.empty())
        {
            n = end > 50 ? end - 50 : 0;
        }
        else
        {
            n = atoi(cursor.c_str());
        }

        for (int i = 0; i < n; i++)
        {
            file.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        }

        int lineno = n;

        for (std::string line; std::getline(file, line);)
        {
            // The timestamp is always the same size followed by three empty spaces. If high precision logging
            // is enabled, the timestamp string is four characters longer.
            mxb::Regex date("^([0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}([.][0-9]{3})?)");
            mxb_assert(date.valid());
            auto captures = date.substr(line);

            if (captures.empty())
            {
                // Could be a multi-line message but it can also be one of the log delimiters. We ignore it as
                // the main interest is in complete messages.
                continue;
            }

            const auto& timestamp = captures[0];
            line.erase(0, timestamp.size());
            mxb::ltrim(line);

            // The logging system sometimes generates messages without a log level. Treat these messages
            // as notice level messages.
            std::string priority = "notice";
            int prio = mxb_log_prefix_to_level(line.c_str());

            if (prio != -1)
            {
                priority = mxb_log_level_to_string(prio);
                line.erase(0, line.find_first_of(':') + 1);
                mxb::ltrim(line);
            }

            auto get_value = [&line](char lp, char rp) {
                    std::string rval;

                    if (line.front() == lp)
                    {
                        line.erase(0, 1);
                        rval = line.substr(0, line.find_first_of(rp, 1));
                        line.erase(0, rval.size() + 1);
                        mxb::ltrim(line);
                    }

                    return rval;
                };

            std::string session = get_value('(', ')');
            std::string module = get_value('[', ']');
            std::string object = get_value('{', '}');

            mxb::trim(line);

            json_t* obj = json_object();
            json_object_set_new(obj, "message", json_string(line.c_str()));
            json_object_set_new(obj, "timestamp", json_string(timestamp.c_str()));
            json_object_set_new(obj, "priority", json_string(priority.c_str()));
            json_object_set_new(obj, "id", json_string(std::to_string(lineno).c_str()));

            if (!session.empty())
            {
                json_object_set_new(obj, "session", json_string(session.c_str()));
            }

            if (!module.empty())
            {
                json_object_set_new(obj, "module", json_string(module.c_str()));
            }

            if (!object.empty())
            {
                json_object_set_new(obj, "object", json_string(object.c_str()));
            }

            json_array_append_new(arr, obj);

            ++lineno;
        }

        cursors.first = "0";
        cursors.previous = std::to_string(n > 50 ? n - 50 : 0);
        cursors.next = std::to_string(end > n + 50 ? n + 50 : end);
        cursors.current = std::to_string(n);
        cursors.last = std::to_string(end);
    }

    return {arr, cursors};
}

json_t* get_log_priorities()
{
    json_t* arr = json_array();

    if (mxb_log_is_priority_enabled(LOG_ALERT))
    {
        json_array_append_new(arr, json_string("alert"));
    }

    if (mxb_log_is_priority_enabled(LOG_ERR))
    {
        json_array_append_new(arr, json_string("error"));
    }

    if (mxb_log_is_priority_enabled(LOG_WARNING))
    {
        json_array_append_new(arr, json_string("warning"));
    }

    if (mxb_log_is_priority_enabled(LOG_NOTICE))
    {
        json_array_append_new(arr, json_string("notice"));
    }

    if (mxb_log_is_priority_enabled(LOG_INFO))
    {
        json_array_append_new(arr, json_string("info"));
    }

    if (mxb_log_is_priority_enabled(LOG_DEBUG))
    {
        json_array_append_new(arr, json_string("debug"));
    }

    return arr;
}
}

json_t* mxs_logs_to_json(const char* host, const std::string& cursor)
{
    std::unordered_set<std::string> log_params = {
        "maxlog",     "syslog",    "log_info",       "log_warning",
        "log_notice", "log_debug", "log_throttling", "ms_timestamp"
    };

    json_t* params = mxs::Config::get().to_json();
    void* ptr;
    const char* key;
    json_t* value;

    // Remove other parameters to appear more backwards compatible
    json_object_foreach_safe(params, ptr, key, value)
    {
        if (log_params.count(key) == 0)
        {
            json_object_del(params, key);
        }
    }

    json_t* attr = json_object();
    json_object_set_new(attr, CN_PARAMETERS, params);
    json_object_set_new(attr, "log_file", json_string(mxb_log_get_filename()));
    json_object_set_new(attr, "log_priorities", get_log_priorities());

    const auto& cnf = mxs::Config::get();

    Cursors cursors;
    json_t* log = nullptr;

    if (cnf.syslog.get())
    {
        std::tie(log, cursors) = get_syslog_data(cursor);
    }
    else if (cnf.maxlog.get())
    {
        std::tie(log, cursors) = get_maxlog_data(cursor);
    }

    json_object_set_new(attr, "log", log);

    json_t* data = json_object();
    json_object_set_new(data, CN_ATTRIBUTES, attr);
    json_object_set_new(data, CN_ID, json_string("logs"));
    json_object_set_new(data, CN_TYPE, json_string("logs"));

    json_t* rval = mxs_json_resource(host, MXS_JSON_API_LOGS, data);

    // Create pagination links
    json_t* links = json_object_get(rval, CN_LINKS);
    std::string base = json_string_value(json_object_get(links, "self"));

    if (!cursors.first.empty())
    {
        auto first = base + "?page[cursor]=" + cursors.first;
        json_object_set_new(links, "first", json_string(first.c_str()));
    }

    if (!cursors.previous.empty())
    {
        auto prev = base + "?page[cursor]=" + cursors.previous;
        json_object_set_new(links, "prev", json_string(prev.c_str()));
    }

    if (!cursors.next.empty())
    {
        auto next = base + "?page[cursor]=" + cursors.next;
        json_object_set_new(links, "next", json_string(next.c_str()));
    }

    if (!cursors.current.empty())
    {
        auto self = base + "?page[cursor]=" + cursors.current;
        json_object_set_new(links, "self", json_string(self.c_str()));
    }

    if (!cursors.last.empty())
    {
        auto last = base + "?page[cursor]=" + cursors.last;
        json_object_set_new(links, "last", json_string(last.c_str()));
    }

    return rval;
}

bool mxs_log_rotate()
{
    bool rotated = mxb_log_rotate();
    if (rotated)
    {
        this_unit.rotation_count.fetch_add(1, std::memory_order_relaxed);
    }
    return rotated;
}

int mxs_get_log_rotation_count()
{
    return this_unit.rotation_count.load(std::memory_order_relaxed);
}
