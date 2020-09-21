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

/**
 * @file The embedded HTTP protocol administrative interface
 */
#include "internal/admin.hh"

#include <climits>
#include <new>
#include <fstream>
#include <unordered_map>

#include <microhttpd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/stat.h>
#include <jwt-cpp/jwt.h>

#include <maxbase/atomic.h>
#include <maxbase/assert.h>
#include <maxscale/utils.h>
#include <maxscale/config.hh>
#include <maxscale/clock.h>
#include <maxscale/http.hh>
#include <maxscale/paths.hh>
#include <maxscale/mainworker.hh>

#include "internal/adminusers.hh"
#include "internal/resource.hh"

using std::string;
using std::ifstream;

namespace
{

static char auth_failure_response[] = "{\"errors\": [ { \"detail\": \"Access denied\" } ] }";
static char no_https_response[] = "{\"errors\": [ { \"detail\": \"Connection is not encrypted\" } ] }";

// The page served when the GUI is accessed without HTTPS
const char* gui_not_secure_page =
    R"EOF(
<!DOCTYPE html>
<html>
  <head>
    <style>code {color: grey; background-color: #f1f1f1; padding: 2px;}</style>
    <meta charset="UTF-8">
    <title>Connection Not Secure</title>
  </head>
  <body>
    <p>
      The MaxScale GUI requires HTTPS to work, please enable it by configuring the
      <a href="https://mariadb.com/kb/en/mariadb-maxscale-24-mariadb-maxscale-configuration-guide/#admin_ssl_key">admin_ssl_key</a>
      and <a href="https://mariadb.com/kb/en/mariadb-maxscale-24-mariadb-maxscale-configuration-guide/#admin_ssl_cert">admin_ssl_cert</a> parameters.
      To allow insecure use of the GUI, add <code>admin_secure_gui=false</code> under the <code>[maxscale]</code> section.
      To disable the GUI completely, add  <code>admin_gui=false</code> under the <code>[maxscale]</code> section.
    </p>
    <p>
      For more information about securing the admin interface of your MaxScale installation, refer to the
      <a href="https://mariadb.com/kb/en/mariadb-maxscale-24-rest-api-tutorial/#configuration-and-hardening">Configuration and Hardening</a>
      section of the REST API tutorial.
    </p>
  </body>
</html>
)EOF";

const std::string TOKEN_BODY = "token_body";
const std::string TOKEN_SIG = "token_sig";

static struct ThisUnit
{
    struct MHD_Daemon* daemon = nullptr;
    std::string        ssl_key;
    std::string        ssl_cert;
    std::string        ssl_ca;
    bool               using_ssl = false;
    bool               log_daemon_errors = true;
    bool               cors = false;
    std::string        sign_key;

    std::unordered_map<std::string, std::string> files;
} this_unit;

int header_cb(void* cls,
              enum MHD_ValueKind kind,
              const char* key,
              const char* value)
{
    Client::Headers* res = (Client::Headers*)cls;
    std::string k = key;
    std::transform(k.begin(), k.end(), k.begin(), ::tolower);
    res->emplace(k, value);
    return MHD_YES;
}

int cookie_cb(void* cls,
              enum MHD_ValueKind kind,
              const char* key,
              const char* value)
{
    std::pair<std::string, std::string>* res = (std::pair<std::string, std::string>*)cls;

    if (key == TOKEN_BODY)
    {
        res->first = value;
    }
    else if (key == TOKEN_SIG)
    {
        res->second = value;
    }

    return MHD_YES;
}

Client::Headers get_headers(MHD_Connection* connection)
{
    Client::Headers rval;
    MHD_get_connection_values(connection, MHD_HEADER_KIND, header_cb, &rval);
    return rval;
}

std::string get_cookie_token(MHD_Connection* connection)
{
    std::pair<std::string, std::string> token;
    MHD_get_connection_values(connection, MHD_COOKIE_KIND, cookie_cb, &token);
    return token.first + token.second;
}

static bool modifies_data(const string& method)
{
    return method == MHD_HTTP_METHOD_POST || method == MHD_HTTP_METHOD_PUT
           || method == MHD_HTTP_METHOD_DELETE || method == MHD_HTTP_METHOD_PATCH;
}

int handle_client(void* cls,
                  MHD_Connection* connection,
                  const char* url,
                  const char* method,
                  const char* version,
                  const char* upload_data,
                  size_t* upload_data_size,
                  void** con_cls)

{
    if (*con_cls == NULL)
    {
        if ((*con_cls = new(std::nothrow) Client(connection)) == NULL)
        {
            return MHD_NO;
        }
    }

    Client* client = static_cast<Client*>(*con_cls);
    return client->handle(url, method, upload_data, upload_data_size);
}

void handle_upgrade(void* cls, MHD_Connection* connection, void* con_cls,
                    const char* extra_in, size_t extra_in_size,
                    int socket, MHD_UpgradeResponseHandle* urh)
{
    Client* client = reinterpret_cast<Client*>(cls);

    auto func = [client, socket, urh](auto action) {
            if (action == mxb::Worker::Call::EXECUTE && client->ws_upgraded(socket))
            {
                return true;
            }
            else
            {
                client->ws_close(socket);
                MHD_upgrade_action(urh, MHD_UPGRADE_ACTION_CLOSE);
                return false;
            }
        };

    // Send the initial payload
    if (!client->ws_upgraded(socket))
    {
        MHD_upgrade_action(urh, MHD_UPGRADE_ACTION_CLOSE);
    }
    else
    {
        mxs::MainWorker::get()->delayed_call(500, func);
    }
}

static bool host_to_sockaddr(const char* host, uint16_t port, struct sockaddr_storage* addr)
{
    struct addrinfo* ai = NULL, hint = {};
    int rc;
    hint.ai_socktype = SOCK_STREAM;
    hint.ai_family = AF_UNSPEC;
    hint.ai_flags = AI_ALL;

    if ((rc = getaddrinfo(host, NULL, &hint, &ai)) != 0)
    {
        MXS_ERROR("Failed to obtain address for host %s: %s", host, gai_strerror(rc));
        return false;
    }

    /* Take the first one */
    if (ai)
    {
        memcpy(addr, ai->ai_addr, ai->ai_addrlen);

        if (addr->ss_family == AF_INET)
        {
            struct sockaddr_in* ip = (struct sockaddr_in*)addr;
            (*ip).sin_port = htons(port);
        }
        else if (addr->ss_family == AF_INET6)
        {
            struct sockaddr_in6* ip = (struct sockaddr_in6*)addr;
            (*ip).sin6_port = htons(port);
        }
    }

    freeaddrinfo(ai);
    return true;
}

std::string load_file(const std::string& file)
{
    std::ostringstream ss;
    std::ifstream infile(file);

    if (infile)
    {
        ss << infile.rdbuf();
    }
    else
    {
        MXS_ERROR("Failed to load file '%s': %d, %s", file.c_str(), errno, mxs_strerror(errno));
    }

    return ss.str();
}

std::string get_file(const std::string& file)
{
    std::string rval;

    if (this_unit.using_ssl || !mxs::Config::get().secure_gui)
    {
        if (this_unit.files.find(file) == this_unit.files.end())
        {
            this_unit.files[file] = load_file(file);
        }

        rval = this_unit.files[file];
    }
    else
    {
        // Don't serve files over insecure connections
        rval = gui_not_secure_page;
    }

    return rval;
}

std::string get_filename(const HttpRequest& request)
{
    std::string sharedir = mxs::sharedir();
    sharedir += "/gui/";
    std::string path = sharedir;

    if (request.uri_part_count() == 0)
    {
        path += "index.html";
    }
    else
    {
        path += request.uri_segment(0, request.uri_part_count());
    }

    char pathbuf[PATH_MAX + 1] = "";

    if (realpath(path.c_str(), pathbuf) && access(pathbuf, R_OK) == 0
        && strncmp(pathbuf, sharedir.c_str(), sharedir.length()) == 0)
    {
        // A valid file that's stored in the GUI directory
        path.assign(pathbuf);
    }
    else
    {
        path.clear();
    }

    return path;
}

static bool load_ssl_certificates()
{
    bool rval = true;
    const auto& config = mxs::Config::get();
    const auto& key = config.admin_ssl_key;
    const auto& cert = config.admin_ssl_cert;
    const auto& ca = config.admin_ssl_ca_cert;

    if (!key.empty() && !cert.empty())
    {
        this_unit.ssl_key = load_file(key.c_str());
        this_unit.ssl_cert = load_file(cert.c_str());

        if (!ca.empty())
        {
            this_unit.ssl_ca = load_file(ca.c_str());
        }

        rval = !this_unit.ssl_key.empty() && !this_unit.ssl_cert.empty()
            && (ca.empty() || !this_unit.ssl_ca.empty());

        if (rval)
        {
            this_unit.using_ssl = true;
        }
    }

    return rval;
}

void admin_log_error(void* arg, const char* fmt, va_list ap)
{
    if (this_unit.log_daemon_errors)
    {
        char buf[1024];
        vsnprintf(buf, sizeof(buf), fmt, ap);
        MXS_ERROR("REST API HTTP daemon error: %s\n", mxb::trimmed_copy(buf).c_str());
    }
}

void close_client(void* cls,
                  MHD_Connection* connection,
                  void** con_cls,
                  enum MHD_RequestTerminationCode toe)
{
    Client* client = static_cast<Client*>(*con_cls);
    delete client;
}

bool authorize_user(const char* user, const char* method, const char* url)
{
    bool rval = true;

    if (modifies_data(method) && !admin_user_is_inet_admin(user, nullptr))
    {
        if (mxs::Config::get().admin_log_auth_failures.get())
        {
            MXS_WARNING("Authorization failed for '%s', request requires "
                        "administrative privileges. Request: %s %s",
                        user, method, url);
        }
        rval = false;
    }

    return rval;
}

void init_jwt_sign_key()
{
    // Initialize JWT signing key
    std::random_device gen;
    constexpr auto KEY_BITS = 512;
    constexpr auto VALUE_SIZE = sizeof(decltype(gen()));
    constexpr auto NUM_VALUES = KEY_BITS / VALUE_SIZE;
    std::vector<decltype(gen())> key;
    key.reserve(NUM_VALUES);
    std::generate_n(std::back_inserter(key), NUM_VALUES, std::ref(gen));
    this_unit.sign_key.assign((const char*)key.data(), key.size() * VALUE_SIZE);
    mxb_assert(this_unit.sign_key.size() == KEY_BITS);
}

void add_extra_headers(MHD_Response* response)
{
    MHD_add_response_header(response, "X-Frame-Options", "Deny");
    MHD_add_response_header(response, "X-XSS-Protection", "1");
    MHD_add_response_header(response, "Referrer-Policy", "same-origin");
}

void add_content_type_header(MHD_Response* response, const std::string& path)
{
    static const std::unordered_map<std::string, std::string> content_types =
    {
        {".bmp",    "image/bmp"            },
        {".bz",     "application/x-bzip"   },
        {".bz2",    "application/x-bzip2"  },
        {".css",    "text/css"             },
        {".csv",    "text/csv"             },
        {".epub",   "application/epub+zip" },
        {".gz",     "application/gzip"     },
        {".gif",    "image/gif"            },
        {".htm",    "text/html"            },
        {".html",   "text/html"            },
        {".jpeg",   "image/jpeg"           },
        {".jpg",    "image/jpeg"           },
        {".js",     "text/javascript"      },
        {".json",   "application/json"     },
        {".jsonld", "application/ld+json"  },
        {".mjs",    "text/javascript"      },
        {".mp3",    "audio/mpeg"           },
        {".mpeg",   "video/mpeg"           },
        {".otf",    "font/otf"             },
        {".png",    "image/png"            },
        {".pdf",    "application/pdf"      },
        {".php",    "application/php"      },
        {".rar",    "application/vnd.rar"  },
        {".rtf",    "application/rtf"      },
        {".svg",    "image/svg+xml"        },
        {".tar",    "application/x-tar"    },
        {".tif",    "image/tiff"           },
        {".tiff",   "image/tiff"           },
        {".ts",     "video/mp2t"           },
        {".ttf",    "font/ttf"             },
        {".txt",    "text/plain"           },
        {".wav",    "audio/wav"            },
        {".weba",   "audio/webm"           },
        {".webm",   "video/webm"           },
        {".webp",   "image/webp"           },
        {".woff",   "font/woff"            },
        {".woff2",  "font/woff2"           },
        {".xhtml",  "application/xhtml+xml"},
        {".xml",    "application/xml"      },
    };

    auto pos = path.find_last_of('.');
    std::string suffix;

    if (pos != std::string::npos)
    {
        suffix = path.substr(pos);
        auto it = content_types.find(suffix);

        if (it != content_types.end())
        {
            MHD_add_response_header(response, "Content-Type", it->second.c_str());
        }
    }


    if (suffix == ".html")
    {
        // The GUI HTML files should be validated by the browser, this causes MaxScale upgrades to eventually
        // trigger a reloading of the GUI.
        MHD_add_response_header(response, "Cache-Control", "public, no-cache");
    }
    else
    {
        MHD_add_response_header(response, "Cache-Control", "public, max-age=31536000");
    }
}

bool is_auth_endpoint(const HttpRequest& request)
{
    return request.uri_part_count() == 1 && request.uri_segment(0, 1) == "auth";
}
}

Client::Client(MHD_Connection* connection)
    : m_connection(connection)
    , m_state(INIT)
    , m_headers(get_headers(connection))
{
}

std::string Client::get_header(const std::string& key) const
{
    auto k = key;
    std::transform(k.begin(), k.end(), k.begin(), ::tolower);
    auto it = m_headers.find(k);
    return it != m_headers.end() ? it->second : "";
}

size_t Client::request_data_length() const
{
    return atoi(get_header("Content-Length").c_str());
}

void Client::send_basic_auth_error() const
{
    MHD_Response* resp =
        MHD_create_response_from_buffer(sizeof(auth_failure_response) - 1,
                                        auth_failure_response,
                                        MHD_RESPMEM_PERSISTENT);

    MHD_queue_basic_auth_fail_response(m_connection, "maxscale", resp);
    MHD_destroy_response(resp);
}

void Client::send_token_auth_error() const
{
    MHD_Response* response =
        MHD_create_response_from_buffer(sizeof(auth_failure_response) - 1,
                                        auth_failure_response,
                                        MHD_RESPMEM_PERSISTENT);

    MHD_queue_response(m_connection, MHD_HTTP_UNAUTHORIZED, response);
    MHD_destroy_response(response);
}

void Client::send_no_https_error() const
{
    MHD_Response* response =
        MHD_create_response_from_buffer(sizeof(no_https_response) - 1,
                                        no_https_response,
                                        MHD_RESPMEM_PERSISTENT);

    MHD_queue_response(m_connection, MHD_HTTP_UNAUTHORIZED, response);
    MHD_destroy_response(response);
}

void Client::add_cors_headers(MHD_Response* response) const
{
    MHD_add_response_header(response, "Access-Control-Allow-Origin", get_header("Origin").c_str());
    MHD_add_response_header(response, "Vary", "Origin");

    auto request_headers = get_header("Access-Control-Request-Headers");
    auto request_method = get_header("Access-Control-Request-Method");

    if (!request_headers.empty())
    {
        MHD_add_response_header(response, "Access-Control-Allow-Headers", request_headers.c_str());
    }

    if (!request_method.empty())
    {
        MHD_add_response_header(response, "Access-Control-Allow-Methods", request_headers.c_str());
    }
}

bool Client::send_cors_preflight_request(const std::string& verb)
{
    bool rval = false;

    if (verb == MHD_HTTP_METHOD_OPTIONS && !get_header("Origin").empty())
    {
        MHD_Response* response =
            MHD_create_response_from_buffer(0, (void*)"", MHD_RESPMEM_PERSISTENT);

        add_cors_headers(response);

        MHD_queue_response(m_connection, MHD_HTTP_OK, response);
        MHD_destroy_response(response);

        rval = true;
    }

    return rval;
}

bool Client::serve_file(const std::string& url) const
{
    bool rval = false;
    HttpRequest request(m_connection, url, MHD_HTTP_METHOD_GET, nullptr);
    request.fix_api_version();

    std::string path = get_filename(request);

    if (!path.empty())
    {
        MXS_DEBUG("Client requested file: %s", path.c_str());
        MXS_DEBUG("Request:\n%s", request.to_string().c_str());
        std::string data = get_file(path);

        if (!data.empty())
        {
            rval = true;

            MHD_Response* response =
                MHD_create_response_from_buffer(data.size(),
                                                (void*)data.c_str(),
                                                MHD_RESPMEM_MUST_COPY);

            if (this_unit.cors && !get_header("Origin").empty())
            {
                add_cors_headers(response);
            }

            add_content_type_header(response, path);
            add_extra_headers(response);

            if (MHD_queue_response(m_connection, MHD_HTTP_OK, response) == MHD_YES)
            {
                rval = true;
            }

            MHD_destroy_response(response);
        }
        else
        {
            MXS_DEBUG("File not found: %s", path.c_str());
        }
    }

    return rval;
}

void Client::ws_open(const std::string& url)
{
    auto key = get_header("Sec-WebSocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    uint8_t digest[SHA_DIGEST_LENGTH];
    SHA1((uint8_t*)key.data(), key.size(), digest);
    auto encoded = mxs::to_base64(digest, sizeof(digest));

    auto resp = MHD_create_response_for_upgrade(handle_upgrade, this);
    MHD_add_response_header(resp, "Sec-WebSocket-Accept", encoded.c_str());
    MHD_add_response_header(resp, "Upgrade", "websocket");
    MHD_add_response_header(resp, "Connection", "Upgrade");

    // This isn't exactly correct but it'll do for now
    MHD_add_response_header(resp, "Sec-WebSocket-Protocol", get_header("Sec-WebSocket-Protocol").c_str());

    MHD_queue_response(m_connection, MHD_HTTP_SWITCHING_PROTOCOLS, resp);
    MHD_destroy_response(resp);

    // Stash the URL as a request so that we can repeatedly do it
    m_url = url;
}

bool Client::ws_upgraded(int socket)
{
    bool rval = true;
    HttpRequest request(m_connection, m_url, MHD_HTTP_METHOD_GET, nullptr);
    HttpResponse response = resource_handle_request(request);

    if (response.get_code() == MHD_HTTP_OK)
    {
        mxb_assert(response.get_response());

        auto data = mxs::json_dump(response.get_response(), JSON_COMPACT);
        auto cksum = '"' + mxs::checksum<mxs::CRC32Checksum>(data) + '"';

        if (cksum != m_prev_cksum)
        {
            m_prev_cksum = cksum;
            rval = ws_write(socket, data);
        }
    }
    else
    {
        rval = false;
    }

    return rval;
}

void Client::ws_close(int socket)
{
    uint8_t header[2] = {0x81, 0x0};
    write(socket, header, 2);
}

bool Client::ws_write(int socket, const std::string& data)
{
    // First bit is for text type frame, last bit is for final frame
    uint8_t header[10] = {0x81};

    if (data.size() < 126)
    {
        header[1] = data.size();
        write(socket, header, 2);
    }
    else if (data.size() < 65535)
    {
        header[1] = 126;
        header[2] = data.size() >> 8;
        header[3] = data.size();
        write(socket, header, 4);
    }
    else
    {
        header[1] = 127;
        header[2] = data.size() >> 56;
        header[3] = data.size() >> 48;
        header[4] = data.size() >> 40;
        header[5] = data.size() >> 32;
        header[6] = data.size() >> 24;
        header[7] = data.size() >> 16;
        header[8] = data.size() >> 8;
        header[9] = data.size();
        write(socket, header, 10);
    }

    return write(socket, data.data(), data.size()) != -1;
}

int Client::handle(const std::string& url, const std::string& method,
                   const char* upload_data, size_t* upload_data_size)
{
    if (this_unit.cors && send_cors_preflight_request(method))
    {
        return MHD_YES;
    }
    else if (mxs::Config::get().gui && method == MHD_HTTP_METHOD_GET && serve_file(url))
    {
        return MHD_YES;
    }

    Client::state state = get_state();
    int rval = MHD_NO;

    if (state != Client::CLOSED)
    {
        if (state == Client::INIT)
        {
            // First request, do authentication
            if (!auth(m_connection, url.c_str(), method.c_str()))
            {
                rval = MHD_YES;
            }
        }

        if (get_state() == Client::OK)
        {
            // Authentication was successful, start processing the request
            if (state == Client::INIT && request_data_length())
            {
                // The first call doesn't have any data
                rval = MHD_YES;
            }
            else
            {
                rval = process(url, method, upload_data, upload_data_size);
            }
        }
        else if (get_state() == Client::FAILED)
        {
            // Authentication has failed, an error will be sent to the client
            rval = MHD_YES;

            if (*upload_data_size || (state == Client::INIT && request_data_length()))
            {
                // The client is uploading data, discard it so we can send the error
                *upload_data_size = 0;
            }
            else if (state != Client::INIT)
            {
                // No pending upload data, close the connection
                close();
            }
        }
    }

    return rval;
}

int Client::process(string url, string method, const char* upload_data, size_t* upload_size)
{
    json_t* json = NULL;

    if (*upload_size)
    {
        m_data.append(upload_data, *upload_size);
        *upload_size = 0;
        return MHD_YES;
    }

    json_error_t err = {};

    if (m_data.length()
        && (json = json_loadb(m_data.c_str(), m_data.size(), 0, &err)) == NULL)
    {
        string msg = string("{\"errors\": [ { \"detail\": \"Invalid JSON in request: ")
            + err.text + "\" } ] }";
        MHD_Response* response = MHD_create_response_from_buffer(msg.size(),
                                                                 &msg[0],
                                                                 MHD_RESPMEM_MUST_COPY);
        MHD_queue_response(m_connection, MHD_HTTP_BAD_REQUEST, response);
        MHD_destroy_response(response);
        return MHD_YES;
    }

    HttpRequest request(m_connection, url, method, json);
    HttpResponse reply(MHD_HTTP_NOT_FOUND);
    MXS_DEBUG("Request:\n%s", request.to_string().c_str());
    request.fix_api_version();

    if (is_auth_endpoint(request))
    {
        reply = generate_token(request);
    }
    else if (request.get_option("watch") == "true")
    {
        ws_open(url);
        return MHD_YES;
    }
    else
    {
        reply = resource_handle_request(request);
    }

    string data;

    if (json_t* js = reply.get_response())
    {
        int flags = JSON_SORT_KEYS;
        string pretty = request.get_option("pretty");

        if (pretty == "true" || pretty.length() == 0)
        {
            flags |= JSON_INDENT(4);
        }
        else
        {
            flags = JSON_COMPACT;
        }

        data = mxs::json_dump(js, flags);
    }

    MHD_Response* response =
        MHD_create_response_from_buffer(data.size(),
                                        (void*)data.c_str(),
                                        MHD_RESPMEM_MUST_COPY);

    for (const auto& a : reply.get_headers())
    {
        MHD_add_response_header(response, a.first.c_str(), a.second.c_str());
    }

    if (this_unit.cors && !get_header("Origin").empty())
    {
        add_cors_headers(response);
    }

    add_extra_headers(response);

    // Prevent caching without verification
    MHD_add_response_header(response, "Cache-Control", "no-cache");

    for (const auto& c : reply.cookies())
    {
        MHD_add_response_header(response, MHD_HTTP_HEADER_SET_COOKIE, c.c_str());
    }

    int rval = MHD_queue_response(m_connection, reply.get_code(), response);
    MHD_destroy_response(response);

    MXS_DEBUG("Response: HTTP %d", reply.get_code());

    return rval;
}

HttpResponse Client::generate_token(const HttpRequest& request)
{
    int token_age = 28800;
    auto max_age = request.get_option("max-age");

    if (!max_age.empty())
    {
        char* end;
        auto l = strtol(max_age.c_str(), &end, 10);

        if (l > 0 && *end == '\0')
        {
            token_age = l;
        }
    }

    auto now = std::chrono::system_clock::now();
    auto token = jwt::create()
        .set_issuer("maxscale")
        .set_audience(m_user)
        .set_issued_at(now)
        .set_expires_at(now + std::chrono::seconds {token_age})
        .sign(jwt::algorithm::hs256 {this_unit.sign_key});

    if (request.get_option("persist") == "yes")
    {
        // Store the token signature part in a HttpOnly cookie and the claims in a normal one. This allows
        // the token information to be displayed while preventing the actual token from leaking due to a
        // CSRF attack. This also prevents JavaScript from ever accessing the token which completely prevents
        // the token from leaking.
        HttpResponse reply = HttpResponse(MHD_HTTP_NO_CONTENT);

        auto pos = token.find_last_of('.');
        std::string cookie_opts;

        if (this_unit.using_ssl)
        {
            cookie_opts = "; Secure";
        }

        if (!max_age.empty())
        {
            cookie_opts += "; Max-Age=" + std::to_string(token_age);
        }

        reply.add_cookie(TOKEN_BODY + "=" + token.substr(0, pos) + cookie_opts + "; SameSite=Lax");
        reply.add_cookie(TOKEN_SIG + "=" + token.substr(pos) + cookie_opts + "; SameSite=Strict; HttpOnly");

        return reply;
    }
    else
    {
        // Normal auth, return token as JSON
        return HttpResponse(MHD_HTTP_OK, json_pack("{s {s: s}}", "meta", "token", token.c_str()));
    }
}

bool Client::auth_with_token(const std::string& token)
{
    bool rval = false;

    try
    {
        auto d = jwt::decode(token);
        jwt::verify()
        .allow_algorithm(jwt::algorithm::hs256 {this_unit.sign_key})
        .with_issuer("maxscale")
        .verify(d);

        m_user = *d.get_audience().begin();
        rval = true;
    }
    catch (const std::exception& e)
    {
    }

    return rval;
}

bool Client::auth(MHD_Connection* connection, const char* url, const char* method)
{
    bool rval = true;

    if (mxs::Config::get().admin_auth)
    {
        HttpRequest request(m_connection, url, MHD_HTTP_METHOD_GET, nullptr);
        request.fix_api_version();
        bool done = false;

        if (!is_auth_endpoint(request))
        {
            // Not the /auth endpoint, use the cookie or Bearer token
            auto cookie_token = get_cookie_token(m_connection);
            auto token = get_header(MHD_HTTP_HEADER_AUTHORIZATION);

            if (!cookie_token.empty())
            {
                done = true;

                if (!auth_with_token(cookie_token))
                {
                    send_token_auth_error();
                    rval = false;
                }
            }
            else if (token.substr(0, 7) == "Bearer ")
            {
                done = true;

                if (!auth_with_token(token.substr(7)))
                {
                    send_token_auth_error();
                    rval = false;
                }
            }
        }
        else if (!this_unit.using_ssl && mxs::Config::get().secure_gui)
        {
            // The /auth endpoint must be used with an encrypted connection
            done = true;
            rval = false;
            send_no_https_error();
        }

        if (!done)
        {
            rval = false;
            char* pw = NULL;
            char* user = MHD_basic_auth_get_username_password(connection, &pw);

            if (!user || !pw || !admin_verify_inet_user(user, pw))
            {
                if (mxs::Config::get().admin_log_auth_failures.get())
                {
                    MXS_WARNING("Authentication failed for '%s', %s. Request: %s %s",
                                user ? user : "",
                                pw ? "using password" : "no password",
                                method, url);
                }
            }
            else if (authorize_user(user, method, url))
            {
                MXS_INFO("Accept authentication from '%s', %s. Request: %s",
                         user ? user : "",
                         pw ? "using password" : "no password",
                         url);

                // Store the username for later in case we are generating a token
                m_user = user ? user : "";
                rval = true;
            }
            MXS_FREE(user);
            MXS_FREE(pw);

            if (!rval)
            {
                if (is_auth_endpoint(request))
                {
                    send_token_auth_error();
                }
                else
                {
                    send_basic_auth_error();
                }
            }
        }
    }

    m_state = rval ? Client::OK : Client::FAILED;

    return rval;
}

bool mxs_admin_init()
{
    struct sockaddr_storage addr;
    const auto& config = mxs::Config::get();

    init_jwt_sign_key();

    if (!load_ssl_certificates())
    {
        MXS_ERROR("Failed to load REST API TLS certificates.");
    }
    else if (host_to_sockaddr(config.admin_host.c_str(), config.admin_port, &addr))
    {
        int options = MHD_USE_EPOLL_INTERNALLY_LINUX_ONLY | MHD_USE_DEBUG | MHD_ALLOW_UPGRADE;

        if (addr.ss_family == AF_INET6)
        {
            options |= MHD_USE_DUAL_STACK;
        }

        if (this_unit.using_ssl)
        {
            options |= MHD_USE_SSL;
            MXS_NOTICE("The REST API will be encrypted, all requests must use HTTPS.");
        }
        else if (mxs::Config::get().gui && mxs::Config::get().secure_gui)
        {
            MXS_WARNING("The MaxScale GUI is enabled but encryption for the REST API is not enabled, "
                        "the GUI will not be enabled. Configure `admin_ssl_key` and `admin_ssl_cert` "
                        "to enable HTTPS or add `admin_secure_gui=false` to allow use of the GUI without encryption.");
        }

        // The port argument is ignored and the port in the struct sockaddr is used instead
        this_unit.daemon = MHD_start_daemon(options, 0, NULL, NULL, handle_client, NULL,
                                            MHD_OPTION_EXTERNAL_LOGGER, admin_log_error, NULL,
                                            MHD_OPTION_NOTIFY_COMPLETED, close_client, NULL,
                                            MHD_OPTION_SOCK_ADDR, &addr,
                                            !this_unit.using_ssl ? MHD_OPTION_END :
                                            MHD_OPTION_HTTPS_MEM_KEY, this_unit.ssl_key.c_str(),
                                            MHD_OPTION_HTTPS_MEM_CERT, this_unit.ssl_cert.c_str(),
                                            this_unit.ssl_ca.empty() ? MHD_OPTION_END :
                                            MHD_OPTION_HTTPS_MEM_TRUST, this_unit.ssl_cert.c_str(),
                                            MHD_OPTION_END);
    }

    // Silence all other errors to prevent malformed requests from flooding the log
    this_unit.log_daemon_errors = false;

    return this_unit.daemon != NULL;
}

void mxs_admin_shutdown()
{
    MHD_stop_daemon(this_unit.daemon);
    MXS_NOTICE("Stopped MaxScale REST API");
}

bool mxs_admin_https_enabled()
{
    return this_unit.using_ssl;
}

bool mxs_admin_enable_cors()
{
    return this_unit.cors = true;
}
