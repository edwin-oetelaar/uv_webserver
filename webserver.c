#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include "libuv/include/uv.h"
#include "http-parser/http_parser.h"


#define RESPONSE \
  "HTTP/1.1 200 OK\r\n" \
  "Content-Type: text/plain\r\n" \
  "Content-Length: 12\r\n" \
  "\r\n" \
  "hello world\n"

static uv_buf_t resbuf;
static uv_tcp_t server;
static http_parser_settings settings;

typedef struct {
    uv_tcp_t tcp;
    http_parser parser;
    uv_write_t write_req;
} client_t;


void on_close(uv_handle_t *handle) {
    free(handle);
}


void on_alloc(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    buf->base = malloc(suggested_size);
    buf->len = suggested_size;
}


static void on_read(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {

    client_t *client = stream->data;
    size_t parsed;

    if (nread >= 0) {
        /* parse http */

        parsed = http_parser_execute(&client->parser,
                                     &settings,
                                     buf->base,
                                     (size_t) nread);

        if (parsed < (size_t) nread) {
            printf("parse error");
            uv_close((uv_handle_t *) stream, on_close);
        }

    } else {
        // uv_err_t err = uv_last_error(handle->loop);

        if (nread == UV_EOF) {
            /* do nothing */
        } else {
            fprintf(stderr, "read: %s\n", uv_strerror(nread));
        }

        uv_close((uv_handle_t *) stream, on_close);
    }

    free(buf->base);
}


void on_connected(uv_stream_t *s, int status) {
    assert(s == (uv_stream_t *) &server);
    assert(status == 0);


    client_t *client = malloc(sizeof(client_t));


    int r = uv_tcp_init(s->loop, &client->tcp);
    r = uv_accept((uv_stream_t *) &server, (uv_stream_t *) &client->tcp);

    if (r != 0) {

        fprintf(stderr, "accept: %s\n", uv_strerror(r));
        return;
    }

    client->tcp.data = client;
    client->parser.data = client;

    http_parser_init(&client->parser, HTTP_REQUEST);

    uv_read_start((uv_stream_t *) &client->tcp, on_alloc, on_read);
}

static void write_cb(uv_write_t *req, int status) {
    if (status < 0)
        fprintf(stderr, "write error\n");

    uv_close((uv_handle_t *) req->data, on_close);
}


int on_headers_complete(http_parser *parser) {
    client_t *client = parser->data;

    client->write_req.data = client;
    uv_write(&client->write_req, (uv_stream_t *) &client->tcp, &resbuf, 1, write_cb);

    return 1;
}


int main() {

    uv_loop_t *loop = uv_default_loop();

    resbuf.base = RESPONSE;
    resbuf.len = sizeof(RESPONSE);

    settings.on_headers_complete = on_headers_complete;

    uv_tcp_init(loop, &server);
    struct sockaddr_in addr;

    int r;
    r = uv_ip4_addr("0.0.0.0", 8001, &addr);

    if (r < 0)
        fprintf(stderr, "ip4_addr error %d\n", r);

    r = uv_tcp_bind(&server, (const struct sockaddr *) &addr, 0);

    if (r < 0) {
        fprintf(stderr, "bind: %s\n", uv_strerror(r));
        // return -1;
    }

    r = uv_listen((uv_stream_t *) &server, 128, on_connected);

    if (r < 0) {
        fprintf(stderr, "listen: %s\n", uv_strerror(r));
        return -1;
    }

    return uv_run(loop, UV_RUN_DEFAULT);
}
