
/*
 * Copyright (C) Roman Arutyunyan
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <nginx.h>
#include "ngx_rtmp_proxy_protocol.h"


static void ngx_rtmp_proxy_protocol_recv(ngx_event_t *rev);


void
ngx_rtmp_proxy_protocol(ngx_rtmp_session_t *s)
{
    ngx_event_t       *rev;
    ngx_connection_t  *c;

    c = s->connection;
    rev = c->read;
    rev->handler =  ngx_rtmp_proxy_protocol_recv;

    ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "proxy_protocol: start");

    if (rev->ready) {
        /* the deferred accept(), rtsig, aio, iocp */

        if (ngx_use_accept_mutex) {
            ngx_post_event(rev, &ngx_posted_events);
            return;
        }

        rev->handler(rev);
        return;
    }

    ngx_add_timer(rev, s->timeout);

    if (ngx_handle_read_event(rev, 0) != NGX_OK) {
        ngx_rtmp_finalize_session(s);
        return;
    }
}


static void
ngx_rtmp_proxy_protocol_recv(ngx_event_t *rev)
{
    u_char               buf[NGX_PROXY_PROTOCOL_MAX_HEADER], *p, *text;
    size_t               len, size;
    ssize_t              n;
    ngx_err_t            err;
    ngx_addr_t           addr;
    ngx_connection_t    *c;
    ngx_rtmp_session_t  *s;

    c = rev->data;
    s = c->data;

    if (c->destroyed) {
        return;
    }

    if (rev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT,
                "proxy_protocol: recv: client timed out");
        c->timedout = 1;
        ngx_rtmp_finalize_session(s);
        return;
    }

    if (rev->timer_set) {
        ngx_del_timer(rev);
    }

    n = recv(c->fd, (char *) buf, sizeof(buf), MSG_PEEK);

    err = ngx_socket_errno;

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, c->log, 0, "recv(): %d", n);

    if (n == -1) {

        if (err == NGX_EAGAIN) {
            ngx_add_timer(rev, s->timeout);

            if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
                ngx_rtmp_finalize_session(s);
            }

            return;
        }

        ngx_rtmp_finalize_session(s);

        return;
    }

    ngx_memzero(&addr, sizeof(ngx_addr_t));

    p = ngx_proxy_protocol_read(c, buf, buf + n);
    if (p) {
        size = p - buf;
        if (c->recv(c, buf, size) != (ssize_t) size) {
            goto failed;
        }
        if (ngx_parse_addr(c->pool, &addr, c->proxy_protocol->src_addr.data,
                           c->proxy_protocol->src_addr.len) != NGX_OK) {
            goto failed;
        }

        ngx_inet_set_port(addr.sockaddr, c->proxy_protocol->src_port);

        text = ngx_pnalloc(c->pool, NGX_SOCKADDR_STRLEN);
        len = ngx_sock_ntop(addr.sockaddr, addr.socklen, text,
                            NGX_SOCKADDR_STRLEN, 0);
        if (len == 0) {
            goto failed;
        }

        if (text == NULL) {
            goto failed;
        }

        c->sockaddr = addr.sockaddr;
        c->socklen = addr.socklen;
        c->addr_text.data = text;
        c->addr_text.len = len;

        ngx_rtmp_handshake(s);
        return;
    }

failed:
    ngx_rtmp_finalize_session(s);
}
