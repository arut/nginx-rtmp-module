/*
 * Copyright (c) 2012 Roman Arutyunyan
 */


#ifndef _NGX_RTMP_H_INCLUDED_
#define _NGX_RTMP_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_connect.h>


#define NGX_RTMP_HANDSHAKE_SIZE    1536

#define NGX_RTMP_DEFAULT_CHUNK_SIZE 128

#define NGX_LOG_DEBUG_RTMP NGX_LOG_DEBUG_CORE


typedef struct {
    void                  **main_conf;
    void                  **srv_conf;
} ngx_rtmp_conf_ctx_t;


typedef struct {
    u_char                  sockaddr[NGX_SOCKADDRLEN];
    socklen_t               socklen;

    /* server ctx */
    ngx_rtmp_conf_ctx_t    *ctx;

    unsigned                bind:1;
    unsigned                wildcard:1;
#if (NGX_HAVE_INET6 && defined IPV6_V6ONLY)
    unsigned                ipv6only:2;
#endif
    unsigned                so_keepalive:2;
#if (NGX_HAVE_KEEPALIVE_TUNABLE)
    int                     tcp_keepidle;
    int                     tcp_keepintvl;
    int                     tcp_keepcnt;
#endif
} ngx_rtmp_listen_t;


typedef struct {
    ngx_rtmp_conf_ctx_t    *ctx;
    ngx_str_t               addr_text;
} ngx_rtmp_addr_conf_t;

typedef struct {
    in_addr_t               addr;
    ngx_rtmp_addr_conf_t    conf;
} ngx_rtmp_in_addr_t;


#if (NGX_HAVE_INET6)

typedef struct {
    struct in6_addr         addr6;
    ngx_rtmp_addr_conf_t    conf;
} ngx_rtmp_in6_addr_t;

#endif


typedef struct {
    void                   *addrs;
    ngx_uint_t              naddrs;
} ngx_rtmp_port_t;


typedef struct {
    int                     family;
    in_port_t               port;
    ngx_array_t             addrs;       /* array of ngx_rtmp_conf_addr_t */
} ngx_rtmp_conf_port_t;


typedef struct {
    struct sockaddr        *sockaddr;
    socklen_t               socklen;

    ngx_rtmp_conf_ctx_t    *ctx;

    unsigned                bind:1;
    unsigned                wildcard:1;
#if (NGX_HAVE_INET6 && defined IPV6_V6ONLY)
    unsigned                ipv6only:2;
#endif
    unsigned                so_keepalive:2;
#if (NGX_HAVE_KEEPALIVE_TUNABLE)
    int                     tcp_keepidle;
    int                     tcp_keepintvl;
    int                     tcp_keepcnt;
#endif
} ngx_rtmp_conf_addr_t;


typedef struct {
    ngx_array_t             servers;     /* ngx_rtmp_core_srv_conf_t */
    ngx_array_t             listen;      /* ngx_rtmp_listen_t */
} ngx_rtmp_core_main_conf_t;


typedef struct {
    uint8_t                 channel;
    uint8_t                 type;
    uint8_t                 hsize;
    uint8_t                 size;
    uint32_t                timer;
    uint32_t                stream;
} ngx_rtmp_packet_hdr_t;


#define NGX_RTMP_PUBLISHER   0x01
#define NGX_RTMP_SUBSCRIBER  0x02


struct ngx_rtmp_session_s {
    uint32_t                signature;         /* "RTMP" */

    ngx_connection_t       *connection;

    void                  **ctx;
    void                  **main_conf;
    void                  **srv_conf;

    ngx_str_t              *addr_text;

    ngx_uint_t              chunk_size;
    ngx_chain_t            *free;

    /* FIXME: there should probably be a better way
     * to store handshake buffers & states
     */

    /* handshake */
    ngx_buf_t               buf;
    ngx_uint_t              hs_stage;

    /* input */
    ngx_chain_t            *in;
    ngx_rtmp_packet_hdr_t   in_hdr;

    /* output */
    ngx_chain_t            *out;
    ngx_rtmp_packet_hdr_t   out_hdr;

    /* broadcast */
    ngx_str_t               name;
    struct ngx_rtmp_session_s
                            *next;
    ngx_uint_t              flags;
};

typedef struct ngx_rtmp_session_s ngx_rtmp_session_t;


#define NGX_RTMP_SESSION_HASH_SIZE 16384


typedef struct {
    ngx_msec_t              timeout;
    ngx_flag_t              so_keepalive;
    ngx_int_t               buffers;
    ngx_msec_t              resolver_timeout;
    ngx_resolver_t         *resolver;
    ngx_rtmp_conf_ctx_t    *ctx;
    ngx_rtmp_session_t    **sessions;  /* session hash map: name->session */
} ngx_rtmp_core_srv_conf_t;


typedef struct {
    ngx_str_t              *client;
    ngx_rtmp_session_t     *session;
} ngx_rtmp_log_ctx_t;


typedef struct {
    void                 *(*create_main_conf)(ngx_conf_t *cf);
    char                 *(*init_main_conf)(ngx_conf_t *cf, void *conf);

    void                 *(*create_srv_conf)(ngx_conf_t *cf);
    char                 *(*merge_srv_conf)(ngx_conf_t *cf, void *prev,
                                      void *conf);
} ngx_rtmp_module_t;


/* RTMP packet types*/
#define NGX_RTMP_PACKET_CHUNK_SIZE  0x01
#define NGX_RTMP_PACKET_BYTES_READ  0x03
#define NGX_RTMP_PACKET_PING        0x04
#define NGX_RTMP_PACKET_SERVER_BW   0x05
#define NGX_RTMP_PACKET_CLIENT_BW   0x06
#define NGX_RTMP_PACKET_AUDIO       0x08
#define NGX_RTMP_PACKET_VIDEO       0x09
#define NGX_RTMP_PACKET_FLEX        0x0f
#define NGX_RTMP_PACKET_FLEX_SO     0x10
#define NGX_RTMP_PACKET_FLEX_MSG    0x11
#define NGX_RTMP_PACKET_NOTIFY      0x12
#define NGX_RTMP_PACKET_SO          0x13
#define NGX_RTMP_PACKET_INVOKE      0x14

/* RMTP ping types */
#define NGX_RMTP_PING_CLEAR_STEAM   0
#define NGX_RMTP_PING_CLEAR_BUFFER  1
#define NGX_RMTP_PING_CLIENT_TIME   3
#define NGX_RMTP_PING_RESET_STREAM  4
#define NGX_RMTP_PING_PING          6
#define NGX_RMTP_PING_PONG          7


#define NGX_RTMP_MODULE         0x504D5452     /* "RTMP" */

#define NGX_RTMP_MAIN_CONF      0x02000000
#define NGX_RTMP_SRV_CONF       0x04000000


#define NGX_RTMP_MAIN_CONF_OFFSET  offsetof(ngx_rtmp_conf_ctx_t, main_conf)
#define NGX_RTMP_SRV_CONF_OFFSET   offsetof(ngx_rtmp_conf_ctx_t, srv_conf)


#define ngx_rtmp_get_module_ctx(s, module)     (s)->ctx[module.ctx_index]
#define ngx_rtmp_set_ctx(s, c, module)         s->ctx[module.ctx_index] = c;
#define ngx_rtmp_delete_ctx(s, module)         s->ctx[module.ctx_index] = NULL;


#define ngx_rtmp_get_module_main_conf(s, module)                             \
    (s)->main_conf[module.ctx_index]
#define ngx_rtmp_get_module_srv_conf(s, module)  (s)->srv_conf[module.ctx_index]

#define ngx_rtmp_conf_get_module_main_conf(cf, module)                       \
    ((ngx_rtmp_conf_ctx_t *) cf->ctx)->main_conf[module.ctx_index]
#define ngx_rtmp_conf_get_module_srv_conf(cf, module)                        \
    ((ngx_rtmp_conf_ctx_t *) cf->ctx)->srv_conf[module.ctx_index]

void ngx_rtmp_init_connection(ngx_connection_t *c);    
void ngx_rtmp_close_session(ngx_rtmp_session_t *s);
u_char * ngx_rtmp_log_error(ngx_log_t *log, u_char *buf, size_t len);

void ngx_rtmp_set_chunk_size(ngx_rtmp_session_t *s, uint32_t chunk_size);
void ngx_rtmp_set_bytes_read(ngx_rtmp_session_t *s, uint32_t bytes_read);
void ngx_rtmp_set_client_buffer_time(ngx_rtmp_session_t *s, int16_t msec);
void ngx_rtmp_clear_buffer(ngx_rtmp_session_t *s);
void ngx_rtmp_set_ping_time(ngx_rtmp_session_t *s, int16_t msec);
void ngx_rtmp_set_server_bw(ngx_rtmp_session_t *s, uint32_t bw, 
    uint8_t limit_type);
void ngx_rtmp_set_client_bw(ngx_rtmp_session_t *s, uint32_t bw, 
    uint8_t limit_type);

void ngx_rtmp_join(ngx_rtmp_session_t *s, ngx_str_t *name, ngx_uint_t flags);
void ngx_rtmp_leave(ngx_rtmp_session_t *s);

ngx_int_t ngx_rtmp_receive_packet(ngx_rtmp_session_t *s,
    ngx_rtmp_packet_hdr_t *h, ngx_chain_t *b);

void ngx_rtmp_send_packet(ngx_rtmp_session_t *s, 
    ngx_rtmp_packet_hdr_t *h, ngx_chain_t *b);


/* NetConnection methods */
ngx_int_t ngx_rtmp_connect(ngx_rtmp_session_t *s, ngx_chain_t **l);
ngx_int_t ngx_rtmp_call(ngx_rtmp_session_t *s, ngx_chain_t **l);
ngx_int_t ngx_rtmp_close(ngx_rtmp_session_t *s, ngx_chain_t **l);
ngx_int_t ngx_rtmp_createstream(ngx_rtmp_session_t *s, ngx_chain_t **l);


/* NetStream methods */
ngx_int_t ngx_rtmp_play(ngx_rtmp_session_t *s, ngx_chain_t **l);
ngx_int_t ngx_rtmp_play2(ngx_rtmp_session_t *s, ngx_chain_t **l);
ngx_int_t ngx_rtmp_deletestream(ngx_rtmp_session_t *s, ngx_chain_t **l);
ngx_int_t ngx_rtmp_closestream(ngx_rtmp_session_t *s, ngx_chain_t **l);
ngx_int_t ngx_rtmp_receiveaudio(ngx_rtmp_session_t *s, ngx_chain_t **l);
ngx_int_t ngx_rtmp_receivevideo(ngx_rtmp_session_t *s, ngx_chain_t **l);
ngx_int_t ngx_rtmp_publish(ngx_rtmp_session_t *s, ngx_chain_t **l);
ngx_int_t ngx_rtmp_seek(ngx_rtmp_session_t *s, ngx_chain_t **l);
ngx_int_t ngx_rtmp_pause(ngx_rtmp_session_t *s, ngx_chain_t **l);


extern ngx_uint_t    ngx_rtmp_max_module;
extern ngx_module_t  ngx_rtmp_core_module;


#endif /* _NGX_RTMP_H_INCLUDED_ */
