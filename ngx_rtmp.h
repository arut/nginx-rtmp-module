/*
 * Copyright (c) 2012 Roman Arutyunyan
 */


#ifndef _NGX_RTMP_H_INCLUDED_
#define _NGX_RTMP_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_connect.h>

#include "ngx_rtmp_amf0.h"


typedef struct {
    void                  **main_conf;
    void                  **srv_conf;
    void                  **app_conf;
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


#define NGX_RTMP_VERSION                3

#define NGX_LOG_DEBUG_RTMP              NGX_LOG_DEBUG_CORE

#define NGX_RTMP_HANDSHAKE_SIZE         1536

#define NGX_RTMP_DEFAULT_CHUNK_SIZE     128


/* RTMP handshake stages */
#define NGX_RTMP_HS_READ_DATA           0
#define NGX_RTMP_HS_WRITE_DATA          1
#define NGX_RTMP_HS_WRITE_ECHO          2
#define NGX_RTMP_HS_READ_ECHO           3


/* RTMP message types */
#define NGX_RTMP_MSG_CHUNK_SIZE         1
#define NGX_RTMP_MSG_ABORT              2
#define NGX_RTMP_MSG_ACK                3
#define NGX_RTMP_MSG_USER               4
#define NGX_RTMP_MSG_ACK_SIZE           5
#define NGX_RTMP_MSG_BANDWIDTH          6
#define NGX_RTMP_MSG_EDGE               7
#define NGX_RTMP_MSG_AUDIO              8
#define NGX_RTMP_MSG_VIDEO              9
#define NGX_RTMP_MSG_AMF3_META          15
#define NGX_RTMP_MSG_AMF3_SHARED        16
#define NGX_RTMP_MSG_AMF3_CMD           17
#define NGX_RTMP_MSG_AMF0_META          18
#define NGX_RTMP_MSG_AMF0_SHARED        19
#define NGX_RTMP_MSG_AMF0_CMD           20
#define NGX_RTMP_MSG_AGGREGATE          22
#define NGX_RTMP_MSG_MAX                22

#define NGX_RTMP_CONNECT                NGX_RTMP_MSG_MAX + 1
#define NGX_RTMP_DISCONNECT             NGX_RTMP_MSG_MAX + 2
#define NGX_RTMP_MAX_EVENT              NGX_RTMP_MSG_MAX + 3


/* RMTP control message types */
#define NGX_RTMP_USER_STREAM_BEGIN      0
#define NGX_RTMP_USER_STREAM_EOF        1
#define NGX_RTMP_USER_STREAM_DRY        2
#define NGX_RTMP_USER_SET_BUFLEN        3
#define NGX_RTMP_USER_RECORDED          4
#define NGX_RTMP_USER_PING_REQUEST      6
#define NGX_RTMP_USER_PING_RESPONSE     7
#define NGX_RTMP_USER_UNKNOWN           8


/* Chunk header:
 *   max 3  basic header
 * + max 11 message header
 * + max 4  extended header (timestamp) */
#define NGX_RTMP_MAX_CHUNK_HEADER       18


typedef struct {
    uint32_t                csid;       /* chunk stream id */
    uint32_t                timestamp;  /* timestamp (delta) */
    uint32_t                mlen;       /* message length */
    uint8_t                 type;       /* message type id */
    uint32_t                msid;       /* message stream id */
} ngx_rtmp_header_t;


typedef struct {
    ngx_rtmp_header_t       hdr;
    uint32_t                len;        /* current fragment length */
    ngx_chain_t            *in;
} ngx_rtmp_stream_t;


typedef struct {
    uint32_t                signature;  /* "RTMP" */ /* <-- FIXME wtf */

    ngx_connection_t       *connection;

    void                  **ctx;
    void                  **main_conf;
    void                  **srv_conf;
    void                  **app_conf;

    ngx_str_t              *addr_text;
    int                     connected;

    /* connection parameters */
    ngx_str_t               app;
    ngx_str_t               flashver;
    ngx_str_t               swf_url;
    ngx_str_t               tc_url;
    uint32_t                acodecs;
    uint32_t                vcodecs;
    ngx_str_t               page_url;

    /* TODO: allocate this bufs from shared pool */
    ngx_buf_t               hs_in_buf;
    ngx_buf_t               hs_out_buf;
    ngx_uint_t              hs_stage;

    /* connection timestamps */
    uint32_t                epoch;
    uint32_t                peer_epoch;

    /* input stream 0 (reserved by RTMP spec)
     * is used as free chain link */

    ngx_rtmp_stream_t      *in_streams;
    uint32_t                in_csid;
    ngx_uint_t              in_chunk_size;
    ngx_pool_t             *in_pool;
    uint32_t                in_bytes;
    uint32_t                in_last_ack;

    ngx_chain_t            *out;
    ngx_chain_t            *out_free_chains;
} ngx_rtmp_session_t;


/* handler result code:
 *  NGX_ERROR - error
 *  NGX_OK    - success, may continue
 *  NGX_DONE  - success, input parsed, reply sent; need no
 *      more calls on this event */
typedef ngx_int_t (*ngx_rtmp_handler_pt)(ngx_rtmp_session_t *s,
        ngx_rtmp_header_t *h, ngx_chain_t *in);


typedef struct {
    ngx_str_t               name;
    ngx_rtmp_handler_pt     handler;
} ngx_rtmp_amf0_handler_t;


typedef struct {
    ngx_array_t             servers;    /* ngx_rtmp_core_srv_conf_t */
    ngx_array_t             listen;     /* ngx_rtmp_listen_t */

    ngx_array_t             events[NGX_RTMP_MAX_EVENT];

    ngx_hash_t              amf0_hash;
    ngx_array_t             amf0_arrays;
    ngx_array_t             amf0;
} ngx_rtmp_core_main_conf_t;


typedef struct ngx_rtmp_core_srv_conf_s {
    ngx_array_t             applications; /* ngx_rtmp_core_app_conf_t */

    ngx_msec_t              timeout;
    ngx_flag_t              so_keepalive;
    ngx_int_t               max_streams;

    ngx_uint_t              ack_window;
    
    ngx_int_t               chunk_size;
    ngx_pool_t             *pool;
    ngx_chain_t            *free;
    ngx_chain_t            *free_chains;
    size_t                  max_buf;
    size_t                  max_message;
    ngx_flag_t              play_time_fix;
    ngx_flag_t              publish_time_fix;

    ngx_rtmp_conf_ctx_t    *ctx;
} ngx_rtmp_core_srv_conf_t;


typedef struct {
    ngx_str_t               name;
    void                  **app_conf;
} ngx_rtmp_core_app_conf_t;


typedef struct {
    ngx_str_t              *client;
    ngx_rtmp_session_t     *session;
} ngx_rtmp_log_ctx_t;


typedef struct {
    ngx_int_t             (*preconfiguration)(ngx_conf_t *cf);
    ngx_int_t             (*postconfiguration)(ngx_conf_t *cf);

    void                 *(*create_main_conf)(ngx_conf_t *cf);
    char                 *(*init_main_conf)(ngx_conf_t *cf, void *conf);

    void                 *(*create_srv_conf)(ngx_conf_t *cf);
    char                 *(*merge_srv_conf)(ngx_conf_t *cf, void *prev, 
                                    void *conf);

    void                 *(*create_app_conf)(ngx_conf_t *cf);
    char                 *(*merge_app_conf)(ngx_conf_t *cf, void *prev,
                                    void *conf);
} ngx_rtmp_module_t;

#define NGX_RTMP_MODULE                 0x504D5452     /* "RTMP" */

#define NGX_RTMP_MAIN_CONF              0x02000000
#define NGX_RTMP_SRV_CONF               0x04000000
#define NGX_RTMP_APP_CONF               0x08000000


#define NGX_RTMP_MAIN_CONF_OFFSET  offsetof(ngx_rtmp_conf_ctx_t, main_conf)
#define NGX_RTMP_SRV_CONF_OFFSET   offsetof(ngx_rtmp_conf_ctx_t, srv_conf)
#define NGX_RTMP_APP_CONF_OFFSET   offsetof(ngx_rtmp_conf_ctx_t, app_conf)


#define ngx_rtmp_get_module_ctx(s, module)     (s)->ctx[module.ctx_index]
#define ngx_rtmp_set_ctx(s, c, module)         s->ctx[module.ctx_index] = c;
#define ngx_rtmp_delete_ctx(s, module)         s->ctx[module.ctx_index] = NULL;


#define ngx_rtmp_get_module_main_conf(s, module)                             \
    (s)->main_conf[module.ctx_index]
#define ngx_rtmp_get_module_srv_conf(s, module)  (s)->srv_conf[module.ctx_index]
#define ngx_rtmp_get_module_app_conf(s, module)  ((s)->app_conf ? \
    (s)->app_conf[module.ctx_index] : NULL)

#define ngx_rtmp_conf_get_module_main_conf(cf, module)                       \
    ((ngx_rtmp_conf_ctx_t *) cf->ctx)->main_conf[module.ctx_index]
#define ngx_rtmp_conf_get_module_srv_conf(cf, module)                        \
    ((ngx_rtmp_conf_ctx_t *) cf->ctx)->srv_conf[module.ctx_index]


#ifdef NGX_DEBUG
char* ngx_rtmp_message_type(uint8_t type);
char* ngx_rtmp_user_message_type(uint16_t evt);
#endif

void ngx_rtmp_init_connection(ngx_connection_t *c);    
void ngx_rtmp_close_connection(ngx_connection_t *c);
u_char * ngx_rtmp_log_error(ngx_log_t *log, u_char *buf, size_t len);
uint32_t ngx_rtmp_get_timestamp();


/* Bit reverse: we need big-endians in many places  */
void * ngx_rtmp_rmemcpy(void *dst, void* src, size_t n);

#define ngx_rtmp_rcpymem(dst, src, n) \
    (((u_char*)ngx_rtmp_rmemcpy(dst, src, n)) + (n))


/* Receiving messages */
ngx_int_t ngx_rtmp_protocol_message_handler(ngx_rtmp_session_t *s,
        ngx_rtmp_header_t *h, ngx_chain_t *in);
ngx_int_t ngx_rtmp_user_message_handler(ngx_rtmp_session_t *s,
        ngx_rtmp_header_t *h, ngx_chain_t *in);
ngx_int_t ngx_rtmp_amf0_message_handler(ngx_rtmp_session_t *s,
        ngx_rtmp_header_t *h, ngx_chain_t *in);


/* Shared output buffers */
ngx_chain_t * ngx_rtmp_alloc_shared_buf(ngx_rtmp_core_srv_conf_t *cscf);
void ngx_rtmp_free_shared_bufs(ngx_rtmp_core_srv_conf_t *cscf, 
        ngx_chain_t *out);
void ngx_rtmp_free_shared_buf(ngx_rtmp_core_srv_conf_t *cscf,
        ngx_buf_t *b);
void ngx_rtmp_acquire_shared_buf(ngx_buf_t *b);
ngx_chain_t * ngx_rtmp_append_shared_bufs(ngx_rtmp_core_srv_conf_t *cscf, 
        ngx_chain_t *head, ngx_chain_t *in);


/* Sending messages */
void ngx_rtmp_prepare_message(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h, 
        ngx_rtmp_header_t *lh, ngx_chain_t *out);
ngx_int_t ngx_rtmp_send_message(ngx_rtmp_session_t *s, ngx_chain_t *out,
        ngx_uint_t priority);

/* Note on priorities:
 * the bigger value the lower the priority.
 * priority=0 is the highest */

#define NGX_RTMP_LIMIT_SOFT         0
#define NGX_RTMP_LIMIT_HARD         1
#define NGX_RTMP_LIMIT_DYNAMIC      2

/* Protocol control messages */
ngx_int_t ngx_rtmp_send_chunk_size(ngx_rtmp_session_t *s, 
        uint32_t chunk_size);
ngx_int_t ngx_rtmp_send_abort(ngx_rtmp_session_t *s, 
        uint32_t csid);
ngx_int_t ngx_rtmp_send_ack(ngx_rtmp_session_t *s, 
        uint32_t seq);
ngx_int_t ngx_rtmp_send_ack_size(ngx_rtmp_session_t *s, 
        uint32_t ack_size);
ngx_int_t ngx_rtmp_send_bandwidth(ngx_rtmp_session_t *s, 
        uint32_t ack_size, uint8_t limit_type);

/* User control messages */
ngx_int_t ngx_rtmp_send_user_stream_begin(ngx_rtmp_session_t *s, 
        uint32_t msid);
ngx_int_t ngx_rtmp_send_user_stream_eof(ngx_rtmp_session_t *s, 
        uint32_t msid);
ngx_int_t ngx_rtmp_send_user_stream_dry(ngx_rtmp_session_t *s, 
        uint32_t msid);
ngx_int_t ngx_rtmp_send_user_set_buflen(ngx_rtmp_session_t *s, 
        uint32_t msid, uint32_t buflen_msec);
ngx_int_t ngx_rtmp_send_user_recorded(ngx_rtmp_session_t *s, 
        uint32_t msid);
ngx_int_t ngx_rtmp_send_user_ping_request(ngx_rtmp_session_t *s,
        uint32_t timestamp);
ngx_int_t ngx_rtmp_send_user_ping_response(ngx_rtmp_session_t *s, 
        uint32_t timestamp);
ngx_int_t ngx_rtmp_send_user_unknown(ngx_rtmp_session_t *s, 
        uint32_t timestamp);

/* AMF0 sender/receiver */
ngx_int_t ngx_rtmp_send_amf0(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
        ngx_rtmp_amf0_elt_t *elts, size_t nelts);
ngx_int_t ngx_rtmp_receive_amf0(ngx_rtmp_session_t *s, ngx_chain_t *in, 
        ngx_rtmp_amf0_elt_t *elts, size_t nelts);


extern ngx_uint_t    ngx_rtmp_max_module;
extern ngx_module_t  ngx_rtmp_core_module;


#endif /* _NGX_RTMP_H_INCLUDED_ */
