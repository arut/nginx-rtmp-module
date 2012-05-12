/*
 * Copyright (c) 2012 Roman Arutyunyan
 */


#include <ngx_http.h>

#include "ngx_rtmp.h"
#include "ngx_rtmp_live_module.h"
#include "ngx_rtmp_codecs.h"


static ngx_int_t ngx_rtmp_stat_postconfiguration(ngx_conf_t *cf);
static void * ngx_rtmp_stat_create_loc_conf(ngx_conf_t *cf);
static char * ngx_rtmp_stat_merge_loc_conf(ngx_conf_t *cf, 
        void *parent, void *child);


#define NGX_RTMP_STAT_ALL           0xff
#define NGX_RTMP_STAT_GLOBAL        0x01
#define NGX_RTMP_STAT_LIVE          0x02
#define NGX_RTMP_STAT_CLIENTS       0x04

/*
 * global: stat-{bufs-{total,free,used}, total bytes in/out, bw in/out} - cscf
*/


typedef struct {
    ngx_uint_t                      stat;
    ngx_str_t                       stylesheet;
} ngx_rtmp_stat_loc_conf_t;


static ngx_conf_bitmask_t           ngx_rtmp_stat_masks[] = {
    { ngx_string("all"),            NGX_RTMP_STAT_ALL           },
    { ngx_string("global"),         NGX_RTMP_STAT_GLOBAL        },
    { ngx_string("live"),           NGX_RTMP_STAT_LIVE          },
    { ngx_string("clients"),        NGX_RTMP_STAT_CLIENTS       },
    { ngx_null_string,              0 }
}; 


static ngx_command_t  ngx_rtmp_stat_commands[] = {

    { ngx_string("rtmp_stat"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
        ngx_conf_set_bitmask_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_rtmp_stat_loc_conf_t, stat),
        ngx_rtmp_stat_masks },

    { ngx_string("rtmp_stat_stylesheet"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_rtmp_stat_loc_conf_t, stylesheet),
        NULL },

    ngx_null_command
};


static ngx_http_module_t  ngx_rtmp_stat_module_ctx = {
	NULL,                               /* preconfiguration */
	ngx_rtmp_stat_postconfiguration,    /* postconfiguration */

	NULL,                               /* create main configuration */
	NULL,                               /* init main configuration */

	NULL,                               /* create server configuration */
	NULL,                               /* merge server configuration */

	ngx_rtmp_stat_create_loc_conf,      /* create location configuration */
	ngx_rtmp_stat_merge_loc_conf,       /* merge location configuration */
};


ngx_module_t  ngx_rtmp_stat_module = {
	NGX_MODULE_V1,
	&ngx_rtmp_stat_module_ctx,          /* module context */
	ngx_rtmp_stat_commands,             /* module directives */
	NGX_HTTP_MODULE,                    /* module type */
	NULL,                               /* init master */
	NULL,                               /* init module */
	NULL,                               /* init process */
	NULL,                               /* init thread */
	NULL,                               /* exit thread */
	NULL,                               /* exit process */
	NULL,                               /* exit master */
	NGX_MODULE_V1_PADDING
};


#define NGX_RTMP_STAT_BUFSIZE           256


static void
ngx_rtmp_stat_output(ngx_http_request_t *r, ngx_chain_t ***lll,
        void *data, size_t len, ngx_uint_t escape)
{
    ngx_chain_t        *cl;
    ngx_buf_t          *b;
    size_t              real_len;

    if (len == 0) {
        return;
    }

    real_len = escape
        ? len + ngx_escape_html(NULL, data, len)
        : len;

    cl = **lll;
    if (cl && cl->buf->last + real_len > cl->buf->end) {
        *lll = &cl->next;
    }

    if (**lll == NULL) {
        cl = ngx_alloc_chain_link(r->pool);
        if (cl == NULL) {
            return;
        }
        b = ngx_create_temp_buf(r->pool, 
                ngx_max(NGX_RTMP_STAT_BUFSIZE, real_len));
        if (b == NULL || b->pos == NULL) {
            return;
        }
        cl->next = NULL;
        cl->buf = b;
        **lll = cl;
    }

    b = (**lll)->buf;

    if (escape) {
        b->last = (u_char *)ngx_escape_html(b->last, data, len);
    } else {
        b->last = ngx_cpymem(b->last, data, len);
    }
}


/* These shortcuts assume 2 variables exist in current context:
 *   ngx_http_request_t    *r
 *   ngx_chain_t         ***lll */

/* plain data */
#define NGX_RTMP_STAT(data, len)    ngx_rtmp_stat_output(r, lll, data, len, 0)

/* escaped data */
#define NGX_RTMP_STAT_E(data, len)  ngx_rtmp_stat_output(r, lll, data, len, 1)

/* literal */
#define NGX_RTMP_STAT_L(s)          NGX_RTMP_STAT((s), sizeof(s) - 1)

/* ngx_str_t */
#define NGX_RTMP_STAT_S(s)          NGX_RTMP_STAT((s)->data, (s)->len)

/* escaped ngx_str_t */
#define NGX_RTMP_STAT_ES(s)         NGX_RTMP_STAT_E((s)->data, (s)->len)

/* C string */
#define NGX_RTMP_STAT_CS(s)         NGX_RTMP_STAT((s), ngx_strlen(s))

/* escaped C string */
#define NGX_RTMP_STAT_ECS(s)        NGX_RTMP_STAT_E((s), ngx_strlen(s))


static void
ngx_rtmp_stat_bw(ngx_http_request_t *r, ngx_chain_t ***lll,
        ngx_rtmp_bandwidth_t *bw_in, ngx_rtmp_bandwidth_t *bw_out)
{
    u_char                          buf[NGX_OFF_T_LEN + 1];

    ngx_rtmp_update_bandwidth(bw_in, 0);
    ngx_rtmp_update_bandwidth(bw_out, 0);

    NGX_RTMP_STAT_L("<in>");
    NGX_RTMP_STAT(buf, ngx_snprintf(buf, sizeof(buf), 
                "%uz", bw_in->bytes) - buf);
    NGX_RTMP_STAT_L("</in>\r\n");

    NGX_RTMP_STAT_L("<out>");
    NGX_RTMP_STAT(buf, ngx_snprintf(buf, sizeof(buf), 
                "%uz", bw_out->bytes) - buf);
    NGX_RTMP_STAT_L("</out>\r\n");

    NGX_RTMP_STAT_L("<bwin>");
    NGX_RTMP_STAT(buf, ngx_snprintf(buf, sizeof(buf), 
                "%uz", bw_in->bandwidth * 8) - buf);
    NGX_RTMP_STAT_L("</bwin>\r\n");

    NGX_RTMP_STAT_L("<bwout>");
    NGX_RTMP_STAT(buf, ngx_snprintf(buf, sizeof(buf), 
                "%uz", bw_out->bandwidth * 8) - buf);
    NGX_RTMP_STAT_L("</bwout>\r\n");
}


static void
ngx_rtmp_stat_live(ngx_http_request_t *r, ngx_chain_t ***lll, 
        ngx_rtmp_live_app_conf_t *lacf)
{
    ngx_rtmp_live_stream_t         *stream;
    ngx_rtmp_live_meta_t           *meta;
    ngx_rtmp_live_ctx_t            *ctx;
    ngx_rtmp_session_t             *s;
    ngx_int_t                       n;
    size_t                          nclients, total_nclients;
    ngx_int_t                       publishing;
    u_char                          buf[NGX_OFF_T_LEN + 1];
    ngx_rtmp_stat_loc_conf_t       *slcf;
    u_char                         *codec;

    slcf = ngx_http_get_module_loc_conf(r, ngx_rtmp_stat_module);

    NGX_RTMP_STAT_L("<live>\r\n");

    total_nclients = 0;
    for (n = 0; n < lacf->nbuckets; ++n) {
        for (stream = lacf->streams[n]; stream; stream = stream->next) {
            publishing = 0;
            NGX_RTMP_STAT_L("<stream>\r\n");

            NGX_RTMP_STAT_L("<name>");
            NGX_RTMP_STAT_ECS(stream->name);
            NGX_RTMP_STAT_L("</name>\r\n");

            meta = &stream->meta;
            NGX_RTMP_STAT_L("<meta><width>");
            NGX_RTMP_STAT(buf, ngx_snprintf(buf, sizeof(buf), 
                                "%ui", meta->width) - buf);
            NGX_RTMP_STAT_L("</width><height>");
            NGX_RTMP_STAT(buf, ngx_snprintf(buf, sizeof(buf), 
                                "%ui", meta->height) - buf);
            NGX_RTMP_STAT_L("</height><framerate>");
            NGX_RTMP_STAT(buf, ngx_snprintf(buf, sizeof(buf), 
                                "%ui", meta->frame_rate) - buf);
            NGX_RTMP_STAT_L("</framerate><video>");
            codec = ngx_rtmp_get_video_codec_name(meta->video_codec_id);
            if (*codec) {
                NGX_RTMP_STAT_ECS(codec);
            }
            NGX_RTMP_STAT_L("</video><audio>");
            codec = ngx_rtmp_get_audio_codec_name(meta->audio_codec_id);
            if (*codec) {
                NGX_RTMP_STAT_ECS(codec);
            }
            NGX_RTMP_STAT_L("</audio></meta>\r\n");

            ngx_rtmp_stat_bw(r, lll, &stream->bw_in, &stream->bw_out);

            nclients = 0;
            for (ctx = stream->ctx; ctx; ctx = ctx->next, ++nclients) {
                s = ctx->session;
                /* TODO: add 
                 * 1) session start time 
                 * 2) drop stats  */
                if (slcf->stat & NGX_RTMP_STAT_CLIENTS) {
                    NGX_RTMP_STAT_L("<client>");

                    NGX_RTMP_STAT_L("<address>");
                    NGX_RTMP_STAT_S(&s->connection->addr_text);
                    NGX_RTMP_STAT_L("</address>");

                    NGX_RTMP_STAT_L("<dropped>");
                    NGX_RTMP_STAT(buf, ngx_snprintf(buf, sizeof(buf), 
                                "%uz", ctx->dropped) - buf);
                    NGX_RTMP_STAT_L("</dropped>");

                    if (s->flashver.len) {
                        NGX_RTMP_STAT_L("<flashver>");
                        NGX_RTMP_STAT_ES(&s->flashver);
                        NGX_RTMP_STAT_L("</flashver>");
                    }

                    if (s->page_url.len) {
                        NGX_RTMP_STAT_L("<pageurl>");
                        NGX_RTMP_STAT_ES(&s->page_url);
                        NGX_RTMP_STAT_L("</pageurl>");
                    }

                    if (ctx->flags & NGX_RTMP_LIVE_PUBLISHING) {
                        NGX_RTMP_STAT_L("<publishing/>");
                    }

                    NGX_RTMP_STAT_L("</client>\r\n");
                }
                if (ctx->flags & NGX_RTMP_LIVE_PUBLISHING) {
                    publishing = 1;
                }
            }
            total_nclients += nclients;

            NGX_RTMP_STAT_L("<nclients>");
            NGX_RTMP_STAT(buf, ngx_snprintf(buf, sizeof(buf), 
                        "%uz", nclients) - buf);
            NGX_RTMP_STAT_L("</nclients>\r\n");

            if (publishing) {
                NGX_RTMP_STAT_L("<publishing/>\r\n");
            }

            NGX_RTMP_STAT_L("</stream>\r\n");
        }
    }

    NGX_RTMP_STAT_L("<nclients>");
    NGX_RTMP_STAT(buf, ngx_snprintf(buf, sizeof(buf), 
                "%uz", total_nclients) - buf);
    NGX_RTMP_STAT_L("</nclients>\r\n");

    NGX_RTMP_STAT_L("</live>\r\n");
}


static void
ngx_rtmp_stat_application(ngx_http_request_t *r, ngx_chain_t ***lll, 
        ngx_rtmp_core_app_conf_t *cacf)
{
    ngx_rtmp_stat_loc_conf_t       *slcf;

    NGX_RTMP_STAT_L("<application>\r\n");
    NGX_RTMP_STAT_L("<name>");
    NGX_RTMP_STAT_ES(&cacf->name);
    NGX_RTMP_STAT_L("</name>\r\n");

    slcf = ngx_http_get_module_loc_conf(r, ngx_rtmp_stat_module);

    if (slcf->stat & NGX_RTMP_STAT_LIVE) {
        ngx_rtmp_stat_live(r, lll, 
                cacf->app_conf[ngx_rtmp_live_module.ctx_index]);
    }

    NGX_RTMP_STAT_L("</application>\r\n");
}


static void
ngx_rtmp_stat_server(ngx_http_request_t *r, ngx_chain_t ***lll, 
        ngx_rtmp_core_srv_conf_t *cscf)
{
    ngx_rtmp_core_app_conf_t      **cacf;
    size_t                          n;

    NGX_RTMP_STAT_L("<server>\r\n");

    cacf = cscf->applications.elts;
    for (n = 0; n < cscf->applications.nelts; ++n, ++cacf) {
        ngx_rtmp_stat_application(r, lll, *cacf);
    }

    NGX_RTMP_STAT_L("</server>\r\n");
}


static ngx_int_t
ngx_rtmp_stat_handler(ngx_http_request_t *r)
{
    ngx_rtmp_stat_loc_conf_t       *slcf;
    ngx_rtmp_core_main_conf_t      *cmcf;
    ngx_rtmp_core_srv_conf_t      **cscf;
    ngx_chain_t                    *cl, *l, **ll, ***lll;
    size_t                          n;
    off_t                           len;

    r->keepalive = 0;
    slcf = ngx_http_get_module_loc_conf(r, ngx_rtmp_stat_module);
    if (slcf->stat == 0) {
        return NGX_DECLINED;
    }

    cmcf = ngx_rtmp_core_main_conf;
    if (cmcf == NULL) {
        goto error;
    }

    cl = NULL;
    ll = &cl;
    lll = &ll;

    NGX_RTMP_STAT_L("<?xml version=\"1.0\" encoding=\"utf-8\" ?>\r\n");
    if (slcf->stylesheet.len) {
        NGX_RTMP_STAT_L("<?xml-stylesheet type=\"text/xsl\" href=\"");
        NGX_RTMP_STAT_ES(&slcf->stylesheet);
        NGX_RTMP_STAT_L("\" ?>\r\n");
    }

    NGX_RTMP_STAT_L("<rtmp>\r\n");

    ngx_rtmp_stat_bw(r, lll, &ngx_rtmp_bw_in, &ngx_rtmp_bw_out);

    cscf = cmcf->servers.elts;
    for (n = 0; n < cmcf->servers.nelts; ++n, ++cscf) {
        ngx_rtmp_stat_server(r, lll, *cscf);
    }

    NGX_RTMP_STAT_L("</rtmp>\r\n");

    len = 0;
    for (l = cl; l; l = l->next) {
        len += (l->buf->last - l->buf->pos);
    }
    ngx_str_set(&r->headers_out.content_type, "text/xml");
    r->headers_out.content_length_n = len;
    r->headers_out.status = NGX_HTTP_OK;
    ngx_http_send_header(r);
    (*ll)->buf->last_buf = 1;
    return ngx_http_output_filter(r, cl);

error:
    r->headers_out.status = NGX_HTTP_INTERNAL_SERVER_ERROR;
    r->headers_out.content_length_n = 0;
    return ngx_http_send_header(r);
}


static void *
ngx_rtmp_stat_create_loc_conf(ngx_conf_t *cf)
{
	ngx_rtmp_stat_loc_conf_t       *conf;

	conf = ngx_pcalloc(cf->pool, sizeof(ngx_rtmp_stat_loc_conf_t));
	if (conf == NULL) {
		return NULL;
	}

    conf->stat = 0;

	return conf;
}


static char *
ngx_rtmp_stat_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
	ngx_rtmp_stat_loc_conf_t       *prev = parent;
	ngx_rtmp_stat_loc_conf_t       *conf = child;

	ngx_conf_merge_bitmask_value(conf->stat, prev->stat, 0);
	ngx_conf_merge_str_value(conf->stylesheet, prev->stylesheet, "");

	return NGX_CONF_OK;
}


static ngx_int_t
ngx_rtmp_stat_postconfiguration(ngx_conf_t *cf)
{
	ngx_http_handler_pt            *h;
	ngx_http_core_main_conf_t      *cmcf;

	cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

	h = ngx_array_push(&cmcf->phases[NGX_HTTP_CONTENT_PHASE].handlers);
	if (h == NULL) {
		return NGX_ERROR;
	}
	*h = ngx_rtmp_stat_handler;

	return NGX_OK;
}

