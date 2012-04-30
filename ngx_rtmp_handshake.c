/*
 * Copyright (c) 2012 Roman Arutyunyan
 */

/* TODO: implement hs in/out buf free chains */

ngx_int_t
ngx_rtmp_handshake_response(ngx_rtmp_session_t *s)
{
    u_char             *p;

    /* read client epoch */
    p = (u_char *)&s->peer_epoch;
    *p++ = s->hs_in[4];
    *p++ = s->hs_in[3];
    *p++ = s->hs_in[2];
    *p++ = s->hs_in[1];

    /* set out version */
    s->hs_out[0] = '\x03';

    /* set server epoch */
    s->epoch = ngx_current_msec;
    p = (u_char *)&s->epoch;
    s->hs_out[4] = *p++;
    s->hs_out[3] = *p++;
    s->hs_out[2] = *p++;
    s->hs_out[1] = *p++;

    ngx_memcpy(hs_out + 5, s->hs_in + 5, 4);
    ngx_memcpy(hs_out + 9, s->hs_in + 9, 
            NGX_RTMP_HANDSHAKE_SIZE - 8);
    ngx_memcpy(hs_out + 1 + NGX_RTMP_HANDSHAKE_SIZE, s->hs_out + 1, 
            NGX_RTMP_HANDSHAKE_SIZE);

    if (*(uint32_t *)(s->hs_in + 5) == 0) {
        ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0, 
                "RTMP old-style handshake");
        return NGX_OK;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0, 
            "RTMP new-style handshake");

    /* set last 32 bytes of s->hs_out to hash */

    return NGX_OK;
}

