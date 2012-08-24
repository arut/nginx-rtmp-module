/*
 * Copyright (c) 2012 Roman Arutyunyan
 */


#ifndef _NGX_RTMP_STREAMS_H_INCLUDED_
#define _NGX_RTMP_STREAMS_H_INCLUDED_


#define NGX_RTMP_MSID                   1

#define NGX_RTMP_CSID_AMF_INI           3
#define NGX_RTMP_CSID_AMF               5
#define NGX_RTMP_CSID_AUDIO             6
#define NGX_RTMP_CSID_VIDEO             7


/*legacy*/
#define NGX_RTMP_CMD_CSID_AMF_INI       NGX_RTMP_CSID_AMF_INI
#define NGX_RTMP_CMD_CSID_AMF           NGX_RTMP_CSID_AMF
#define NGX_RTMP_CMD_MSID               NGX_RTMP_MSID
#define NGX_RTMP_LIVE_CSID_META         NGX_RTMP_CSID_AMF
#define NGX_RTMP_LIVE_CSID_AUDIO        NGX_RTMP_CSID_AUDIO
#define NGX_RTMP_LIVE_CSID_VIDEO        NGX_RTMP_CSID_VIDEO
#define NGX_RTMP_LIVE_MSID              NGX_RTMP_MSID


#endif /* _NGX_RTMP_STREAMS_H_INCLUDED_ */
