/*
 * Copyright (c) 2012 Roman Arutyunyan
 */


#include "ngx_rtmp_codecs.h"


const char * audio_codecs[] = {
    "Uncompressed",
    "ADPCM",
    "MP3",
    "",
    "",
    "Nellymoser8",
    "Nellymoser",
    "",
    "",
    "",
    "HE-ACC",
    "Speex"
};


const char * video_codecs[] = {
    "",
    "",
    "Sorenson-H263",
    "ScreenVideo",
    "On2-VP6",
    "On2-VP6-Alpha",
    "H264",
};


u_char * 
ngx_rtmp_get_audio_codec_name(ngx_uint_t id)
{
    return (u_char *)(id < sizeof(audio_codecs) / sizeof(audio_codecs[0])
        ? audio_codecs[id]
        : "");
}


u_char * 
ngx_rtmp_get_video_codec_name(ngx_uint_t id)
{
    return (u_char *)(id < sizeof(video_codecs) / sizeof(video_codecs[0])
        ? video_codecs[id]
        : "");
}
