#ifndef _NGX_RTMP_DASH_TEMPLATES
#define _NGX_RTMP_DASH_TEMPLATES

#define NGX_RTMP_DASH_MANIFEST_HEADER                                          \
    "<?xml version=\"1.0\"?>\n"                                                \
    "<MPD\n"                                                                   \
    "    type=\"dynamic\"\n"                                                   \
    "    xmlns=\"urn:mpeg:dash:schema:mpd:2011\"\n"                            \
    "    availabilityStartTime=\"%s\"\n"                                       \
    "    availabilityEndTime=\"%s\"\n"                                         \
    "    minimumUpdatePeriod=\"PT%uiS\"\n"                                     \
    "    minBufferTime=\"PT%uiS\"\n"                                           \
    "    timeShiftBufferDepth=\"PT0H0M0.00S\"\n"                               \
    "    suggestedPresentationDelay=\"PT%uiS\"\n"                              \
    "    profiles=\"urn:hbbtv:dash:profile:isoff-live:2012,"                   \
                   "urn:mpeg:dash:profile:isoff-live:2011\"\n"                 \
    "    xmlns:xsi=\"http://www.w3.org/2011/XMLSchema-instance\"\n"            \
    "    xsi:schemaLocation=\"urn:mpeg:DASH:schema:MPD:2011 DASH-MPD.xsd\">\n"

#define NGX_RTMP_DASH_PERIOD_HEADER                                            \
    "  <Period start=\"PT0S\" id=\"dash\">\n"

#define NGX_RTMP_DASH_ADAPTATION_SET_VIDEO                                     \
    "    <AdaptationSet\n"                                                     \
    "        group=\"1\"\n"                                                    \
    "        contentType=\"video\"\n"                                          \
    "        segmentAlignment=\"true\">\n"

#define NGX_RTMP_DASH_REPRESENTATION_VIDEO                                     \
    "      <Representation\n"                                                  \
    "          id=\"%V_H264\"\n"                                               \
    "          mimeType=\"video/mp4\"\n"                                       \
    "          codecs=\"avc1.%02uxi%02uxi%02uxi\"\n"                           \
    "          width=\"%ui\"\n"                                                \
    "          height=\"%ui\"\n"                                               \
    "          frameRate=\"%ui\"\n"                                            \
    "          sar=\"1:1\"\n"                                                  \
    "          startWithSAP=\"1\"\n"                                           \
    "          bandwidth=\"%ui\">\n"                                           \
    "        <SegmentTemplate\n"                                               \
    "            presentationTimeOffset=\"0\"\n"                               \
    "            timescale=\"1000\"\n"                                         \
    "            media=\"%V%s$Time$.m4v\"\n"                                   \
    "            initialization=\"%V%sinit.m4v\">\n"                           \
    "          <SegmentTimeline>\n"

#define NGX_RTMP_DASH_ADAPTATION_SET_AUDIO                                     \
    "    <AdaptationSet\n"                                                     \
    "        group=\"2\"\n"                                                    \
    "        segmentAlignment=\"true\">\n"                                     \
    "      <AudioChannelConfiguration\n"                                       \
    "          schemeIdUri=\"urn:mpeg:dash:"                                   \
                                "23003:3:audio_channel_configuration:2011\"\n" \
    "          value=\"1\"/>\n"

#define NGX_RTMP_DASH_REPRESENTATION_AUDIO                                     \
    "      <Representation\n"                                                  \
    "          id=\"%V_AAC\"\n"                                                \
    "          mimeType=\"audio/mp4\"\n"                                       \
    "          codecs=\"mp4a.%s\"\n"                                           \
    "          audioSamplingRate=\"%ui\"\n"                                    \
    "          startWithSAP=\"1\"\n"                                           \
    "          bandwidth=\"%ui\">\n"                                           \
    "        <SegmentTemplate\n"                                               \
    "            presentationTimeOffset=\"0\"\n"                               \
    "            timescale=\"1000\"\n"                                         \
    "            media=\"%V%s$Time$.m4a\"\n"                                   \
    "            initialization=\"%V%sinit.m4a\">\n"                           \
    "          <SegmentTimeline>\n"

#define NGX_RTMP_DASH_REPRESENTATION_FOOTER                                    \
    "          </SegmentTimeline>\n"                                           \
    "        </SegmentTemplate>\n"                                             \
    "      </Representation>\n"

#define NGX_RTMP_DASH_ADAPTATION_SET_FOOTER                                    \
    "    </AdaptationSet>\n"

#define NGX_RTMP_DASH_MANIFEST_TIME                                            \
    "             <S t=\"%uD\" d=\"%uD\"/>\n"

#define NGX_RTMP_DASH_PERIOD_FOOTER                                            \
    "  </Period>\n"

#define NGX_RTMP_DASH_MANIFEST_FOOTER                                          \
    "</MPD>\n"


#define NGX_RTMP_DASH_MANIFEST_PATH "%V/%V%V%s"

#endif
