/* vim:set ft=c ts=2 sw=2 sts=2 et cindent: */
/*
 * Copyright 2012-2013 Michael Steinert
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "amqp_private.h"
#include "amqp_tcp_socket.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

struct amqp_tcp_socket_t {
  const struct amqp_socket_class_t *klass;
  int sockfd;
  void *buffer;
  size_t buffer_length;
  int internal_error;
};


static ssize_t
amqp_tcp_socket_send_inner(void *base, const void *buf, size_t len, int flags)
{
  struct amqp_tcp_socket_t *self = (struct amqp_tcp_socket_t *)base;
  ssize_t res;
  const char *buf_left = buf;
  ssize_t len_left = len;

  if (-1 == self->sockfd) {
    return AMQP_STATUS_SOCKET_CLOSED;
  }

#ifdef MSG_NOSIGNAL
  flags |= MSG_NOSIGNAL;
#endif

start:
  res = send(self->sockfd, buf_left, len_left, flags);

  if (res < 0) {
    self->internal_error = amqp_os_socket_error();
    if (EINTR == self->internal_error) {
      goto start;
    } else {
      res = AMQP_STATUS_SOCKET_ERROR;
    }
  } else {
    if (res == len_left) {
      self->internal_error = 0;
      res = AMQP_STATUS_OK;
    } else {
      buf_left += res;
      len_left -= res;
      goto start;
    }
  }

  return res;
}

static ssize_t
amqp_tcp_socket_send(void *base, const void *buf, size_t len)
{
  return amqp_tcp_socket_send_inner(base, buf, len, 0);
}

static ssize_t
amqp_tcp_socket_writev(void *base, struct iovec *iov, int iovcnt)
{
  struct amqp_tcp_socket_t *self = (struct amqp_tcp_socket_t *)base;
  ssize_t ret;
  if (-1 == self->sockfd) {
    return AMQP_STATUS_SOCKET_CLOSED;
  }

#if defined(_WIN32)
  {
    DWORD res;
    /* Making the assumption here that WSAsend won't do a partial send
     * unless an error occured, in which case we're hosed so it doesn't matter
     */
    if (WSASend(self->sockfd, (LPWSABUF)iov, iovcnt, &res, 0, NULL, NULL) ==
        0) {
      self->internal_error = 0;
      ret = AMQP_STATUS_OK;
    } else {
      self->internal_error = WSAGetLastError();
      ret = AMQP_STATUS_SOCKET_ERROR;
    }
    return ret;
  }

#elif defined(MSG_MORE)
  {
    int i;
    for (i = 0; i < iovcnt - 1; ++i) {
      ret = amqp_tcp_socket_send_inner(self, iov[i].iov_base, iov[i].iov_len,
                                       MSG_MORE);
      if (ret != AMQP_STATUS_OK) {
        goto exit;
      }
    }
    ret = amqp_tcp_socket_send_inner(self, iov[i].iov_base, iov[i].iov_len, 0);

  exit:
    return ret;
  }

#elif defined(SO_NOSIGPIPE) || !defined(MSG_NOSIGNAL)
  {
    int i;
    ssize_t len_left = 0;

    struct iovec *iov_left = iov;
    int iovcnt_left = iovcnt;

    for (i = 0; i < iovcnt; ++i) {
      len_left += iov[i].iov_len;
    }

  start:
    ret = writev(self->sockfd, iov_left, iovcnt_left);

    if (ret < 0) {
      self->internal_error = amqp_os_socket_error();
      if (EINTR == self->internal_error) {
        goto start;
      } else {
        self->internal_error = amqp_os_socket_error();
        ret = AMQP_STATUS_SOCKET_ERROR;
      }
    } else {
      if (ret == len_left) {
        self->internal_error = 0;
        ret = AMQP_STATUS_OK;
      } else {
        len_left -= ret;
        for (i = 0; i < iovcnt_left; ++i) {
          if (ret < (ssize_t)iov_left[i].iov_len) {
            iov_left[i].iov_base = ((char *)iov_left[i].iov_base) + ret;
            iov_left[i].iov_len -= ret;

            iovcnt_left -= i;
            iov_left += i;
            break;
          } else {
            ret -= iov_left[i].iov_len;
          }
        }
        goto start;
      }
    }

    return ret;
  }

#else
  {
    int i;
    size_t bytes = 0;
    void *bufferp;

    for (i = 0; i < iovcnt; ++i) {
      bytes += iov[i].iov_len;
    }

    if (self->buffer_length < bytes) {
      self->buffer = realloc(self->buffer, bytes);
      if (NULL == self->buffer) {
        self->buffer_length = 0;
        self->internal_error = 0;
        ret = AMQP_STATUS_NO_MEMORY;
        goto exit;
      }
      self->buffer_length = bytes;
    }

    bufferp = self->buffer;
    for (i = 0; i < iovcnt; ++i) {
      memcpy(bufferp, iov[i].iov_base, iov[i].iov_len);
      bufferp += iov[i].iov_len;
    }

    ret = amqp_tcp_socket_send_inner(self, self->buffer, bytes, 0);

  exit:
    return ret;
  }
#endif
}

static ssize_t
amqp_tcp_socket_recv(void *base, void *buf, size_t len, int flags)
{
  struct amqp_tcp_socket_t *self = (struct amqp_tcp_socket_t *)base;
  ssize_t ret;
  if (-1 == self->sockfd) {
    return AMQP_STATUS_SOCKET_CLOSED;
  }

start:
  ret = recv(self->sockfd, buf, len, flags);

  if (0 > ret) {
    self->internal_error = amqp_os_socket_error();
    if (EINTR == self->internal_error) {
      goto start;
    } else {
      ret = AMQP_STATUS_SOCKET_ERROR;
    }
  } else if (0 == ret) {
    ret = AMQP_STATUS_CONNECTION_CLOSED;
  }

  return ret;
}

static int
amqp_tcp_socket_open(void *base, const char *host, int port, struct timeval *timeout)
{
  struct amqp_tcp_socket_t *self = (struct amqp_tcp_socket_t *)base;
  if (-1 != self->sockfd) {
    return AMQP_STATUS_SOCKET_INUSE;
  }
  self->sockfd = amqp_open_socket_noblock(host, port, timeout);
  if (0 > self->sockfd) {
    int err = self->sockfd;
    self->sockfd = -1;
    return err;
  }
  return AMQP_STATUS_OK;
}

static int
amqp_tcp_socket_close(void *base)
{
  struct amqp_tcp_socket_t *self = (struct amqp_tcp_socket_t *)base;
  if (-1 == self->sockfd) {
    return AMQP_STATUS_SOCKET_CLOSED;
  }

  if (amqp_os_socket_close(self->sockfd)) {
    return AMQP_STATUS_SOCKET_ERROR;
  }
  self->sockfd = -1;

  return AMQP_STATUS_OK;
}

static int
amqp_tcp_socket_get_sockfd(void *base)
{
  struct amqp_tcp_socket_t *self = (struct amqp_tcp_socket_t *)base;
  return self->sockfd;
}

static void
amqp_tcp_socket_delete(void *base)
{
  struct amqp_tcp_socket_t *self = (struct amqp_tcp_socket_t *)base;

  if (self) {
    amqp_tcp_socket_close(self);
    free(self->buffer);
    free(self);
  }
}

static const struct amqp_socket_class_t amqp_tcp_socket_class = {
  amqp_tcp_socket_writev, /* writev */
  amqp_tcp_socket_send, /* send */
  amqp_tcp_socket_recv, /* recv */
  amqp_tcp_socket_open, /* open */
  amqp_tcp_socket_close, /* close */
  amqp_tcp_socket_get_sockfd, /* get_sockfd */
  amqp_tcp_socket_delete /* delete */
};

amqp_socket_t *
amqp_tcp_socket_new(amqp_connection_state_t state)
{
  struct amqp_tcp_socket_t *self = calloc(1, sizeof(*self));
  if (!self) {
    return NULL;
  }
  self->klass = &amqp_tcp_socket_class;
  self->sockfd = -1;

  amqp_set_socket(state, (amqp_socket_t *)self);

  return (amqp_socket_t *)self;
}

void
amqp_tcp_socket_set_sockfd(amqp_socket_t *base, int sockfd)
{
  struct amqp_tcp_socket_t *self;
  if (base->klass != &amqp_tcp_socket_class) {
    amqp_abort("<%p> is not of type amqp_tcp_socket_t", base);
  }
  self = (struct amqp_tcp_socket_t *)base;
  self->sockfd = sockfd;
}
