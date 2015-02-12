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

#include "amqp_ssl_socket.h"
#include "amqp_private.h"
#include <cyassl/ssl.h>
#include <stdlib.h>
#include <string.h>

#ifndef AMQP_USE_UNTESTED_SSL_BACKEND
# error This SSL backend is alpha quality and likely contains errors.\
  -DAMQP_USE_UNTESTED_SSL_BACKEND to use this backend
#endif

struct amqp_ssl_socket_t {
  const struct amqp_socket_class_t *klass;
  CYASSL_CTX *ctx;
  CYASSL *ssl;
  int sockfd;
  char *buffer;
  size_t length;
  int last_error;
};

static ssize_t
amqp_ssl_socket_send(void *base,
                     const void *buf,
                     size_t len,
                     AMQP_UNUSED int flags)
{
  int status;
  struct amqp_ssl_socket_t *self = (struct amqp_ssl_socket_t *)base;

  self->last_error = 0;
  status = CyaSSL_write(self->ssl, buf, len);
  if (status <= 0) {
    self->last_error = AMQP_STATUS_SSL_ERROR;
  }

  return status;
}

static ssize_t
amqp_ssl_socket_writev(void *base,
                       const struct iovec *iov,
                       int iovcnt)
{
  struct amqp_ssl_socket_t *self = (struct amqp_ssl_socket_t *)base;
  ssize_t written = -1;
  char *bufferp;
  size_t bytes;
  int i;
  self->last_error = 0;
  bytes = 0;
  for (i = 0; i < iovcnt; ++i) {
    bytes += iov[i].iov_len;
  }
  if (self->length < bytes) {
    free(self->buffer);
    self->buffer = malloc(bytes);
    if (!self->buffer) {
      self->length = 0;
      self->last_error = AMQP_STATUS_NO_MEMORY;
      goto exit;
    }
    self->length = bytes;
  }
  bufferp = self->buffer;
  for (i = 0; i < iovcnt; ++i) {
    memcpy(bufferp, iov[i].iov_base, iov[i].iov_len);
    bufferp += iov[i].iov_len;
  }
  written = amqp_ssl_socket_send(self, self->buffer, bytes, 0);
exit:
  return written;
}

static ssize_t
amqp_ssl_socket_recv(void *base,
                     void *buf,
                     size_t len,
                     AMQP_UNUSED int flags)
{
  int status;
  struct amqp_ssl_socket_t *self = (struct amqp_ssl_socket_t *)base;

  self->last_error = 0;
  status = CyaSSL_read(self->ssl, buf, len);
  if (status <= 0) {
    self->last_error = AMQP_STATUS_SSL_ERROR;
  }

  return status;
}

static int
amqp_ssl_socket_get_sockfd(void *base)
{
  struct amqp_ssl_socket_t *self = (struct amqp_ssl_socket_t *)base;
  return self->sockfd;
}

static int
amqp_ssl_socket_close(void *base)
{
  int status = -1;
  struct amqp_ssl_socket_t *self = (struct amqp_ssl_socket_t *)base;
  if (self->sockfd >= 0) {
    status = amqp_os_socket_close(self->sockfd);
  }
  if (self) {
    CyaSSL_free(self->ssl);
    CyaSSL_CTX_free(self->ctx);
    free(self->buffer);
    free(self);
  }
  return status;
}

static int
amqp_ssl_socket_error(void *base)
{
  struct amqp_ssl_socket_t *self = (struct amqp_ssl_socket_t *)base;
  return self->last_error;
}

char *
amqp_ssl_error_string(AMQP_UNUSED int err)
{
  return strdup("A ssl socket error occurred.");
}

static int
amqp_ssl_socket_open(void *base, const char *host, int port, struct timeval *timeout)
{
  struct amqp_ssl_socket_t *self = (struct amqp_ssl_socket_t *)base;
  int status;
  self->last_error = 0;

  self->ssl = CyaSSL_new(self->ctx);
  if (NULL == self->ssl) {
    self->last_error = AMQP_STATUS_SSL_ERROR;
    return -1;
  }

  self->sockfd = amqp_open_socket_noblock(host, port, timeout);
  if (0 > self->sockfd) {
    self->last_error = - self->sockfd;
    return -1;
  }
  CyaSSL_set_fd(self->ssl, self->sockfd);
  status = CyaSSL_connect(self->ssl);
  if (SSL_SUCCESS != status) {
    self->last_error = AMQP_STATUS_SSL_ERROR;
    return -1;
  }
  return 0;
}

static const struct amqp_socket_class_t amqp_ssl_socket_class = {
  amqp_ssl_socket_writev, /* writev */
  amqp_ssl_socket_send, /* send */
  amqp_ssl_socket_recv, /* recv */
  amqp_ssl_socket_open, /* open */
  amqp_ssl_socket_close, /* close */
  amqp_ssl_socket_error, /* error */
  amqp_ssl_socket_get_sockfd /* get_sockfd */
};

amqp_socket_t *
amqp_ssl_socket_new(void)
{
  struct amqp_ssl_socket_t *self = calloc(1, sizeof(*self));
  if (!self) {
    goto error;
  }
  CyaSSL_Init();
  self->ctx = CyaSSL_CTX_new(CyaSSLv23_client_method());
  if (!self->ctx) {
    goto error;
  }
  self->klass = &amqp_ssl_socket_class;
  return (amqp_socket_t *)self;
error:
  amqp_socket_close((amqp_socket_t *)self);
  return NULL;
}

int
amqp_ssl_socket_set_cacert(amqp_socket_t *base,
                           const char *cacert)
{
  int status;
  struct amqp_ssl_socket_t *self;
  if (base->klass != &amqp_ssl_socket_class) {
    amqp_abort("<%p> is not of type amqp_ssl_socket_t", base);
  }
  self = (struct amqp_ssl_socket_t *)base;
  status = CyaSSL_CTX_load_verify_locations(self->ctx, cacert, NULL);
  if (SSL_SUCCESS != status) {
    return -1;
  }
  return 0;
}

int
amqp_ssl_socket_set_key(amqp_socket_t *base,
                        const char *cert,
                        const char *key)
{
  int status;
  struct amqp_ssl_socket_t *self;
  if (base->klass != &amqp_ssl_socket_class) {
    amqp_abort("<%p> is not of type amqp_ssl_socket_t", base);
  }
  self = (struct amqp_ssl_socket_t *)base;
  status = CyaSSL_CTX_use_PrivateKey_file(self->ctx, key,
                                          SSL_FILETYPE_PEM);
  if (SSL_SUCCESS != status) {
    return -1;
  }
  status = CyaSSL_CTX_use_certificate_chain_file(self->ctx, cert);
  return 0;
}

int
amqp_ssl_socket_set_key_buffer(AMQP_UNUSED amqp_socket_t *base,
                               AMQP_UNUSED const char *cert,
                               AMQP_UNUSED const void *key,
                               AMQP_UNUSED size_t n)
{
  amqp_abort("%s is not implemented for CyaSSL", __func__);
  return -1;
}

void
amqp_ssl_socket_set_verify(AMQP_UNUSED amqp_socket_t *base,
                           AMQP_UNUSED amqp_boolean_t verify)
{
  /* noop for CyaSSL */
}

void
amqp_set_initialize_ssl_library(AMQP_UNUSED amqp_boolean_t do_initialize)
{
}
