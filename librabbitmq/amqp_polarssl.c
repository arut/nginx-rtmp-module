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
#include <polarssl/ctr_drbg.h>
#include <polarssl/entropy.h>
#include <polarssl/net.h>
#include <polarssl/ssl.h>
#include <polarssl/version.h>
#include <stdlib.h>
#include <string.h>

#ifndef AMQP_USE_UNTESTED_SSL_BACKEND
# error This SSL backend is alpha quality and likely contains errors.\
  -DAMQP_USE_UNTESTED_SSL_BACKEND to use this backend
#endif

struct amqp_ssl_socket_t {
  const struct amqp_socket_class_t *klass;
  int sockfd;
  entropy_context *entropy;
  ctr_drbg_context *ctr_drbg;
  x509_cert *cacert;
  rsa_context *key;
  x509_cert *cert;
  ssl_context *ssl;
  ssl_session *session;
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
  ssize_t status;
  struct amqp_ssl_socket_t *self = (struct amqp_ssl_socket_t *)base;

  self->last_error = 0;
  status = ssl_write(self->ssl, buf, len);
  if (status < 0) {
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
  written = amqp_ssl_socket_send(self, (const unsigned char *)self->buffer,
                      bytes, 0);
exit:
  return written;
}

static ssize_t
amqp_ssl_socket_recv(void *base,
                     void *buf,
                     size_t len,
                     AMQP_UNUSED int flags)
{
  ssize_t status;
  struct amqp_ssl_socket_t *self = (struct amqp_ssl_socket_t *)base;

  self->last_error = 0;
  status = ssl_read(self->ssl, buf, len);
  if (status < 0) {
    self->last_error = AMQP_STATUS_SSL_ERROR;
  }

  return status;
}

static int
amqp_ssl_socket_open(void *base, const char *host, int port, struct timeval *timeout)
{
  int status;
  struct amqp_ssl_socket_t *self = (struct amqp_ssl_socket_t *)base;
  self->last_error = 0;

  if (timeout && (timeout->tv_sec != 0 || timeout->tv_usec != 0)) {
    /* We don't support PolarSSL for now because it uses its own connect() wrapper
     * It is not too hard to implement net_connect() with noblock support,
     * but then we will have to maintain that piece of code and keep it synced with main PolarSSL code base
     */
    return AMQP_STATUS_INVALID_PARAMETER;
  }

  status = net_connect(&self->sockfd, host, port);
  if (status) {
    /* This isn't quite right. We should probably translate between
     * POLARSSL_ERR_* to our internal error codes
     */
    self->last_error = AMQP_STATUS_SSL_ERROR;
    return -1;
  }
  if (self->cacert) {
    ssl_set_ca_chain(self->ssl, self->cacert, NULL, host);
  }
  ssl_set_bio(self->ssl, net_recv, &self->sockfd,
              net_send, &self->sockfd);
  if (self->key && self->cert) {
    ssl_set_own_cert(self->ssl, self->cert, self->key);
  }
  while (0 != (status = ssl_handshake(self->ssl))) {
    switch (status) {
    case POLARSSL_ERR_NET_WANT_READ:
    case POLARSSL_ERR_NET_WANT_WRITE:
      continue;
    default:
      self->last_error = AMQP_STATUS_SSL_ERROR;
      break;
    }
  }
  return status;
}

static int
amqp_ssl_socket_close(void *base)
{
  int status = -1;
  struct amqp_ssl_socket_t *self = (struct amqp_ssl_socket_t *)base;
  if (self) {
    free(self->entropy);
    free(self->ctr_drbg);
    x509_free(self->cacert);
    free(self->cacert);
    rsa_free(self->key);
    free(self->key);
    x509_free(self->cert);
    free(self->cert);
    ssl_free(self->ssl);
    free(self->ssl);
    free(self->session);
    free(self->buffer);
    if (self->sockfd >= 0) {
      net_close(self->sockfd);
      status = 0;
    }
    free(self);
  }
  return status;
}

static int
amqp_ssl_socket_error(AMQP_UNUSED void *user_data)
{
  return AMQP_STATUS_SSL_ERROR;
}

char *
amqp_ssl_error_string(AMQP_UNUSED int err)
{
  return strdup("A SSL socket error occurred");
}

static int
amqp_ssl_socket_get_sockfd(void *base)
{
  struct amqp_ssl_socket_t *self = (struct amqp_ssl_socket_t *)base;
  return self->sockfd;
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
  int status;
  if (!self) {
    goto error;
  }
  self->entropy = calloc(1, sizeof(*self->entropy));
  if (!self->entropy) {
    goto error;
  }
  self->sockfd = -1;
  entropy_init(self->entropy);
  self->ctr_drbg = calloc(1, sizeof(*self->ctr_drbg));
  if (!self->ctr_drbg) {
    goto error;
  }
  status = ctr_drbg_init(self->ctr_drbg, entropy_func, self->entropy,
                         NULL, 0);
  if (status) {
    goto error;
  }
  self->ssl = calloc(1, sizeof(*self->ssl));
  if (!self->ssl) {
    goto error;
  }
  status = ssl_init(self->ssl);
  if (status) {
    goto error;
  }
  ssl_set_endpoint(self->ssl, SSL_IS_CLIENT);
  ssl_set_rng(self->ssl, ctr_drbg_random, self->ctr_drbg);
  ssl_set_ciphersuites(self->ssl, ssl_default_ciphersuites);
  ssl_set_authmode(self->ssl, SSL_VERIFY_REQUIRED);
  self->session = calloc(1, sizeof(*self->session));
  if (!self->session) {
    goto error;
  }
#if POLARSSL_VERSION_NUMBER >= 0x01020000
  ssl_set_session(self->ssl, self->session);
#else
  ssl_set_session(self->ssl, 0, 0, self->session);
#endif

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
  self->cacert = calloc(1, sizeof(*self->cacert));
  if (!self->cacert) {
    return -1;
  }
  status = x509parse_crtfile(self->cacert, cacert);
  if (status) {
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
  self->key = calloc(1, sizeof(*self->key));
  if (!self->key) {
    return -1;
  }
  status = x509parse_keyfile(self->key, key, NULL);
  if (status) {
    return -1;
  }
  self->cert = calloc(1, sizeof(*self->cert));
  if (!self->cert) {
    return -1;
  }
  status = x509parse_crtfile(self->cert, cert);
  if (status) {
    return -1;
  }
  return 0;
}

int
amqp_ssl_socket_set_key_buffer(AMQP_UNUSED amqp_socket_t *base,
                               AMQP_UNUSED const char *cert,
                               AMQP_UNUSED const void *key,
                               AMQP_UNUSED size_t n)
{
  amqp_abort("%s is not implemented for PolarSSL", __func__);
  return -1;
}

void
amqp_ssl_socket_set_verify(amqp_socket_t *base,
                           amqp_boolean_t verify)
{
  struct amqp_ssl_socket_t *self;
  if (base->klass != &amqp_ssl_socket_class) {
    amqp_abort("<%p> is not of type amqp_ssl_socket_t", base);
  }
  self = (struct amqp_ssl_socket_t *)base;
  if (verify) {
    ssl_set_authmode(self->ssl, SSL_VERIFY_REQUIRED);
  } else {
    ssl_set_authmode(self->ssl, SSL_VERIFY_NONE);
  }
}

void
amqp_set_initialize_ssl_library(AMQP_UNUSED amqp_boolean_t do_initialize)
{
}
