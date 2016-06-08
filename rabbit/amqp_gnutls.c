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
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <stdlib.h>
#include <string.h>

#ifndef AMQP_USE_UNTESTED_SSL_BACKEND
# error This SSL backend is alpha quality and likely contains errors.\
  -DAMQP_USE_UNTESTED_SSL_BACKEND to use this backend
#endif

struct amqp_ssl_socket_t {
  const struct amqp_socket_class_t *klass;
  gnutls_session_t session;
  gnutls_certificate_credentials_t credentials;
  int sockfd;
  char *host;
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
  status = gnutls_record_send(self->session, buf, len);
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
    self->length = 0;
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
  ssize_t status;
  struct amqp_ssl_socket_t *self = (struct amqp_ssl_socket_t *)base;

  self->last_error = 0;
  status = gnutls_record_recv(self->session, buf, len);
  if (status < 0) {
    self->last_error = AMQP_STATUS_SSL_ERROR;
  }

  return status;
}

static int
amqp_ssl_socket_open(void *base, const char *host, int port, struct timeval *timeout)
{
  struct amqp_ssl_socket_t *self = (struct amqp_ssl_socket_t *)base;
  int status;
  self->last_error = 0;

  free(self->host);
  self->host = strdup(host);
  if (NULL == self->host) {
    self->last_error = AMQP_STATUS_NO_MEMORY;
    return -1;
  }

  self->sockfd = amqp_open_socket_noblock(host, port, timeout);
  if (0 > self->sockfd) {
    self->last_error = -self->sockfd;
    return -1;
  }
  gnutls_transport_set_ptr(self->session,
                           (gnutls_transport_ptr_t)self->sockfd);
  do {
    status = gnutls_handshake(self->session);
  } while (status < 0 && !gnutls_error_is_fatal(status));

  if (gnutls_error_is_fatal(status)) {
    self->last_error = AMQP_STATUS_SSL_ERROR;
  }

  return status;
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
    gnutls_deinit(self->session);
    gnutls_certificate_free_credentials(self->credentials);
    free(self->host);
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
  return strdup("A SSL error occurred");
}

static int
amqp_ssl_socket_get_sockfd(void *base)
{
  struct amqp_ssl_socket_t *self = (struct amqp_ssl_socket_t *)base;
  return self->sockfd;
}

static int
amqp_ssl_verify(gnutls_session_t session)
{
  int ret;
  unsigned int status, size;
  const gnutls_datum_t *list;
  gnutls_x509_crt_t cert = NULL;
  struct amqp_ssl_socket_t *self = gnutls_session_get_ptr(session);
  ret = gnutls_certificate_verify_peers2(session, &status);
  if (0 > ret) {
    goto error;
  }
  if (status & GNUTLS_CERT_INVALID) {
    goto error;
  }
  if (status & GNUTLS_CERT_SIGNER_NOT_FOUND) {
    goto error;
  }
  if (status & GNUTLS_CERT_REVOKED) {
    goto error;
  }
  if (status & GNUTLS_CERT_EXPIRED) {
    goto error;
  }
  if (status & GNUTLS_CERT_NOT_ACTIVATED) {
    goto error;
  }
  if (gnutls_certificate_type_get(session) != GNUTLS_CRT_X509) {
    goto error;
  }
  if (gnutls_x509_crt_init(&cert) < 0) {
    goto error;
  }
  list = gnutls_certificate_get_peers(session, &size);
  if (!list) {
    goto error;
  }
  ret = gnutls_x509_crt_import(cert, &list[0], GNUTLS_X509_FMT_DER);
  if (0 > ret) {
    goto error;
  }
  if (!gnutls_x509_crt_check_hostname(cert, self->host)) {
    goto error;
  }
  gnutls_x509_crt_deinit(cert);
  return 0;
error:
  if (cert) {
    gnutls_x509_crt_deinit (cert);
  }
  return GNUTLS_E_CERTIFICATE_ERROR;
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
  const char *error;
  int status;
  if (!self) {
    goto error;
  }
  gnutls_global_init();
  status = gnutls_init(&self->session, GNUTLS_CLIENT);
  if (GNUTLS_E_SUCCESS != status) {
    goto error;
  }
  status = gnutls_certificate_allocate_credentials(&self->credentials);
  if (GNUTLS_E_SUCCESS != status) {
    goto error;
  }
  gnutls_certificate_set_verify_function(self->credentials,
                                         amqp_ssl_verify);
  status = gnutls_credentials_set(self->session, GNUTLS_CRD_CERTIFICATE,
                                  self->credentials);
  if (GNUTLS_E_SUCCESS != status) {
    goto error;
  }
  gnutls_session_set_ptr(self->session, self);
  status = gnutls_priority_set_direct(self->session, "NORMAL", &error);
  if (GNUTLS_E_SUCCESS != status) {
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
  status = gnutls_certificate_set_x509_trust_file(self->credentials,
           cacert,
           GNUTLS_X509_FMT_PEM);
  if (0 > status) {
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
  status = gnutls_certificate_set_x509_key_file(self->credentials,
           cert,
           key,
           GNUTLS_X509_FMT_PEM);
  if (0 > status) {
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
  amqp_abort("%s is not implemented for GnuTLS", __func__);
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
    gnutls_certificate_set_verify_function(self->credentials,
                                           amqp_ssl_verify);
  } else {
    gnutls_certificate_set_verify_function(self->credentials,
                                           NULL);
  }
}

void
amqp_set_initialize_ssl_library(AMQP_UNUSED amqp_boolean_t do_initialize)
{
}
