/* vim:set ft=c ts=2 sw=2 sts=2 et cindent: */
/*
 * Portions created by Alan Antonuk are Copyright (c) 2012-2014 Alan Antonuk.
 * All Rights Reserved.
 *
 * Portions created by Michael Steinert are Copyright (c) 2012-2014 Michael
 * Steinert. All Rights Reserved.
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
#include "amqp_socket.h"
#include "amqp_hostcheck.h"
#include "amqp_private.h"
#include "threads.h"

#include <ctype.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <stdlib.h>
#include <string.h>


static int initialize_openssl(void);
static int destroy_openssl(void);

static int open_ssl_connections = 0;
static amqp_boolean_t do_initialize_openssl = 1;
static amqp_boolean_t openssl_initialized = 0;

#ifdef ENABLE_THREAD_SAFETY
static unsigned long amqp_ssl_threadid_callback(void);
static void amqp_ssl_locking_callback(int mode, int n, const char *file, int line);

#ifdef _WIN32
static long win32_create_mutex = 0;
static pthread_mutex_t openssl_init_mutex = NULL;
#else
static pthread_mutex_t openssl_init_mutex = PTHREAD_MUTEX_INITIALIZER;
#endif
static pthread_mutex_t *amqp_openssl_lockarray = NULL;
#endif /* ENABLE_THREAD_SAFETY */

struct amqp_ssl_socket_t {
  const struct amqp_socket_class_t *klass;
  SSL_CTX *ctx;
  int sockfd;
  SSL *ssl;
  char *buffer;
  size_t length;
  amqp_boolean_t verify;
  int internal_error;
};

static ssize_t
amqp_ssl_socket_send(void *base,
                     const void *buf,
                     size_t len)
{
  struct amqp_ssl_socket_t *self = (struct amqp_ssl_socket_t *)base;
  ssize_t res;
  if (-1 == self->sockfd) {
    return AMQP_STATUS_SOCKET_CLOSED;
  }

  ERR_clear_error();
  self->internal_error = 0;

  /* This will only return on error, or once the whole buffer has been
   * written to the SSL stream. See SSL_MODE_ENABLE_PARTIAL_WRITE */
  res = SSL_write(self->ssl, buf, len);
  if (0 >= res) {
    self->internal_error = SSL_get_error(self->ssl, res);
    /* TODO: Close connection if it isn't already? */
    /* TODO: Possibly be more intelligent in reporting WHAT went wrong */
    switch (self->internal_error) {
      case SSL_ERROR_ZERO_RETURN:
        res = AMQP_STATUS_CONNECTION_CLOSED;
        break;
      default:
        res = AMQP_STATUS_SSL_ERROR;
        break;
    }
  } else {
    self->internal_error = 0;
    res = AMQP_STATUS_OK;
  }

  return res;
}

static ssize_t
amqp_ssl_socket_writev(void *base,
                       struct iovec *iov,
                       int iovcnt)
{
  struct amqp_ssl_socket_t *self = (struct amqp_ssl_socket_t *)base;
  ssize_t ret = -1;
  char *bufferp;
  size_t bytes;
  int i;
  if (-1 == self->sockfd) {
    return AMQP_STATUS_SOCKET_CLOSED;
  }

  bytes = 0;
  for (i = 0; i < iovcnt; ++i) {
    bytes += iov[i].iov_len;
  }
  if (self->length < bytes) {
    self->buffer = realloc(self->buffer, bytes);
    if (!self->buffer) {
      self->length = 0;
      ret = AMQP_STATUS_NO_MEMORY;
      goto exit;
    }
    self->length = bytes;
  }
  bufferp = self->buffer;
  for (i = 0; i < iovcnt; ++i) {
    memcpy(bufferp, iov[i].iov_base, iov[i].iov_len);
    bufferp += iov[i].iov_len;
  }
  ret = amqp_ssl_socket_send(self, self->buffer, bytes);
exit:
  return ret;
}

static ssize_t
amqp_ssl_socket_recv(void *base,
                     void *buf,
                     size_t len,
                     AMQP_UNUSED int flags)
{
  struct amqp_ssl_socket_t *self = (struct amqp_ssl_socket_t *)base;
  ssize_t received;
  if (-1 == self->sockfd) {
    return AMQP_STATUS_SOCKET_CLOSED;
  }
  ERR_clear_error();
  self->internal_error = 0;

  received = SSL_read(self->ssl, buf, len);
  if (0 >= received) {
    self->internal_error = SSL_get_error(self->ssl, received);
    switch(self->internal_error) {
    case SSL_ERROR_ZERO_RETURN:
      received = AMQP_STATUS_CONNECTION_CLOSED;
      break;
    default:
      received = AMQP_STATUS_SSL_ERROR;
      break;
    }
  }

  return received;
}

static int match(ASN1_STRING *entry_string, const char *string)
{
  unsigned char *utf8_value = NULL, *cp, ch;
  int utf8_length, status = 1;
  utf8_length = ASN1_STRING_to_UTF8(&utf8_value, entry_string);
  if (0 > utf8_length) {
    goto error;
  }
  while (utf8_length > 0 && utf8_value[utf8_length - 1] == 0) {
    --utf8_length;
  }
  if (utf8_length >= 256) {
    goto error;
  }
  if ((size_t)utf8_length != strlen((char *)utf8_value)) {
    goto error;
  }
  for (cp = utf8_value; (ch = *cp) != '\0'; ++cp) {
    if (isascii(ch) && !isprint(ch)) {
      goto error;
    }
  }
  if (!amqp_hostcheck((char *)utf8_value, string)) {
    goto error;
  }
exit:
  OPENSSL_free(utf8_value);
  return status;
error:
  status = 0;
  goto exit;
}

/* Does this hostname match an entry in the subjectAltName extension?
 * returns: 0 if no, 1 if yes, -1 if no subjectAltName entries were found.
 */
static int hostname_matches_subject_alt_name(const char *hostname, X509 *cert)
{
  int found_any_entries = 0;
  int found_match;
  GENERAL_NAME *namePart = NULL;
  STACK_OF(GENERAL_NAME) *san =
    (STACK_OF(GENERAL_NAME)*) X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);

  while (sk_GENERAL_NAME_num(san) > 0)
  {
    namePart = sk_GENERAL_NAME_pop(san);

    if (namePart->type == GEN_DNS) {
      found_any_entries = 1;
      found_match = match(namePart->d.uniformResourceIdentifier, hostname);
      if (found_match)
        return 1;
    }
  }

  return (found_any_entries ? 0 : -1);
}

static int hostname_matches_subject_common_name(const char *hostname, X509 *cert)
{
  X509_NAME *name;
  X509_NAME_ENTRY *name_entry;
  int position;
  ASN1_STRING *entry_string;

  name = X509_get_subject_name(cert);
  position = -1;
  for (;;) {
    position = X509_NAME_get_index_by_NID(name, NID_commonName, position);
    if (position == -1)
      break;
    name_entry = X509_NAME_get_entry(name, position);
    entry_string = X509_NAME_ENTRY_get_data(name_entry);
    if (match(entry_string, hostname))
      return 1;
  }
  return 0;
}

static int
amqp_ssl_socket_verify_hostname(void *base, const char *host)
{
  struct amqp_ssl_socket_t *self = (struct amqp_ssl_socket_t *)base;
  int status = 0;
  X509 *cert;
  int res;
  cert = SSL_get_peer_certificate(self->ssl);
  if (!cert) {
    goto error;
  }
  res = hostname_matches_subject_alt_name(host, cert);
  if (res != 1) {
    res = hostname_matches_subject_common_name(host, cert);
    if (!res)
      goto error;
  }
exit:
  return status;
error:
  status = -1;
  goto exit;
}

static int
amqp_ssl_socket_open(void *base, const char *host, int port, struct timeval *timeout)
{
  struct amqp_ssl_socket_t *self = (struct amqp_ssl_socket_t *)base;
  long result;
  int status;
  if (-1 != self->sockfd) {
    return AMQP_STATUS_SOCKET_INUSE;
  }
  ERR_clear_error();

  self->ssl = SSL_new(self->ctx);
  if (!self->ssl) {
    self->internal_error = ERR_peek_error();
    status = AMQP_STATUS_SSL_ERROR;
    goto exit;
  }

  SSL_set_mode(self->ssl, SSL_MODE_AUTO_RETRY);
  self->sockfd = amqp_open_socket_noblock(host, port, timeout);
  if (0 > self->sockfd) {
    status = self->sockfd;
    self->internal_error = amqp_os_socket_error();
    self->sockfd = -1;
    goto error_out1;
  }

  status = SSL_set_fd(self->ssl, self->sockfd);
  if (!status) {
    self->internal_error = SSL_get_error(self->ssl, status);
    status = AMQP_STATUS_SSL_ERROR;
    goto error_out2;
  }

  status = SSL_connect(self->ssl);
  if (!status) {
    self->internal_error = SSL_get_error(self->ssl, status);
    status = AMQP_STATUS_SSL_CONNECTION_FAILED;
    goto error_out2;
  }

  result = SSL_get_verify_result(self->ssl);
  if (X509_V_OK != result) {
    self->internal_error = result;
    status = AMQP_STATUS_SSL_PEER_VERIFY_FAILED;
    goto error_out3;
  }
  if (self->verify) {
    int verify_status = amqp_ssl_socket_verify_hostname(self, host);
    if (verify_status) {
      self->internal_error = 0;
      status = AMQP_STATUS_SSL_HOSTNAME_VERIFY_FAILED;
      goto error_out3;
    }
  }

  self->internal_error = 0;
  status = AMQP_STATUS_OK;

exit:
  return status;

error_out3:
  SSL_shutdown(self->ssl);
error_out2:
  amqp_os_socket_close(self->sockfd);
  self->sockfd = -1;
error_out1:
  SSL_free(self->ssl);
  self->ssl = NULL;
  goto exit;
}

static int
amqp_ssl_socket_close(void *base)
{
  struct amqp_ssl_socket_t *self = (struct amqp_ssl_socket_t *)base;

  if (-1 == self->sockfd) {
    return AMQP_STATUS_SOCKET_CLOSED;
  }

  SSL_shutdown(self->ssl);
  SSL_free(self->ssl);
  self->ssl = NULL;

  if (amqp_os_socket_close(self->sockfd)) {
    return AMQP_STATUS_SOCKET_ERROR;
  }
  self->sockfd = -1;

  return AMQP_STATUS_OK;
}

static int
amqp_ssl_socket_get_sockfd(void *base)
{
  struct amqp_ssl_socket_t *self = (struct amqp_ssl_socket_t *)base;
  return self->sockfd;
}

static void
amqp_ssl_socket_delete(void *base)
{
  struct amqp_ssl_socket_t *self = (struct amqp_ssl_socket_t *)base;

  if (self) {
    amqp_ssl_socket_close(self);

    SSL_CTX_free(self->ctx);
    free(self->buffer);
    free(self);
  }
  destroy_openssl();
}

static const struct amqp_socket_class_t amqp_ssl_socket_class = {
  amqp_ssl_socket_writev, /* writev */
  amqp_ssl_socket_send, /* send */
  amqp_ssl_socket_recv, /* recv */
  amqp_ssl_socket_open, /* open */
  amqp_ssl_socket_close, /* close */
  amqp_ssl_socket_get_sockfd, /* get_sockfd */
  amqp_ssl_socket_delete /* delete */
};

amqp_socket_t *
amqp_ssl_socket_new(amqp_connection_state_t state)
{
  struct amqp_ssl_socket_t *self = calloc(1, sizeof(*self));
  int status;
  if (!self) {
    return NULL;
  }

  self->sockfd = -1;
  self->klass = &amqp_ssl_socket_class;
  self->verify = 1;

  status = initialize_openssl();
  if (status) {
    goto error;
  }

  self->ctx = SSL_CTX_new(SSLv23_client_method());
  if (!self->ctx) {
    goto error;
  }

  amqp_set_socket(state, (amqp_socket_t *)self);

  return (amqp_socket_t *)self;
error:
  amqp_ssl_socket_delete((amqp_socket_t *)self);
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
  status = SSL_CTX_load_verify_locations(self->ctx, cacert, NULL);
  if (1 != status) {
    return AMQP_STATUS_SSL_ERROR;
  }
  return AMQP_STATUS_OK;
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
  status = SSL_CTX_use_certificate_chain_file(self->ctx, cert);
  if (1 != status) {
    return AMQP_STATUS_SSL_ERROR;
  }
  status = SSL_CTX_use_PrivateKey_file(self->ctx, key,
                                       SSL_FILETYPE_PEM);
  if (1 != status) {
    return AMQP_STATUS_SSL_ERROR;
  }
  return AMQP_STATUS_OK;
}

static int
password_cb(AMQP_UNUSED char *buffer,
            AMQP_UNUSED int length,
            AMQP_UNUSED int rwflag,
            AMQP_UNUSED void *user_data)
{
  amqp_abort("rabbitmq-c does not support password protected keys");
  return 0;
}

int
amqp_ssl_socket_set_key_buffer(amqp_socket_t *base,
                               const char *cert,
                               const void *key,
                               size_t n)
{
  int status = AMQP_STATUS_OK;
  BIO *buf = NULL;
  RSA *rsa = NULL;
  struct amqp_ssl_socket_t *self;
  if (base->klass != &amqp_ssl_socket_class) {
    amqp_abort("<%p> is not of type amqp_ssl_socket_t", base);
  }
  self = (struct amqp_ssl_socket_t *)base;
  status = SSL_CTX_use_certificate_chain_file(self->ctx, cert);
  if (1 != status) {
    return AMQP_STATUS_SSL_ERROR;
  }
  buf = BIO_new_mem_buf((void *)key, n);
  if (!buf) {
    goto error;
  }
  rsa = PEM_read_bio_RSAPrivateKey(buf, NULL, password_cb, NULL);
  if (!rsa) {
    goto error;
  }
  status = SSL_CTX_use_RSAPrivateKey(self->ctx, rsa);
  if (1 != status) {
    goto error;
  }
exit:
  BIO_vfree(buf);
  RSA_free(rsa);
  return status;
error:
  status = AMQP_STATUS_SSL_ERROR;
  goto exit;
}

int
amqp_ssl_socket_set_cert(amqp_socket_t *base,
                         const char *cert)
{
  int status;
  struct amqp_ssl_socket_t *self;
  if (base->klass != &amqp_ssl_socket_class) {
    amqp_abort("<%p> is not of type amqp_ssl_socket_t", base);
  }
  self = (struct amqp_ssl_socket_t *)base;
  status = SSL_CTX_use_certificate_chain_file(self->ctx, cert);
  if (1 != status) {
    return AMQP_STATUS_SSL_ERROR;
  }
  return AMQP_STATUS_OK;
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
  self->verify = verify;
}

void
amqp_set_initialize_ssl_library(amqp_boolean_t do_initialize)
{
  if (!openssl_initialized) {
    do_initialize_openssl = do_initialize;
  }
}

#ifdef ENABLE_THREAD_SAFETY
unsigned long
amqp_ssl_threadid_callback(void)
{
  return (unsigned long)pthread_self();
}

void
amqp_ssl_locking_callback(int mode, int n,
                          AMQP_UNUSED const char *file,
                          AMQP_UNUSED int line)
{
  if (mode & CRYPTO_LOCK) {
    if (pthread_mutex_lock(&amqp_openssl_lockarray[n])) {
      amqp_abort("Runtime error: Failure in trying to lock OpenSSL mutex");
    }
  } else {
    if (pthread_mutex_unlock(&amqp_openssl_lockarray[n])) {
      amqp_abort("Runtime error: Failure in trying to unlock OpenSSL mutex");
    }
  }
}
#endif /* ENABLE_THREAD_SAFETY */

static int
initialize_openssl(void)
{
#ifdef ENABLE_THREAD_SAFETY
#ifdef _WIN32
  /* No such thing as PTHREAD_INITIALIZE_MUTEX macro on Win32, so we use this */
  if (NULL == openssl_init_mutex) {
    while (InterlockedExchange(&win32_create_mutex, 1) == 1)
      /* Loop, someone else is holding this lock */ ;

    if (NULL == openssl_init_mutex) {
      if (pthread_mutex_init(&openssl_init_mutex, NULL)) {
        return -1;
      }
    }
    InterlockedExchange(&win32_create_mutex, 0);
  }
#endif /* _WIN32 */

  if (pthread_mutex_lock(&openssl_init_mutex)) {
    return -1;
  }
#endif /* ENABLE_THREAD_SAFETY */
  if (do_initialize_openssl) {
#ifdef ENABLE_THREAD_SAFETY
    if (NULL == amqp_openssl_lockarray) {
      int i = 0;
      amqp_openssl_lockarray = calloc(CRYPTO_num_locks(), sizeof(pthread_mutex_t));
      if (!amqp_openssl_lockarray) {
        pthread_mutex_unlock(&openssl_init_mutex);
        return -1;
      }
      for (i = 0; i < CRYPTO_num_locks(); ++i) {
        if (pthread_mutex_init(&amqp_openssl_lockarray[i], NULL)) {
          free(amqp_openssl_lockarray);
          amqp_openssl_lockarray = NULL;
          pthread_mutex_unlock(&openssl_init_mutex);
          return -1;
        }
      }
    }

    if (0 == open_ssl_connections) {
      CRYPTO_set_id_callback(amqp_ssl_threadid_callback);
      CRYPTO_set_locking_callback(amqp_ssl_locking_callback);
    }
#endif /* ENABLE_THREAD_SAFETY */

    if (!openssl_initialized) {
      OPENSSL_config(NULL);

      SSL_library_init();
      SSL_load_error_strings();

      openssl_initialized = 1;
    }
  }

  ++open_ssl_connections;

#ifdef ENABLE_THREAD_SAFETY
  pthread_mutex_unlock(&openssl_init_mutex);
#endif /* ENABLE_THREAD_SAFETY */
  return 0;
}

static int
destroy_openssl(void)
{
#ifdef ENABLE_THREAD_SAFETY
  if (pthread_mutex_lock(&openssl_init_mutex)) {
    return -1;
  }
#endif /* ENABLE_THREAD_SAFETY */

  if (open_ssl_connections > 0) {
    --open_ssl_connections;
  }

#ifdef ENABLE_THREAD_SAFETY
  if (0 == open_ssl_connections && do_initialize_openssl) {
    /* Unsetting these allows the rabbitmq-c library to be unloaded
     * safely. We do leak the amqp_openssl_lockarray. Which is only
     * an issue if you repeatedly unload and load the library
     */
    CRYPTO_set_locking_callback(NULL);
    CRYPTO_set_id_callback(NULL);
  }

  pthread_mutex_unlock(&openssl_init_mutex);
#endif /* ENABLE_THREAD_SAFETY */
  return 0;
}
