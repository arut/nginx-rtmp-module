/* vim:set ft=c ts=2 sw=2 sts=2 et cindent: */
/*
 * ***** BEGIN LICENSE BLOCK *****
 * Version: MIT
 *
 * Portions created by Alan Antonuk are Copyright (c) 2012-2014
 * Alan Antonuk. All Rights Reserved.
 *
 * Portions created by VMware are Copyright (c) 2007-2012 VMware, Inc.
 * All Rights Reserved.
 *
 * Portions created by Tony Garnock-Jones are Copyright (c) 2009-2010
 * VMware, Inc. and Tony Garnock-Jones. All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 * ***** END LICENSE BLOCK *****
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "amqp_private.h"
#include "amqp_timer.h"

#include <assert.h>
#include <limits.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <errno.h>

#ifdef _WIN32
# ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
# endif
# include <Winsock2.h>
# include <ws2tcpip.h>
#else
# include <sys/types.h>      /* On older BSD this must come before net includes */
# include <netinet/in.h>
# include <netinet/tcp.h>
# include <sys/socket.h>
# include <netdb.h>
# include <sys/uio.h>
# include <fcntl.h>
# include <poll.h>
# include <unistd.h>
#endif

#ifdef _WIN32
# define poll(fdarray, nfds, timeout) WSAPoll(fdarray, nfds, timeout)
#endif

static int
amqp_os_socket_init(void)
{
#ifdef _WIN32
  static called_wsastartup = 0;
  if (!called_wsastartup) {
    WSADATA data;
    int res = WSAStartup(0x0202, &data);
    if (res) {
      return AMQP_STATUS_TCP_SOCKETLIB_INIT_ERROR;
    }

    called_wsastartup = 1;
  }
  return AMQP_STATUS_OK;

#else
  return AMQP_STATUS_OK;
#endif
}

static int
amqp_os_socket_socket(int domain, int type, int protocol)
{
#ifdef _WIN32
    /*
      This cast is to squash warnings on Win64, see:
      http://stackoverflow.com/questions/1953639/is-it-safe-to-cast-socket-to-int-under-win64
    */
  return (int)socket(domain, type, protocol);
#else
  int flags;

  int s = socket(domain, type, protocol);
  if (s < 0) {
    return s;
  }

  /* Always enable CLOEXEC on the socket */
  flags = fcntl(s, F_GETFD);
  if (flags == -1
      || fcntl(s, F_SETFD, (long)(flags | FD_CLOEXEC)) == -1) {
    int e = errno;
    close(s);
    errno = e;
    return -1;
  }

  return s;

#endif
}

static int
amqp_os_socket_setsockopt(int sock, int level, int optname,
                       const void *optval, size_t optlen)
{
#ifdef _WIN32
  /* the winsock setsockopt function has its 4th argument as a
     const char * */
  return setsockopt(sock, level, optname, (const char *)optval, optlen);
#else
  return setsockopt(sock, level, optname, optval, optlen);
#endif
}

static int
amqp_os_socket_setsockblock(int sock, int block)
{

#ifdef _WIN32
  int nonblock = !block;
  if (NO_ERROR != ioctlsocket(sock, FIONBIO, &nonblock)) {
    return AMQP_STATUS_SOCKET_ERROR;
  } else {
    return AMQP_STATUS_OK;
  }
#else
  long arg;

  if ((arg = fcntl(sock, F_GETFL, NULL)) < 0) {
     return AMQP_STATUS_SOCKET_ERROR;
  }

  if (block) {
    arg &= (~O_NONBLOCK);
  } else {
    arg |= O_NONBLOCK;
  }

  if (fcntl(sock, F_SETFL, arg) < 0) {
    return AMQP_STATUS_SOCKET_ERROR;
  }

  return AMQP_STATUS_OK;
#endif
}


int
amqp_os_socket_error(void)
{
#ifdef _WIN32
  return WSAGetLastError();
#else
  return errno;
#endif
}

int
amqp_os_socket_close(int sockfd)
{
#ifdef _WIN32
  return closesocket(sockfd);
#else
  return close(sockfd);
#endif
}

ssize_t
amqp_socket_writev(amqp_socket_t *self, struct iovec *iov, int iovcnt)
{
  assert(self);
  assert(self->klass->writev);
  return self->klass->writev(self, iov, iovcnt);
}

ssize_t
amqp_socket_send(amqp_socket_t *self, const void *buf, size_t len)
{
  assert(self);
  assert(self->klass->send);
  return self->klass->send(self, buf, len);
}

ssize_t
amqp_socket_recv(amqp_socket_t *self, void *buf, size_t len, int flags)
{
  assert(self);
  assert(self->klass->recv);
  return self->klass->recv(self, buf, len, flags);
}

int
amqp_socket_open(amqp_socket_t *self, const char *host, int port)
{
  assert(self);
  assert(self->klass->open);
  return self->klass->open(self, host, port, NULL);
}

int
amqp_socket_open_noblock(amqp_socket_t *self, const char *host, int port, struct timeval *timeout)
{
  assert(self);
  assert(self->klass->open);
  return self->klass->open(self, host, port, timeout);
}

int
amqp_socket_close(amqp_socket_t *self)
{
  assert(self);
  assert(self->klass->close);
  return self->klass->close(self);
}

void
amqp_socket_delete(amqp_socket_t *self)
{
  if (self) {
    assert(self->klass->delete);
    self->klass->delete(self);
  }
}

int
amqp_socket_get_sockfd(amqp_socket_t *self)
{
  assert(self);
  assert(self->klass->get_sockfd);
  return self->klass->get_sockfd(self);
}

int
amqp_open_socket(char const *hostname,
                 int portnumber)
{
  return amqp_open_socket_noblock(hostname, portnumber, NULL);
}

int amqp_open_socket_noblock(char const *hostname,
                     int portnumber,
                     struct timeval *timeout)
{
  struct addrinfo hint;
  struct addrinfo *address_list;
  struct addrinfo *addr;
  char portnumber_string[33];
  int sockfd = -1;
  int last_error = AMQP_STATUS_OK;
  int one = 1; /* for setsockopt */
  int res;
  int timer_error;
  amqp_timer_t timer;

  AMQP_INIT_TIMER(timer)

  if (timeout && (timeout->tv_sec < 0 || timeout->tv_usec < 0 ||
      INT_MAX < ((uint64_t)timeout->tv_sec * AMQP_MS_PER_S +
      (uint64_t)timeout->tv_usec / AMQP_US_PER_MS))) {
    return AMQP_STATUS_INVALID_PARAMETER;
  }

  last_error = amqp_os_socket_init();
  if (AMQP_STATUS_OK != last_error) {
    return last_error;
  }

  memset(&hint, 0, sizeof(hint));
  hint.ai_family = PF_UNSPEC; /* PF_INET or PF_INET6 */
  hint.ai_socktype = SOCK_STREAM;
  hint.ai_protocol = IPPROTO_TCP;

  (void)sprintf(portnumber_string, "%d", portnumber);

  last_error = getaddrinfo(hostname, portnumber_string, &hint, &address_list);

  if (0 != last_error) {
    return AMQP_STATUS_HOSTNAME_RESOLUTION_FAILED;
  }

  for (addr = address_list; addr; addr = addr->ai_next) {
    if (-1 != sockfd) {
      amqp_os_socket_close(sockfd);
    }

    sockfd = amqp_os_socket_socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);

    if (-1 == sockfd) {
      last_error = AMQP_STATUS_SOCKET_ERROR;
      continue;
    }

#ifdef SO_NOSIGPIPE
    if (0 != amqp_os_socket_setsockopt(sockfd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one))) {
      last_error = AMQP_STATUS_SOCKET_ERROR;
      continue;
    }
#endif /* SO_NOSIGPIPE */

    if (0 != amqp_os_socket_setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one))) {
      last_error = AMQP_STATUS_SOCKET_ERROR;
      continue;
    }

    if (timeout) {
      /* Trying to connect with timeout, set socket to non-blocking mode */
      if (AMQP_STATUS_OK != amqp_os_socket_setsockblock(sockfd, 0)) {
        last_error = AMQP_STATUS_SOCKET_ERROR;
        continue;
      }

      res = connect(sockfd, addr->ai_addr, addr->ai_addrlen);

      if (0 == res) {
        /* Connected immediately, set to blocking mode again */
        if (AMQP_STATUS_OK != amqp_os_socket_setsockblock(sockfd, 1)) {
          last_error = AMQP_STATUS_SOCKET_ERROR;
          continue;
        }

        last_error = AMQP_STATUS_OK;
        break;
      }

#ifdef _WIN32
      if (WSAEWOULDBLOCK == amqp_os_socket_error()) {
#else
      if (EINPROGRESS == amqp_os_socket_error()) {
#endif

        while(1) {
          struct pollfd pfd;
          int timeout_ms;

          pfd.fd = sockfd;
          pfd.events = POLLERR | POLLOUT;
          pfd.revents = 0;

          timer_error = amqp_timer_update(&timer, timeout);

          if (timer_error < 0) {
            last_error = timer_error;
            break;
          }

          timeout_ms = timer.tv.tv_sec * AMQP_MS_PER_S +
              timer.tv.tv_usec / AMQP_US_PER_MS;
          /* Win32 requires except_fds to be passed to detect connection
           * failure. Other platforms only need write_fds, passing except_fds
           * seems to be harmless otherwise
           */
          res = poll(&pfd, 1, timeout_ms);

          if (res > 0) {
            int result;
            socklen_t result_len = sizeof(result);

            if (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &result, &result_len) < 0) {
              last_error = AMQP_STATUS_SOCKET_ERROR;
              break;
            }

            if (result != 0) {
              last_error = AMQP_STATUS_SOCKET_ERROR;
              break;
            }

            /* socket is ready to be written to, set to blocking mode again */
            if (AMQP_STATUS_OK != amqp_os_socket_setsockblock(sockfd, 1)) {
              last_error = AMQP_STATUS_SOCKET_ERROR;
              continue;
            }

            last_error = AMQP_STATUS_OK;
            break;
          } else if (0 == res) {
            /* Timed out - return */
            last_error = AMQP_STATUS_TIMEOUT;
            break;
          } else if (errno == EINTR) {
            /* Try again */
            continue;
          } else {
            /* Error connecting */
            last_error = AMQP_STATUS_SOCKET_ERROR;
            break;
          }
        } /* end while(1) loop */

        if (last_error == AMQP_STATUS_OK
            || last_error == AMQP_STATUS_TIMEOUT
            || last_error == AMQP_STATUS_TIMER_FAILURE) {
          /* Exit for loop on timer errors or when connection established */
          break;
        }

      } else {
        /* Error connecting */
        last_error = AMQP_STATUS_SOCKET_ERROR;
        break;

      }

    } else {
      /* Connect in blocking mode */
      if (0 != connect(sockfd, addr->ai_addr, addr->ai_addrlen)) {
        last_error = AMQP_STATUS_SOCKET_ERROR;
        continue;
      } else {
        last_error = AMQP_STATUS_OK;
        break;
      }
    }
  }

  freeaddrinfo(address_list);
  if (last_error != AMQP_STATUS_OK) {
    if (-1 != sockfd) {
      amqp_os_socket_close(sockfd);
    }

    return last_error;
  }

  return sockfd;
}

int amqp_send_header(amqp_connection_state_t state)
{
  static const uint8_t header[8] = { 'A', 'M', 'Q', 'P', 0,
                                     AMQP_PROTOCOL_VERSION_MAJOR,
                                     AMQP_PROTOCOL_VERSION_MINOR,
                                     AMQP_PROTOCOL_VERSION_REVISION
                                   };
  return amqp_socket_send(state->socket, header, sizeof(header));
}

static amqp_bytes_t sasl_method_name(amqp_sasl_method_enum method)
{
  amqp_bytes_t res;

  switch (method) {
  case AMQP_SASL_METHOD_PLAIN:
    res.bytes = "PLAIN";
    res.len = 5;
    break;

  default:
    amqp_abort("Invalid SASL method: %d", (int) method);
  }

  return res;
}

static amqp_bytes_t sasl_response(amqp_pool_t *pool,
                                  amqp_sasl_method_enum method,
                                  va_list args)
{
  amqp_bytes_t response;

  switch (method) {
  case AMQP_SASL_METHOD_PLAIN: {
    char *username = va_arg(args, char *);
    size_t username_len = strlen(username);
    char *password = va_arg(args, char *);
    size_t password_len = strlen(password);
    char *response_buf;

    amqp_pool_alloc_bytes(pool, strlen(username) + strlen(password) + 2, &response);
    if (response.bytes == NULL)
      /* We never request a zero-length block, because of the +2
         above, so a NULL here really is ENOMEM. */
    {
      return response;
    }

    response_buf = response.bytes;
    response_buf[0] = 0;
    memcpy(response_buf + 1, username, username_len);
    response_buf[username_len + 1] = 0;
    memcpy(response_buf + username_len + 2, password, password_len);
    break;
  }
  default:
    amqp_abort("Invalid SASL method: %d", (int) method);
  }

  return response;
}

amqp_boolean_t amqp_frames_enqueued(amqp_connection_state_t state)
{
  return (state->first_queued_frame != NULL);
}

/*
 * Check to see if we have data in our buffer. If this returns 1, we
 * will avoid an immediate blocking read in amqp_simple_wait_frame.
 */
amqp_boolean_t amqp_data_in_buffer(amqp_connection_state_t state)
{
  return (state->sock_inbound_offset < state->sock_inbound_limit);
}

static int consume_one_frame(amqp_connection_state_t state, amqp_frame_t *decoded_frame)
{
  int res;

  amqp_bytes_t buffer;
  buffer.len = state->sock_inbound_limit - state->sock_inbound_offset;
  buffer.bytes = ((char *) state->sock_inbound_buffer.bytes) + state->sock_inbound_offset;

  res = amqp_handle_input(state, buffer, decoded_frame);
  if (res < 0) {
    return res;
  }

  state->sock_inbound_offset += res;

  return AMQP_STATUS_OK;
}


static int recv_with_timeout(amqp_connection_state_t state, uint64_t start, struct timeval *timeout)
{
  int res;

  if (timeout) {
    int fd;

    fd = amqp_get_sockfd(state);
    if (-1 == fd) {
      return AMQP_STATUS_CONNECTION_CLOSED;
    }

    if (INT_MAX < (uint64_t)timeout->tv_sec * AMQP_MS_PER_S +
        (uint64_t)timeout->tv_usec / AMQP_US_PER_MS) {
      return AMQP_STATUS_INVALID_PARAMETER;
    }

    while (1) {
      struct pollfd pfd;
      int timeout_ms;

      pfd.fd = fd;
      pfd.events = POLLIN;
      pfd.revents = 0;

      timeout_ms = timeout->tv_sec * AMQP_MS_PER_S +
          timeout->tv_usec / AMQP_US_PER_MS;

      res = poll(&pfd, 1, timeout_ms);

      if (0 < res) {
        break;
      } else if (0 == res) {
        return AMQP_STATUS_TIMEOUT;
      } else if (-1 == res) {
        if (EINTR == errno) {
          if (timeout) {
            uint64_t end_timestamp;
            uint64_t time_left;
            uint64_t current_timestamp = amqp_get_monotonic_timestamp();
            if (0 == current_timestamp) {
              return AMQP_STATUS_TIMER_FAILURE;
            }
            end_timestamp = start +
              (uint64_t)timeout->tv_sec * AMQP_NS_PER_S +
              (uint64_t)timeout->tv_usec * AMQP_NS_PER_US;
            if (current_timestamp > end_timestamp) {
              return AMQP_STATUS_TIMEOUT;
            }

            time_left = end_timestamp - current_timestamp;

            timeout->tv_sec = time_left / AMQP_NS_PER_S;
            timeout->tv_usec = (time_left % AMQP_NS_PER_S) / AMQP_NS_PER_US;
          }
          continue;
        }
        return AMQP_STATUS_SOCKET_ERROR;
      }
    }
  }

  res = amqp_socket_recv(state->socket, state->sock_inbound_buffer.bytes,
                         state->sock_inbound_buffer.len, 0);

  if (res < 0) {
    return res;
  }

  state->sock_inbound_limit = res;
  state->sock_inbound_offset = 0;

  if (amqp_heartbeat_enabled(state)) {
    uint64_t current_time = amqp_get_monotonic_timestamp();
    if (0 == current_time) {
      return AMQP_STATUS_TIMER_FAILURE;
    }
    state->next_recv_heartbeat = amqp_calc_next_recv_heartbeat(state, current_time);
  }

  return AMQP_STATUS_OK;
}

int amqp_try_recv(amqp_connection_state_t state, uint64_t current_time)
{
  struct timeval tv;

  while (amqp_data_in_buffer(state)) {
    amqp_frame_t frame;
    int res = consume_one_frame(state, &frame);

    if (AMQP_STATUS_OK != res) {
      return res;
    }

    if (frame.frame_type != 0) {
      amqp_pool_t *channel_pool;
      amqp_frame_t *frame_copy;
      amqp_link_t *link;

      channel_pool = amqp_get_or_create_channel_pool(state, frame.channel);
      if (NULL == channel_pool) {
        return AMQP_STATUS_NO_MEMORY;
      }

      frame_copy = amqp_pool_alloc(channel_pool, sizeof(amqp_frame_t));
      link = amqp_pool_alloc(channel_pool, sizeof(amqp_link_t));

      if (frame_copy == NULL || link == NULL) {
        return AMQP_STATUS_NO_MEMORY;
      }

      *frame_copy = frame;

      link->next = NULL;
      link->data = frame_copy;

      if (state->last_queued_frame == NULL) {
        state->first_queued_frame = link;
      } else {
        state->last_queued_frame->next = link;
      }
      state->last_queued_frame = link;
    }
  }

  memset(&tv, 0, sizeof(struct timeval));
  tv.tv_sec = 0;
  tv.tv_usec = 0;

  return recv_with_timeout(state, current_time, &tv);
}

static int wait_frame_inner(amqp_connection_state_t state,
                            amqp_frame_t *decoded_frame,
                            struct timeval *timeout)
{
  uint64_t current_timestamp = 0;
  uint64_t timeout_timestamp = 0;
  uint64_t next_timestamp = 0;
  struct timeval tv;
  struct timeval *tvp = NULL;

  if (timeout && (timeout->tv_sec < 0 || timeout->tv_usec < 0)) {
    return AMQP_STATUS_INVALID_PARAMETER;
  }

  while (1) {
    int res;

    while (amqp_data_in_buffer(state)) {
      res = consume_one_frame(state, decoded_frame);

      if (AMQP_STATUS_OK != res) {
        return res;
      }

      if (AMQP_FRAME_HEARTBEAT == decoded_frame->frame_type) {
        amqp_maybe_release_buffers_on_channel(state, 0);
        continue;
      }

      if (decoded_frame->frame_type != 0) {
        /* Complete frame was read. Return it. */
        return AMQP_STATUS_OK;
      }
    }

beginrecv:
    if (timeout || amqp_heartbeat_enabled(state)) {
      uint64_t ns_until_next_timeout;

      current_timestamp = amqp_get_monotonic_timestamp();
      if (0 == current_timestamp) {
        return AMQP_STATUS_TIMER_FAILURE;
      }

      if (amqp_heartbeat_enabled(state) && current_timestamp > state->next_send_heartbeat) {
        amqp_frame_t heartbeat;
        heartbeat.channel = 0;
        heartbeat.frame_type = AMQP_FRAME_HEARTBEAT;

        res = amqp_send_frame(state, &heartbeat);
        if (AMQP_STATUS_OK != res) {
          return res;
        }

        current_timestamp = amqp_get_monotonic_timestamp();
        if (0 == current_timestamp) {
          return AMQP_STATUS_TIMER_FAILURE;
        }
      }

      if (timeout) {
        if (0 == timeout_timestamp) {
          timeout_timestamp = current_timestamp +
            (uint64_t)timeout->tv_sec * AMQP_NS_PER_S +
            (uint64_t)timeout->tv_usec * AMQP_NS_PER_US;
        }

        if (current_timestamp > timeout_timestamp) {
          return AMQP_STATUS_TIMEOUT;
        }
      }


      if (amqp_heartbeat_enabled(state)) {
        if (current_timestamp > state->next_recv_heartbeat) {
          state->next_recv_heartbeat = current_timestamp;
        }
        next_timestamp = (state->next_recv_heartbeat < state->next_send_heartbeat ?
            state->next_recv_heartbeat :
            state->next_send_heartbeat);
        if (timeout) {
          next_timestamp = (timeout_timestamp < next_timestamp ?
              timeout_timestamp : next_timestamp);
        }
      } else if (timeout) {
        next_timestamp = timeout_timestamp;
      } else {
        amqp_abort("Internal error: both timeout == NULL && state->heartbeat == 0");
      }

      ns_until_next_timeout = next_timestamp - current_timestamp;

      memset(&tv, 0, sizeof(struct timeval));
      tv.tv_sec = ns_until_next_timeout / AMQP_NS_PER_S;
      tv.tv_usec = (ns_until_next_timeout % AMQP_NS_PER_S) / AMQP_NS_PER_US;

      tvp = &tv;
    }

    res = recv_with_timeout(state, current_timestamp, tvp);

    if (AMQP_STATUS_TIMEOUT == res) {
      if (next_timestamp == state->next_recv_heartbeat) {
        amqp_socket_close(state->socket);
        return AMQP_STATUS_HEARTBEAT_TIMEOUT;
      } else if (next_timestamp == timeout_timestamp) {
        return AMQP_STATUS_TIMEOUT;
      } else if (next_timestamp == state->next_send_heartbeat) {
        /* send heartbeat happens before we do recv_with_timeout */
        goto beginrecv;
      } else {
        amqp_abort("Internal error: unable to determine timeout reason");
      }
    } else if (AMQP_STATUS_OK != res) {
      return res;
    }
  }
}

static amqp_link_t * amqp_create_link_for_frame(amqp_connection_state_t state, amqp_frame_t *frame)
{
  amqp_link_t *link;
  amqp_frame_t *frame_copy;

  amqp_pool_t *channel_pool = amqp_get_or_create_channel_pool(state, frame->channel);

  if (NULL == channel_pool) {
    return NULL;
  }

  link = amqp_pool_alloc(channel_pool, sizeof(amqp_link_t));
  frame_copy = amqp_pool_alloc(channel_pool, sizeof(amqp_frame_t));

  if (NULL == link || NULL == frame_copy) {
    return NULL;
  }

  *frame_copy = *frame;
  link->data = frame_copy;

  return link;
}

int amqp_queue_frame(amqp_connection_state_t state, amqp_frame_t *frame)
{
  amqp_link_t *link = amqp_create_link_for_frame(state, frame);
  if (NULL == link) {
    return AMQP_STATUS_NO_MEMORY;
  }

  if (NULL == state->first_queued_frame) {
    state->first_queued_frame = link;
  } else {
    state->last_queued_frame->next = link;
  }

  link->next = NULL;
  state->last_queued_frame = link;

  return AMQP_STATUS_OK;
}

int amqp_put_back_frame(amqp_connection_state_t state, amqp_frame_t *frame)
{
  amqp_link_t *link = amqp_create_link_for_frame(state, frame);
  if (NULL == link) {
    return AMQP_STATUS_NO_MEMORY;
  }

  if (NULL == state->first_queued_frame) {
    state->first_queued_frame = link;
    state->last_queued_frame = link;
    link->next = NULL;
  } else {
    link->next = state->first_queued_frame;
    state->first_queued_frame = link;
  }

  return AMQP_STATUS_OK;
}

int amqp_simple_wait_frame_on_channel(amqp_connection_state_t state,
                                      amqp_channel_t channel,
                                      amqp_frame_t *decoded_frame)
{
  amqp_frame_t *frame_ptr;
  amqp_link_t *cur;
  int res;

  for (cur = state->first_queued_frame; NULL != cur; cur = cur->next) {
    frame_ptr = cur->data;

    if (channel == frame_ptr->channel) {
      state->first_queued_frame = cur->next;
      if (NULL == state->first_queued_frame) {
        state->last_queued_frame = NULL;
      }

      *decoded_frame = *frame_ptr;

      return AMQP_STATUS_OK;
    }
  }

  while (1) {
    res = wait_frame_inner(state, decoded_frame, NULL);

    if (AMQP_STATUS_OK != res) {
      return res;
    }

    if (channel == decoded_frame->channel) {
      return AMQP_STATUS_OK;
    } else {
      res = amqp_queue_frame(state, decoded_frame);
      if (res != AMQP_STATUS_OK) {
        return res;
      }
    }
  }
}

int amqp_simple_wait_frame(amqp_connection_state_t state,
                           amqp_frame_t *decoded_frame)
{
  return amqp_simple_wait_frame_noblock(state, decoded_frame, NULL);
}

int amqp_simple_wait_frame_noblock(amqp_connection_state_t state,
                                   amqp_frame_t *decoded_frame,
                                   struct timeval *timeout)
{
  if (state->first_queued_frame != NULL) {
    amqp_frame_t *f = (amqp_frame_t *) state->first_queued_frame->data;
    state->first_queued_frame = state->first_queued_frame->next;
    if (state->first_queued_frame == NULL) {
      state->last_queued_frame = NULL;
    }
    *decoded_frame = *f;
    return AMQP_STATUS_OK;
  } else {
    return wait_frame_inner(state, decoded_frame, timeout);
  }
}

int amqp_simple_wait_method(amqp_connection_state_t state,
                            amqp_channel_t expected_channel,
                            amqp_method_number_t expected_method,
                            amqp_method_t *output)
{
  amqp_frame_t frame;
  int res = amqp_simple_wait_frame(state, &frame);
  if (AMQP_STATUS_OK != res) {
    return res;
  }

  if (frame.channel != expected_channel
      || frame.frame_type != AMQP_FRAME_METHOD
      || frame.payload.method.id != expected_method) {
    amqp_socket_close(state->socket);
    return AMQP_STATUS_WRONG_METHOD;
  }
  *output = frame.payload.method;
  return AMQP_STATUS_OK;
}

int amqp_send_method(amqp_connection_state_t state,
                     amqp_channel_t channel,
                     amqp_method_number_t id,
                     void *decoded)
{
  amqp_frame_t frame;

  frame.frame_type = AMQP_FRAME_METHOD;
  frame.channel = channel;
  frame.payload.method.id = id;
  frame.payload.method.decoded = decoded;
  return amqp_send_frame(state, &frame);
}

static int amqp_id_in_reply_list( amqp_method_number_t expected, amqp_method_number_t *list )
{
  while ( *list != 0 ) {
    if ( *list == expected ) {
      return 1;
    }
    list++;
  }
  return 0;
}

amqp_rpc_reply_t amqp_simple_rpc(amqp_connection_state_t state,
                                 amqp_channel_t channel,
                                 amqp_method_number_t request_id,
                                 amqp_method_number_t *expected_reply_ids,
                                 void *decoded_request_method)
{
  int status;
  amqp_rpc_reply_t result;

  memset(&result, 0, sizeof(result));

  status = amqp_send_method(state, channel, request_id, decoded_request_method);
  if (status < 0) {
    result.reply_type = AMQP_RESPONSE_LIBRARY_EXCEPTION;
    result.library_error = status;
    return result;
  }

  {
    amqp_frame_t frame;

retry:
    status = wait_frame_inner(state, &frame, NULL);
    if (status < 0) {
      result.reply_type = AMQP_RESPONSE_LIBRARY_EXCEPTION;
      result.library_error = status;
      return result;
    }

    /*
     * We store the frame for later processing unless it's something
     * that directly affects us here, namely a method frame that is
     * either
     *  - on the channel we want, and of the expected type, or
     *  - on the channel we want, and a channel.close frame, or
     *  - on channel zero, and a connection.close frame.
     */
    if (!((frame.frame_type == AMQP_FRAME_METHOD)
          && (
            ((frame.channel == channel)
             && (amqp_id_in_reply_list(frame.payload.method.id, expected_reply_ids)
                 || (frame.payload.method.id == AMQP_CHANNEL_CLOSE_METHOD)))
            ||
            ((frame.channel == 0)
             && (frame.payload.method.id == AMQP_CONNECTION_CLOSE_METHOD))
          )
         )) {
      amqp_pool_t *channel_pool;
      amqp_frame_t *frame_copy;
      amqp_link_t *link;

      channel_pool = amqp_get_or_create_channel_pool(state, frame.channel);
      if (NULL == channel_pool) {
        result.reply_type = AMQP_RESPONSE_LIBRARY_EXCEPTION;
        result.library_error = AMQP_STATUS_NO_MEMORY;
        return result;
      }

      frame_copy = amqp_pool_alloc(channel_pool, sizeof(amqp_frame_t));
      link = amqp_pool_alloc(channel_pool, sizeof(amqp_link_t));

      if (frame_copy == NULL || link == NULL) {
        result.reply_type = AMQP_RESPONSE_LIBRARY_EXCEPTION;
        result.library_error = AMQP_STATUS_NO_MEMORY;
        return result;
      }

      *frame_copy = frame;

      link->next = NULL;
      link->data = frame_copy;

      if (state->last_queued_frame == NULL) {
        state->first_queued_frame = link;
      } else {
        state->last_queued_frame->next = link;
      }
      state->last_queued_frame = link;

      goto retry;
    }

    result.reply_type = (amqp_id_in_reply_list(frame.payload.method.id, expected_reply_ids))
                        ? AMQP_RESPONSE_NORMAL
                        : AMQP_RESPONSE_SERVER_EXCEPTION;

    result.reply = frame.payload.method;
    return result;
  }
}

void *amqp_simple_rpc_decoded(amqp_connection_state_t state,
                              amqp_channel_t channel,
                              amqp_method_number_t request_id,
                              amqp_method_number_t reply_id,
                              void *decoded_request_method)
{
  amqp_method_number_t replies[2];

  replies[0] = reply_id;
  replies[1] = 0;

  state->most_recent_api_result = amqp_simple_rpc(state, channel,
                                  request_id, replies,
                                  decoded_request_method);
  if (state->most_recent_api_result.reply_type == AMQP_RESPONSE_NORMAL) {
    return state->most_recent_api_result.reply.decoded;
  } else {
    return NULL;
  }
}

amqp_rpc_reply_t amqp_get_rpc_reply(amqp_connection_state_t state)
{
  return state->most_recent_api_result;
}


static int amqp_table_contains_entry(const amqp_table_t *table,
                                     const amqp_table_entry_t *entry)
{
  int i;
  amqp_table_entry_t *current_entry;

  assert(table != NULL);
  assert(entry != NULL);

  current_entry = table->entries;

  for (i = 0; i < table->num_entries; ++i, ++current_entry) {
    if (0 == amqp_table_entry_cmp(current_entry, entry)) {
      return 1;
    }
  }

  return 0;
}

static amqp_rpc_reply_t amqp_login_inner(amqp_connection_state_t state,
    char const *vhost,
    int channel_max,
    int frame_max,
    int heartbeat,
    const amqp_table_t *client_properties,
    amqp_sasl_method_enum sasl_method,
    va_list vl)
{
  int res;
  amqp_method_t method;
  int server_frame_max;
  uint16_t server_channel_max;
  uint16_t server_heartbeat;
  amqp_rpc_reply_t result;

  res = amqp_send_header(state);
  if (AMQP_STATUS_OK != res) {
    goto error_res;
  }

  res = amqp_simple_wait_method(state, 0, AMQP_CONNECTION_START_METHOD,
                                &method);
  if (res < 0) {
    goto error_res;
  }

  {
    amqp_connection_start_t *s = (amqp_connection_start_t *) method.decoded;
    if ((s->version_major != AMQP_PROTOCOL_VERSION_MAJOR)
        || (s->version_minor != AMQP_PROTOCOL_VERSION_MINOR)) {
      res = AMQP_STATUS_INCOMPATIBLE_AMQP_VERSION;
      goto error_res;
    }

    res = amqp_table_clone(&s->server_properties, &state->server_properties,
                           &state->properties_pool);

    if (AMQP_STATUS_OK != res) {
      goto error_res;
    }

    /* TODO: check that our chosen SASL mechanism is in the list of
       acceptable mechanisms. Or even let the application choose from
       the list! */
  }

  {
    amqp_table_entry_t default_properties[5];
    amqp_table_t default_table;
    amqp_connection_start_ok_t s;
    amqp_pool_t *channel_pool;
    amqp_bytes_t response_bytes;

    channel_pool = amqp_get_or_create_channel_pool(state, 0);
    if (NULL == channel_pool) {
      res = AMQP_STATUS_NO_MEMORY;
      goto error_res;
    }

    response_bytes = sasl_response(channel_pool,
                     sasl_method, vl);
    if (response_bytes.bytes == NULL) {
      res = AMQP_STATUS_NO_MEMORY;
      goto error_res;
    }

    default_properties[0].key = amqp_cstring_bytes("product");
    default_properties[0].value.kind = AMQP_FIELD_KIND_UTF8;
    default_properties[0].value.value.bytes =
      amqp_cstring_bytes("rabbitmq-c");

    /* version */
    default_properties[1].key = amqp_cstring_bytes("version");
    default_properties[1].value.kind = AMQP_FIELD_KIND_UTF8;
    default_properties[1].value.value.bytes =
        amqp_cstring_bytes(AMQP_VERSION_STRING);

    /* platform */
    default_properties[2].key = amqp_cstring_bytes("platform");
    default_properties[2].value.kind = AMQP_FIELD_KIND_UTF8;
    default_properties[2].value.value.bytes =
        amqp_cstring_bytes(AMQ_PLATFORM);

    /* copyright */
    default_properties[3].key = amqp_cstring_bytes("copyright");
    default_properties[3].value.kind = AMQP_FIELD_KIND_UTF8;
    default_properties[3].value.value.bytes =
        amqp_cstring_bytes(AMQ_COPYRIGHT);

    default_properties[4].key = amqp_cstring_bytes("information");
    default_properties[4].value.kind = AMQP_FIELD_KIND_UTF8;
    default_properties[4].value.value.bytes =
      amqp_cstring_bytes("See https://github.com/alanxz/rabbitmq-c");

    default_table.entries = default_properties;
    default_table.num_entries = sizeof(default_properties) / sizeof(amqp_table_entry_t);

    if (0 == client_properties->num_entries) {
      s.client_properties = default_table;
    } else {
      /* Merge provided properties with our default properties:
       * - Copy default properties.
       * - Any provided property that doesn't have the same key as a default
       *   property is also copied.
       *
       * TODO: if one of the default properties is a capabilities table, we will
       * need to figure out how to merge this if the user provides a capabilites
       * table
       */
      int i;
      amqp_table_entry_t *current_entry;

      s.client_properties.entries = amqp_pool_alloc(channel_pool,
                                    sizeof(amqp_table_entry_t) * (default_table.num_entries + client_properties->num_entries));
      if (NULL == s.client_properties.entries) {
        res = AMQP_STATUS_NO_MEMORY;
        goto error_res;
      }
      s.client_properties.num_entries = 0;

      current_entry = s.client_properties.entries;

      for (i = 0; i < default_table.num_entries; ++i) {
        memcpy(current_entry, &default_table.entries[i], sizeof(amqp_table_entry_t));
        s.client_properties.num_entries += 1;
        ++current_entry;
      }

      for (i = 0; i < client_properties->num_entries; ++i) {
        if (amqp_table_contains_entry(&default_table, &client_properties->entries[i])) {
          continue;
        }
        memcpy(current_entry, &client_properties->entries[i], sizeof(amqp_table_entry_t));
        s.client_properties.num_entries += 1;
        ++current_entry;
      }
    }

    s.mechanism = sasl_method_name(sasl_method);
    s.response = response_bytes;
    s.locale.bytes = "en_US";
    s.locale.len = 5;

    res = amqp_send_method(state, 0, AMQP_CONNECTION_START_OK_METHOD, &s);
    if (res < 0) {
      goto error_res;
    }
  }

  amqp_release_buffers(state);

  res = amqp_simple_wait_method(state, 0, AMQP_CONNECTION_TUNE_METHOD,
                                &method);
  if (res < 0) {
    goto error_res;
  }

  {
    amqp_connection_tune_t *s = (amqp_connection_tune_t *) method.decoded;
    server_channel_max = s->channel_max;
    server_frame_max = s->frame_max;
    server_heartbeat = s->heartbeat;
  }

  if (server_channel_max != 0 && server_channel_max < channel_max) {
    channel_max = server_channel_max;
  } else if (server_channel_max == 0 && channel_max == 0) {
    channel_max = UINT16_MAX;
  }

  if (server_frame_max != 0 && server_frame_max < frame_max) {
    frame_max = server_frame_max;
  }

  if (server_heartbeat != 0 && server_heartbeat < heartbeat) {
    heartbeat = server_heartbeat;
  }

  res = amqp_tune_connection(state, channel_max, frame_max, heartbeat);
  if (res < 0) {
    goto error_res;
  }

  {
    amqp_connection_tune_ok_t s;
    s.frame_max = frame_max;
    s.channel_max = channel_max;
    s.heartbeat = heartbeat;

    res = amqp_send_method(state, 0, AMQP_CONNECTION_TUNE_OK_METHOD, &s);
    if (res < 0) {
      goto error_res;
    }
  }

  amqp_release_buffers(state);

  {
    amqp_method_number_t replies[] = { AMQP_CONNECTION_OPEN_OK_METHOD, 0 };
    amqp_connection_open_t s;
    s.virtual_host = amqp_cstring_bytes(vhost);
    s.capabilities.len = 0;
    s.capabilities.bytes = NULL;
    s.insist = 1;

    result = amqp_simple_rpc(state,
                             0,
                             AMQP_CONNECTION_OPEN_METHOD,
                             (amqp_method_number_t *) &replies,
                             &s);
    if (result.reply_type != AMQP_RESPONSE_NORMAL) {
      goto out;
    }
  }

  result.reply_type = AMQP_RESPONSE_NORMAL;
  result.reply.id = 0;
  result.reply.decoded = NULL;
  result.library_error = 0;

out:
  amqp_maybe_release_buffers(state);
  return result;

error_res:
  result.reply_type = AMQP_RESPONSE_LIBRARY_EXCEPTION;
  result.reply.id = 0;
  result.reply.decoded = NULL;
  result.library_error = res;

  goto out;
}

amqp_rpc_reply_t amqp_login(amqp_connection_state_t state,
                            char const *vhost,
                            int channel_max,
                            int frame_max,
                            int heartbeat,
                            amqp_sasl_method_enum sasl_method,
                            ...)
{
  va_list vl;
  amqp_rpc_reply_t ret;

  va_start(vl, sasl_method);

  ret = amqp_login_inner(state, vhost, channel_max, frame_max, heartbeat,
                         &amqp_empty_table, sasl_method, vl);

  va_end(vl);

  return ret;
}

amqp_rpc_reply_t amqp_login_with_properties(amqp_connection_state_t state,
    char const *vhost,
    int channel_max,
    int frame_max,
    int heartbeat,
    const amqp_table_t *client_properties,
    amqp_sasl_method_enum sasl_method,
    ...)
{
  va_list vl;
  amqp_rpc_reply_t ret;

  va_start(vl, sasl_method);

  ret = amqp_login_inner(state, vhost, channel_max, frame_max, heartbeat,
                         client_properties, sasl_method, vl);

  va_end(vl);

  return ret;
}
