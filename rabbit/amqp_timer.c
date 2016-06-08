/* vim:set ft=c ts=2 sw=2 sts=2 et cindent: */
/*
 * Portions created by Alan Antonuk are Copyright (c) 2013-2014 Alan Antonuk.
 * All Rights Reserved.
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
#include "amqp.h"
#include "amqp_timer.h"
#include <string.h>

#if (defined(_WIN32) || defined(__WIN32__) || defined(WIN32))
# define AMQP_WIN_TIMER_API
#elif (defined(machintosh) || defined(__APPLE__) || defined(__APPLE_CC__))
# define AMQP_MAC_TIMER_API
#else
# define AMQP_POSIX_TIMER_API
#endif


#ifdef AMQP_WIN_TIMER_API
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

uint64_t
amqp_get_monotonic_timestamp(void)
{
  static double NS_PER_COUNT = 0;
  LARGE_INTEGER perf_count;

  if (0 == NS_PER_COUNT) {
    LARGE_INTEGER perf_frequency;
    if (!QueryPerformanceFrequency(&perf_frequency)) {
      return 0;
    }
    NS_PER_COUNT = (double)AMQP_NS_PER_S / perf_frequency.QuadPart;
  }

  if (!QueryPerformanceCounter(&perf_count)) {
    return 0;
  }

  return (uint64_t)(perf_count.QuadPart * NS_PER_COUNT);
}
#endif /* AMQP_WIN_TIMER_API */

#ifdef AMQP_MAC_TIMER_API
# include <mach/mach_time.h>

uint64_t
amqp_get_monotonic_timestamp(void)
{
  static mach_timebase_info_data_t s_timebase = {0, 0};
  uint64_t timestamp;

  timestamp = mach_absolute_time();

  if (s_timebase.denom == 0) {
    mach_timebase_info(&s_timebase);
    if (0 == s_timebase.denom) {
      return 0;
    }
  }

  timestamp *= (uint64_t)s_timebase.numer;
  timestamp /= (uint64_t)s_timebase.denom;

  return timestamp;
}
#endif /* AMQP_MAC_TIMER_API */

#ifdef AMQP_POSIX_TIMER_API
#include <time.h>

uint64_t
amqp_get_monotonic_timestamp(void)
{
#ifdef __hpux
  return (uint64_t)gethrtime();
#else
  struct timespec tp;
  if (-1 == clock_gettime(CLOCK_MONOTONIC, &tp)) {
    return 0;
  }

  return ((uint64_t)tp.tv_sec * AMQP_NS_PER_S + (uint64_t)tp.tv_nsec);
#endif
}
#endif /* AMQP_POSIX_TIMER_API */

int
amqp_timer_update(amqp_timer_t *timer, struct timeval *timeout)
{
  if (0 == timer->current_timestamp) {
    timer->current_timestamp = amqp_get_monotonic_timestamp();

    if (0 == timer->current_timestamp) {
      return AMQP_STATUS_TIMER_FAILURE;
    }

    timer->timeout_timestamp = timer->current_timestamp +
                               (uint64_t)timeout->tv_sec * AMQP_NS_PER_S +
                               (uint64_t)timeout->tv_usec * AMQP_NS_PER_US;

  } else {
    timer->current_timestamp = amqp_get_monotonic_timestamp();

    if (0 == timer->current_timestamp) {
      return AMQP_STATUS_TIMER_FAILURE;
    }
  }

  if (timer->current_timestamp > timer->timeout_timestamp) {
    return AMQP_STATUS_TIMEOUT;
  }

  timer->ns_until_next_timeout = timer->timeout_timestamp - timer->current_timestamp;

  memset(&timer->tv, 0, sizeof(struct timeval));
  timer->tv.tv_sec = timer->ns_until_next_timeout / AMQP_NS_PER_S;
  timer->tv.tv_usec = (timer->ns_until_next_timeout % AMQP_NS_PER_S) / AMQP_NS_PER_US;

  return AMQP_STATUS_OK;
}
