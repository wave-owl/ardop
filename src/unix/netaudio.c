// Socket audio device ("TCP:<port>") for ardopcf.  See common/netaudio.h for
// the wire format.  A reader thread moves 'R' samples into a ring buffer and
// records 'D' acknowledgements; the polling code of the audio backends reads
// the ring and writes 'T'/'E' messages directly.

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "common/ardopcommon.h"
#include "common/log.h"
#include "common/netaudio.h"
#include "common/os_util.h"

void txSleep(unsigned int mS);

#ifdef MSG_NOSIGNAL
#define NA_SEND_FLAGS MSG_NOSIGNAL
#else
#define NA_SEND_FLAGS 0
#endif

#define NA_RING 48000  // 4 s of 12 kHz audio
#define NA_MAX_PAYLOAD (1 << 20)
#define NA_MAX_TOKEN 128
#define NA_LEAD_MS 500  // TX audio may run this far ahead of real time
#define NA_SEND_TIMEOUT_MS 1000
#define NA_AUTH_TIMEOUT_MS 3000

static int na_fd = -1;
static int na_users = 0;  // bit 0 capture, bit 1 playback
static pthread_t na_thread;
static bool na_thread_running = false;
static pthread_mutex_t na_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t na_send_lock = PTHREAD_MUTEX_INITIALIZER;
static short na_ring[NA_RING];
static int na_head = 0;  // next write
static int na_count = 0;
static uint32_t na_tx_seq = 0;  // number of the current/last transmission
static uint32_t na_last_d = 0;  // number in the last 'D' received
static bool na_have_d = false;
static unsigned int na_burst_start = 0;  // Now (ms) at the first sample
static unsigned int na_burst_samples = 0;
static volatile bool na_broken = false;
static volatile bool na_lost_pending = false;
static char na_devstr[DEVSTRSZ] = "";

void netaudio_list_device(void) {
	if (na_devstr[0] == 0x00)
		return;
	int devindex = ExtendDevices(&AudioDevices);
	DeviceInfo *dev = AudioDevices[devindex];
	dev->name = strdup(na_devstr);
	dev->desc = strdup("Socket audio device (host program owns the radio audio).");
	dev->capture = true;
	dev->playback = true;
}

bool netaudio_is_dev(const char *devstr) {
	return devstr != NULL
		&& strncmp(devstr, NETAUDIO_PREFIX, strlen(NETAUDIO_PREFIX)) == 0;
}

static bool recv_exact(int fd, void *buf, size_t n) {
	size_t got = 0;
	while (got < n) {
		ssize_t r = recv(fd, (char *) buf + got, n - got, 0);
		if (r == 0)
			return false;
		if (r < 0) {
			if (errno == EINTR)
				continue;
			return false;
		}
		got += (size_t) r;
	}
	return true;
}

static void put_u32(unsigned char *b, uint32_t v) {
	b[0] = v & 0xFF;
	b[1] = (v >> 8) & 0xFF;
	b[2] = (v >> 16) & 0xFF;
	b[3] = (v >> 24) & 0xFF;
}

static uint32_t get_u32(const unsigned char *b) {
	return (uint32_t) b[0] | ((uint32_t) b[1] << 8) | ((uint32_t) b[2] << 16)
		| ((uint32_t) b[3] << 24);
}

static void mark_broken(const char *why) {
	if (!na_broken) {
		na_broken = true;
		na_lost_pending = true;
		ZF_LOGE("Socket audio: %s", why);
	}
}

// Send one message.  The socket has SO_SNDTIMEO, so a host that stops reading
// makes this fail after NA_SEND_TIMEOUT_MS instead of blocking forever.
static bool send_msg(char type, const void *payload, uint32_t len) {
	unsigned char hdr[5];
	hdr[0] = (unsigned char) type;
	put_u32(hdr + 1, len);
	bool ok = true;
	pthread_mutex_lock(&na_send_lock);
	if (na_fd < 0 || na_broken) {
		ok = false;
	} else {
		const unsigned char *parts[2] = {hdr, (const unsigned char *) payload};
		size_t sizes[2] = {sizeof(hdr), len};
		for (int p = 0; p < 2 && ok; p++) {
			size_t sent = 0;
			while (sent < sizes[p]) {
				ssize_t w = send(na_fd, parts[p] + sent, sizes[p] - sent,
					NA_SEND_FLAGS);
				if (w < 0 && errno == EINTR)
					continue;
				if (w <= 0) {
					ok = false;
					break;
				}
				sent += (size_t) w;
			}
		}
	}
	pthread_mutex_unlock(&na_send_lock);
	if (!ok)
		mark_broken(errno == EAGAIN || errno == EWOULDBLOCK
			? "host stopped reading (send stalled)" : "send failed");
	return ok;
}

static void *reader(void *arg) {
	(void) arg;
	unsigned char hdr[5];
	static short buf[NA_MAX_PAYLOAD / 2];
	time_t last_warn = 0;
	unsigned int suppressed = 0;
	while (na_fd >= 0) {
		if (!recv_exact(na_fd, hdr, sizeof(hdr)))
			break;
		uint32_t len = get_u32(hdr + 1);
		if (len > NA_MAX_PAYLOAD || (hdr[0] == 'R' && (len & 1))) {
			ZF_LOGE("Socket audio: bad message 0x%02X length %u", hdr[0], len);
			break;
		}
		if (len && !recv_exact(na_fd, buf, len))
			break;
		if (hdr[0] == 'R') {
			int n = (int) (len / 2);
			pthread_mutex_lock(&na_lock);
			for (int i = 0; i < n; i++) {
				// int16 little endian on the wire
				unsigned char *b = (unsigned char *) &buf[i];
				na_ring[na_head] = (short) (b[0] | (b[1] << 8));
				na_head = (na_head + 1) % NA_RING;
				if (na_count < NA_RING)
					na_count++;  // else the oldest sample is overwritten
			}
			pthread_mutex_unlock(&na_lock);
		} else if (hdr[0] == 'D' && len == 4) {
			pthread_mutex_lock(&na_lock);
			na_last_d = get_u32((unsigned char *) buf);
			na_have_d = true;
			pthread_mutex_unlock(&na_lock);
		} else {
			// Rate-limited: a misbehaving host must not flood the log.
			time_t now = time(NULL);
			if (now - last_warn >= 10) {
				ZF_LOGW("Socket audio: ignoring message 0x%02X (len %u)"
					" (+%u suppressed)", hdr[0], len, suppressed);
				last_warn = now;
				suppressed = 0;
			} else {
				suppressed++;
			}
		}
	}
	mark_broken("connection closed by host");
	return NULL;
}

// Parse "TCP:<port>" or "TCP:<host>:<port>", resolve, and accept loopback
// addresses only.
static int connect_dev(const char *devstr) {
	char host[64] = "127.0.0.1";
	char port[16];
	const char *spec = devstr + strlen(NETAUDIO_PREFIX);
	const char *colon = strrchr(spec, ':');
	if (colon != NULL) {
		size_t hlen = (size_t) (colon - spec);
		if (hlen == 0 || hlen >= sizeof(host))
			return -1;
		memcpy(host, spec, hlen);
		host[hlen] = 0;
		snprintf(port, sizeof(port), "%s", colon + 1);
	} else {
		snprintf(port, sizeof(port), "%s", spec);
	}
	struct addrinfo hints, *res = NULL;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	if (getaddrinfo(host, port, &hints, &res) != 0 || res == NULL) {
		ZF_LOGE("Socket audio: cannot resolve %s", devstr);
		return -1;
	}
	bool loopback = false;
	if (res->ai_family == AF_INET) {
		struct sockaddr_in *a = (struct sockaddr_in *) res->ai_addr;
		loopback = (ntohl(a->sin_addr.s_addr) >> 24) == 127;
	} else if (res->ai_family == AF_INET6) {
		struct sockaddr_in6 *a = (struct sockaddr_in6 *) res->ai_addr;
		loopback = IN6_IS_ADDR_LOOPBACK(&a->sin6_addr);
	}
	if (!loopback) {
		ZF_LOGE("Socket audio: %s is not a loopback address; refused", devstr);
		freeaddrinfo(res);
		return -1;
	}
	int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if (fd >= 0 && connect(fd, res->ai_addr, res->ai_addrlen) != 0) {
		close(fd);
		fd = -1;
	}
	freeaddrinfo(res);
	if (fd < 0) {
		ZF_LOGE("Socket audio: cannot connect to %s", devstr);
		return -1;
	}
	int one = 1;
	setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
#ifdef SO_NOSIGPIPE
	setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
#endif
	struct timeval tv = {NA_SEND_TIMEOUT_MS / 1000, (NA_SEND_TIMEOUT_MS % 1000) * 1000};
	setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
	// A small send buffer (about 0.3 s of audio) makes a host that stops
	// reading visible within a second instead of after many seconds of audio.
	int sndbuf = 16384;
	setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
	return fd;
}

// With ARDOPCF_NETAUDIO_TOKEN set, the host must prove it knows the token
// before ardopcf sends anything.
static bool authenticate(int fd, const char *token) {
	struct timeval tv = {NA_AUTH_TIMEOUT_MS / 1000, 0};
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	unsigned char hdr[5];
	char got[NA_MAX_TOKEN + 1];
	bool ok = recv_exact(fd, hdr, sizeof(hdr)) && hdr[0] == 'A';
	uint32_t len = ok ? get_u32(hdr + 1) : 0;
	ok = ok && len == strlen(token) && len <= NA_MAX_TOKEN && recv_exact(fd, got, len);
	unsigned char diff = 0;
	for (uint32_t i = 0; ok && i < len; i++)
		diff |= (unsigned char) (got[i] ^ token[i]);
	ok = ok && diff == 0;
	struct timeval none = {0, 0};
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &none, sizeof(none));
	return ok;
}

bool netaudio_open(const char *devstr, bool capture) {
	int bit = capture ? 1 : 2;
	if (na_fd >= 0 && strcmp(devstr, na_devstr) != 0) {
		ZF_LOGE("Socket audio: %s differs from the open device %s; capture and"
			" playback must use the same socket", devstr, na_devstr);
		return false;
	}
	if (na_fd < 0) {
		const char *token = getenv(NETAUDIO_TOKEN_ENV);
		if (token != NULL && strlen(token) > NA_MAX_TOKEN) {
			ZF_LOGE("Socket audio: %s longer than %d characters", NETAUDIO_TOKEN_ENV,
				NA_MAX_TOKEN);
			return false;
		}
		int fd = connect_dev(devstr);
		if (fd < 0)
			return false;
		if (token != NULL && token[0] != 0x00) {
			if (!authenticate(fd, token)) {
				ZF_LOGE("Socket audio: the host at %s did not authenticate; refused",
					devstr);
				close(fd);
				return false;
			}
		} else {
			ZF_LOGW("Socket audio: %s not set, connection is unauthenticated",
				NETAUDIO_TOKEN_ENV);
		}
		na_fd = fd;
		na_broken = false;
		na_lost_pending = false;
		pthread_mutex_lock(&na_lock);
		na_head = na_count = 0;
		na_have_d = false;
		pthread_mutex_unlock(&na_lock);
		na_burst_samples = 0;
		char hello[64 + NA_MAX_TOKEN];
		int n = snprintf(hello, sizeof(hello), "ARDOPCF-NETAUDIO %d 12000%s%s",
			NETAUDIO_VERSION, token && token[0] ? " " : "", token ? token : "");
		if (!send_msg('H', hello, (uint32_t) n)) {
			close(na_fd);
			na_fd = -1;
			return false;
		}
		if (pthread_create(&na_thread, NULL, reader, NULL) != 0) {
			close(na_fd);
			na_fd = -1;
			return false;
		}
		na_thread_running = true;
		snprintf(na_devstr, sizeof(na_devstr), "%s", devstr);
		// GetDevices() ran before the connection existed; list it now.
		netaudio_list_device();
		ZF_LOGI("Socket audio connected to %s", devstr);
	}
	na_users |= bit;
	return true;
}

void netaudio_close(bool capture) {
	na_users &= ~(capture ? 1 : 2);
	if (na_users != 0 || na_fd < 0)
		return;
	int fd = na_fd;
	shutdown(fd, SHUT_RDWR);
	if (na_thread_running) {
		pthread_join(na_thread, NULL);
		na_thread_running = false;
	}
	pthread_mutex_lock(&na_send_lock);
	na_fd = -1;
	pthread_mutex_unlock(&na_send_lock);
	close(fd);
	na_devstr[0] = 0x00;
	na_lost_pending = false;
	ZF_LOGI("Socket audio closed");
}

bool netaudio_lost(void) {
	if (!na_lost_pending)
		return false;
	na_lost_pending = false;
	return true;
}

bool netaudio_write(const short *samples, unsigned int nSamples) {
	if (na_broken)
		return false;
	static unsigned char out[2 * 1200];
	while (nSamples > 0) {
		unsigned int n = nSamples > 1200 ? 1200 : nSamples;
		if (na_burst_samples == 0)
			na_burst_start = Now;
		// Pace: never more than NA_LEAD_MS ahead of real time, so a stop at
		// the host discards little and a stalled host is noticed quickly.
		while (!na_broken
			&& na_burst_samples / 12 > (Now - na_burst_start) + NA_LEAD_MS)
			txSleep(10);
		if (na_broken)
			return false;
		for (unsigned int i = 0; i < n; i++) {
			out[2 * i] = (unsigned char) (samples[i] & 0xFF);
			out[2 * i + 1] = (unsigned char) ((samples[i] >> 8) & 0xFF);
		}
		if (!send_msg('T', out, 2 * n))
			return false;
		na_burst_samples += n;
		samples += n;
		nSamples -= n;
	}
	return true;
}

int netaudio_read(short *out, unsigned int nSamples) {
	int got = 0;
	pthread_mutex_lock(&na_lock);
	if (na_count >= (int) nSamples) {
		int tail = (na_head - na_count + NA_RING) % NA_RING;
		for (unsigned int i = 0; i < nSamples; i++)
			out[i] = na_ring[(tail + (int) i) % NA_RING];
		na_count -= (int) nSamples;
		got = (int) nSamples;
	}
	pthread_mutex_unlock(&na_lock);
	return got;
}

bool netaudio_flush(unsigned int timeout_ms) {
	uint32_t seq = ++na_tx_seq;
	unsigned int start = Now;
	unsigned int first = na_burst_samples ? na_burst_start : start;
	// Wall clock from the first sample, so pacing does not extend PTT.
	unsigned int deadline = first + timeout_ms;
	// 'D' is honoured only once the transmission could have been played.
	unsigned int min_end = first + na_burst_samples / 12;
	na_burst_samples = 0;
	unsigned char payload[4];
	put_u32(payload, seq);
	if (!send_msg('E', payload, sizeof(payload)))
		return false;
	while (!na_broken) {
		unsigned int now = Now;
		pthread_mutex_lock(&na_lock);
		bool acked = na_have_d && na_last_d == seq;
		pthread_mutex_unlock(&na_lock);
		if (acked && (int) (now - min_end) >= 0)
			return true;
		if ((int) (now - deadline) >= 0)
			break;
		txSleep(5);
	}
	ZF_LOGW("Socket audio: no drain acknowledgement for transmission %u within"
		" %u ms", seq, timeout_ms);
	return false;
}
