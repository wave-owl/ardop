// Socket audio device ("TCP:<port>") for ardopcf.  See common/netaudio.h for
// the wire format.  A reader thread moves 'R' samples into a ring buffer and
// records 'D' acknowledgements; the polling code of the audio backends reads
// the ring and writes 'T'/'E' messages directly.

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
#include <sys/types.h>
#include <unistd.h>

#include "common/ardopcommon.h"
#include "common/log.h"
#include "common/netaudio.h"

void txSleep(unsigned int mS);

#ifdef MSG_NOSIGNAL
#define NA_SEND_FLAGS MSG_NOSIGNAL
#else
#define NA_SEND_FLAGS 0
#endif

#define NA_RING 48000  // 4 s of 12 kHz audio
#define NA_MAX_PAYLOAD (1 << 20)

static int na_fd = -1;
static int na_users = 0;  // bit 0 capture, bit 1 playback
static pthread_t na_thread;
static bool na_thread_running = false;
static pthread_mutex_t na_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t na_send_lock = PTHREAD_MUTEX_INITIALIZER;
static short na_ring[NA_RING];
static int na_head = 0;  // next write
static int na_count = 0;
static unsigned int na_drained = 0;  // number of 'D' messages received
static volatile bool na_broken = false;
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

static bool send_msg(char type, const void *payload, uint32_t len) {
	unsigned char hdr[5];
	hdr[0] = (unsigned char) type;
	hdr[1] = len & 0xFF;
	hdr[2] = (len >> 8) & 0xFF;
	hdr[3] = (len >> 16) & 0xFF;
	hdr[4] = (len >> 24) & 0xFF;
	bool ok = true;
	pthread_mutex_lock(&na_send_lock);
	if (na_fd < 0) {
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
	if (!ok && !na_broken) {
		na_broken = true;
		ZF_LOGE("Socket audio: send failed (%s)", strerror(errno));
	}
	return ok;
}

static void *reader(void *arg) {
	(void) arg;
	unsigned char hdr[5];
	static short buf[NA_MAX_PAYLOAD / 2];
	while (na_fd >= 0) {
		if (!recv_exact(na_fd, hdr, sizeof(hdr)))
			break;
		uint32_t len = (uint32_t) hdr[1] | ((uint32_t) hdr[2] << 8)
			| ((uint32_t) hdr[3] << 16) | ((uint32_t) hdr[4] << 24);
		if (len > NA_MAX_PAYLOAD || (len & 1)) {
			ZF_LOGE("Socket audio: bad message length %u", len);
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
				short s = (short) (b[0] | (b[1] << 8));
				na_ring[na_head] = s;
				na_head = (na_head + 1) % NA_RING;
				if (na_count < NA_RING)
					na_count++;  // else the oldest sample is overwritten
			}
			pthread_mutex_unlock(&na_lock);
		} else if (hdr[0] == 'D') {
			pthread_mutex_lock(&na_lock);
			na_drained++;
			pthread_mutex_unlock(&na_lock);
		} else {
			ZF_LOGW("Socket audio: ignoring message type 0x%02X", hdr[0]);
		}
	}
	if (!na_broken)
		ZF_LOGW("Socket audio: connection closed by host");
	na_broken = true;
	return NULL;
}

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
	return fd;
}

bool netaudio_open(const char *devstr, bool capture) {
	int bit = capture ? 1 : 2;
	if (na_fd < 0) {
		int fd = connect_dev(devstr);
		if (fd < 0)
			return false;
		na_fd = fd;
		na_broken = false;
		pthread_mutex_lock(&na_lock);
		na_head = na_count = 0;
		na_drained = 0;
		pthread_mutex_unlock(&na_lock);
		char hello[64];
		int n = snprintf(hello, sizeof(hello), "ARDOPCF-NETAUDIO %d 12000",
			NETAUDIO_VERSION);
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
	ZF_LOGI("Socket audio closed");
}

bool netaudio_write(const short *samples, unsigned int nSamples) {
	if (na_broken)
		return false;
	static unsigned char out[2 * 4800];
	while (nSamples > 0) {
		unsigned int n = nSamples > 4800 ? 4800 : nSamples;
		for (unsigned int i = 0; i < n; i++) {
			out[2 * i] = (unsigned char) (samples[i] & 0xFF);
			out[2 * i + 1] = (unsigned char) ((samples[i] >> 8) & 0xFF);
		}
		if (!send_msg('T', out, 2 * n))
			return false;
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
	pthread_mutex_lock(&na_lock);
	unsigned int before = na_drained;
	pthread_mutex_unlock(&na_lock);
	if (!send_msg('E', NULL, 0))
		return false;
	unsigned int waited = 0;
	while (waited < timeout_ms && !na_broken) {
		pthread_mutex_lock(&na_lock);
		bool done = na_drained != before;
		pthread_mutex_unlock(&na_lock);
		if (done)
			return true;
		txSleep(5);
		waited += 5;
	}
	ZF_LOGW("Socket audio: no drain acknowledgement within %u ms", timeout_ms);
	return false;
}
