// Socket audio device ("TCP:<port>") for ardopcf.
//
// Lets a host program that owns the radio's sample stream (an SDR such as the
// Hermes Lite 2, which has no sound card) exchange audio with ardopcf over one
// loopback TCP connection instead of a physical or virtual sound card.
//
// Select it with "-i TCP:<port> -o TCP:<port>" (or "TCP:<host>:<port>").
// ardopcf connects to the host program, which must already listen.  Both
// directions share the single connection.
//
// Wire format: every message is
//     type (1 byte) | payload length (uint32, little endian) | payload
// Types:
//     'H' ardopcf -> host   hello, ASCII "ARDOPCF-NETAUDIO 1 12000"
//     'R' host -> ardopcf   RX audio, int16 little endian mono at 12000 Hz,
//                           sent in real time by the host (it owns the clock)
//     'T' ardopcf -> host   TX audio, int16 little endian mono at 12000 Hz
//     'E' ardopcf -> host   end of the current transmission (all T sent)
//     'D' host -> ardopcf   the transmission has left the radio (drained);
//                           ardopcf then drops PTT, so the "PTT FALSE" host
//                           message marks the real end of RF
//
// PTT is unchanged: without CAT/PTT options ardopcf reports "PTT TRUE" and
// "PTT FALSE" on the host command port, and the host keys the radio.
//
// Only built for Unix-like platforms (Linux, macOS).

#ifndef NETAUDIO_H
#define NETAUDIO_H

#include <stdbool.h>

#define NETAUDIO_PREFIX "TCP:"
#define NETAUDIO_VERSION 1

// Append the socket audio device in use (if any) to the device list, so the
// device consistency checks of the WebGui/host interface find it.  Called by
// each backend's GetDevices() after its own devices.
void netaudio_list_device(void);

// True if devstr names a socket audio device.
bool netaudio_is_dev(const char *devstr);

// Open (connect on first use) the socket for capture or playback.
// Returns false (and logs) if the connection cannot be made.
bool netaudio_open(const char *devstr, bool capture);

// Release capture or playback; the connection closes when both are released.
void netaudio_close(bool capture);

// Send nSamples TX samples ('T').  Returns false on a socket error.
bool netaudio_write(const short *samples, unsigned int nSamples);

// Copy nSamples RX samples into out if that many are available, else return 0
// without consuming anything.
int netaudio_read(short *out, unsigned int nSamples);

// Send 'E' and block (calling txSleep) until the host answers 'D' or
// timeout_ms passes.  Returns true if 'D' arrived.
bool netaudio_flush(unsigned int timeout_ms);

#endif
