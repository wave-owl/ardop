// Socket audio device ("TCP:<port>") for ardopcf.
//
// Lets a host program that owns the radio's sample stream (an SDR such as the
// Hermes Lite 2, which has no sound card) exchange audio with ardopcf over one
// loopback TCP connection instead of a physical or virtual sound card.
//
// Select it with "-i TCP:<port> -o TCP:<port>" (or "TCP:<host>:<port>" where
// <host> must be a loopback address).  Capture and playback must name the same
// device.  ardopcf connects to the host program, which must already listen.
//
// Wire format (protocol 3): every message is
//     type (1 byte) | payload length (uint32, little endian) | payload
// Handshake (one 3 s budget in total, the token never crosses the wire):
//     'N' host -> ardopcf   nonce1 (32 random bytes)
//     'H' ardopcf -> host   "ARDOPCF-NETAUDIO 3 12000 <hex nonce2>
//                            <hex HMAC-SHA256(token, nonce1 || "engine")>"
//     'P' host -> ardopcf   HMAC-SHA256(token, nonce2 || "bridge") (32 bytes)
// Audio:
//     'R' host -> ardopcf   RX audio, int16 little endian mono at 12000 Hz,
//                           sent in real time by the host (it owns the clock)
//     'T' ardopcf -> host   TX audio, int16 little endian mono at 12000 Hz,
//                           paced to at most 500 ms ahead of real time
//     'E' ardopcf -> host   end of transmission number N (uint32 LE payload)
//     'D' host -> ardopcf   transmission N has left the radio (uint32 LE);
//                           only a D for the current N received after its E
//                           counts
//
// The token comes from the environment variable ARDOPCF_NETAUDIO_TOKEN
// (16..128 characters), set by the program that starts ardopcf; without it the
// device is refused.  Both sides prove knowledge of the token, so neither a
// local process squatting on the port nor a rogue client gets TX audio, the
// RX stream or PTT control.

// PTT is unchanged: without CAT/PTT options ardopcf reports "PTT TRUE" and
// "PTT FALSE" on the host command port, and the host keys the radio.  ardopcf
// drops PTT only after 'D' for the current transmission AND at least the
// transmission's duration since its first sample (or after the transmission
// length + 2 s, wall clock).  A send that stalls for 1 s or a lost connection
// closes the device (PTT FALSE) and reports "FAULT Socket audio ..." to the
// host.
//
// Only built for Unix-like platforms (Linux, macOS).

#ifndef NETAUDIO_H
#define NETAUDIO_H

#include <stdbool.h>

#define NETAUDIO_PREFIX "TCP:"
#define NETAUDIO_VERSION 3
#define NETAUDIO_TOKEN_ENV "ARDOPCF_NETAUDIO_TOKEN"

// Append the socket audio device in use (if any) to the device list, so the
// device consistency checks of the WebGui/host interface find it.  Called by
// each backend's GetDevices() after its own devices.
void netaudio_list_device(void);

// True if devstr names a socket audio device.
bool netaudio_is_dev(const char *devstr);

// Open (connect and authenticate on first use) the socket for capture or
// playback.  Returns false (and logs) if the device string is not a loopback
// address, names a different device than the one already open, or the
// connection/authentication fails.
bool netaudio_open(const char *devstr, bool capture);

// Release capture or playback; the connection closes when both are released.
void netaudio_close(bool capture);

// Send nSamples TX samples ('T'), paced to real time + 500 ms.  Returns false
// on a socket error or a send stalled for more than 1 s; the caller then
// closes the playback device (which drops PTT).
bool netaudio_write(const short *samples, unsigned int nSamples);

// Copy nSamples RX samples into out if that many are available, else return 0
// without consuming anything.
int netaudio_read(short *out, unsigned int nSamples);

// Send 'E' for the current transmission and block (calling txSleep) until the
// host answers 'D' for it and the transmission's duration has passed, or
// timeout_ms (wall clock, counted from the transmission's first sample) passed.  Returns true if 'D' arrived in time.
bool netaudio_flush(unsigned int timeout_ms);

// True once if the connection was lost since the last call (the caller closes
// the devices and reports a FAULT to the host).
bool netaudio_lost(void);

#endif
