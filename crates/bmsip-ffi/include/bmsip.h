#ifndef BMSIP_H
#define BMSIP_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct BmsipClientHandle BmsipClientHandle;

BmsipClientHandle *bmsip_client_new(
    const char *username,
    const char *password,
    const char *domain,
    const char *registrar_addr,
    const char *bind_ip,
    uint16_t sip_port
);

BmsipClientHandle *bmsip_client_new_ex(
    const char *username,
    const char *password,
    const char *domain,
    const char *registrar_addr,
    const char *bind_ip,
    uint16_t sip_port,
    int32_t enable_opus,
    uint32_t sample_rate_hz
);

BmsipClientHandle *bmsip_client_new_transport(
    const char *username,
    const char *password,
    const char *domain,
    const char *registrar_addr,
    const char *bind_ip,
    uint16_t sip_port,
    int32_t enable_opus,
    uint32_t sample_rate_hz,
    const char *transport,
    const char *tls_ca_pem,
    int32_t tls_insecure
);

BmsipClientHandle *bmsip_client_new_secure(
    const char *username,
    const char *password,
    const char *domain,
    const char *registrar_addr,
    const char *bind_ip,
    uint16_t sip_port,
    int32_t enable_opus,
    uint32_t sample_rate_hz,
    const char *transport,
    const char *srtp_mode,
    const char *tls_ca_pem,
    int32_t tls_insecure
);

uint32_t bmsip_client_audio_sample_rate_hz(const BmsipClientHandle *client);

int32_t bmsip_client_register(const BmsipClientHandle *client);
int32_t bmsip_client_unregister(const BmsipClientHandle *client);
int32_t bmsip_client_dial(const BmsipClientHandle *client, const char *target_uri);
int32_t bmsip_client_ring(const BmsipClientHandle *client, const char *call_id);
int32_t bmsip_client_ring_early_media(const BmsipClientHandle *client, const char *call_id);
int32_t bmsip_client_answer(const BmsipClientHandle *client, const char *call_id);
int32_t bmsip_client_hangup(const BmsipClientHandle *client, const char *call_id);
int32_t bmsip_client_hold(const BmsipClientHandle *client, const char *call_id);
int32_t bmsip_client_resume_call(const BmsipClientHandle *client, const char *call_id);
int32_t bmsip_client_transfer(
    const BmsipClientHandle *client,
    const char *call_id,
    const char *target_uri
);
int32_t bmsip_client_attended_transfer(
    const BmsipClientHandle *client,
    const char *call_id,
    const char *target_call_id
);
int32_t bmsip_client_send_dtmf(
    const BmsipClientHandle *client,
    const char *call_id,
    char digit
);
int32_t bmsip_client_send_info_dtmf(
    const BmsipClientHandle *client,
    const char *call_id,
    char digit,
    uint32_t duration_ms
);
int32_t bmsip_client_notify_network_changed(
    const BmsipClientHandle *client,
    const char *bind_ip,
    uint16_t sip_port
);
int32_t bmsip_client_suspend(const BmsipClientHandle *client);
int32_t bmsip_client_resume(const BmsipClientHandle *client);

int32_t bmsip_client_push_pcm(
    const BmsipClientHandle *client,
    const int16_t *samples,
    size_t len
);
int32_t bmsip_client_pop_pcm(
    const BmsipClientHandle *client,
    int16_t *out_samples,
    size_t capacity
);

char *bmsip_client_poll_event_json(
    const BmsipClientHandle *client,
    uint32_t timeout_ms
);
void bmsip_string_free(char *s);
void bmsip_client_free(BmsipClientHandle *client);

#ifdef __cplusplus
}
#endif

#endif /* BMSIP_H */
