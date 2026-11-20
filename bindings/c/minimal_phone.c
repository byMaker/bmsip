#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bmsip.h"

int main(int argc, char **argv) {
    if (argc < 5) {
        fprintf(stderr, "Usage: %s <server:port> <user> <password> <target_sip_uri>\n", argv[0]);
        return 1;
    }

    const char *server = argv[1];
    const char *user = argv[2];
    const char *password = argv[3];
    const char *target = argv[4];

    BmsipClientHandle *client = bmsip_client_new(
        user,
        password,
        "asterisk",
        server,
        "0.0.0.0",
        0
    );
    if (!client) {
        fprintf(stderr, "Failed to create bmsip client\n");
        return 1;
    }

    if (bmsip_client_register(client) != 0) {
        fprintf(stderr, "Failed to initiate REGISTER\n");
        bmsip_client_free(client);
        return 1;
    }

    int registered = 0;
    for (int i = 0; i < 100; ++i) {
        char *json = bmsip_client_poll_event_json(client, 50);
        if (json) {
            printf("EVENT: %s\n", json);
            if (strstr(json, "\"RegistrationChanged\"") && strstr(json, "Registered")) {
                registered = 1;
            }
            bmsip_string_free(json);
            if (registered) {
                break;
            }
        }
    }

    if (!registered || bmsip_client_dial(client, target) != 0) {
        fprintf(stderr, "Failed to register or dial\n");
        bmsip_client_free(client);
        return 1;
    }

    int16_t silence[160] = {0};
    int16_t rx_buf[160] = {0};
    char call_id[128] = {0};

    for (int i = 0; i < 40; ++i) {
        bmsip_client_push_pcm(client, silence, 160);
        (void)bmsip_client_pop_pcm(client, rx_buf, 160);

        char *json = bmsip_client_poll_event_json(client, 20);
        if (json) {
            printf("EVENT: %s\n", json);
            const char *cid_pos = strstr(json, "\"call_id\":\"");
            if (cid_pos && call_id[0] == '\0') {
                cid_pos += strlen("\"call_id\":\"");
                const char *end = strchr(cid_pos, '"');
                if (end && (size_t)(end - cid_pos) < sizeof(call_id)) {
                    memcpy(call_id, cid_pos, (size_t)(end - cid_pos));
                    call_id[end - cid_pos] = '\0';
                }
            }
            bmsip_string_free(json);
        }
    }

    if (call_id[0] != '\0') {
        (void)bmsip_client_hangup(client, call_id);
    }
    (void)bmsip_client_unregister(client);
    bmsip_client_free(client);
    return 0;
}

