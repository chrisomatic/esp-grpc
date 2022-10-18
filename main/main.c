#include "common.h"
#include "grpc.h"
#include "testpb.h"

// ------------------------------------------------------------------------------------------

#define WIFI_SSID "my_ssid"
#define WIFI_PSWD "my_pswd"
#define TIMEZONE  "America/New_York"

// ------------------------------------------------------------------------------------------

uint8_t bt_mac[6] = {0};

const char* grpc_ca = "-----BEGIN CERTIFICATE-----\nMIIFYjCCBEqgAwIBAgIQd70NbNs2+RrqIQ/E8FjTDTANBgkqhkiG9w0BAQsFADBX\nMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFsU2lnbiBudi1zYTEQMA4GA1UE\nCxMHUm9vdCBDQTEbMBkGA1UEAxMSR2xvYmFsU2lnbiBSb290IENBMB4XDTIwMDYx\nOTAwMDA0MloXDTI4MDEyODAwMDA0MlowRzELMAkGA1UEBhMCVVMxIjAgBgNVBAoT\nGUdvb2dsZSBUcnVzdCBTZXJ2aWNlcyBMTEMxFDASBgNVBAMTC0dUUyBSb290IFIx\nMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAthECix7joXebO9y/lD63\nladAPKH9gvl9MgaCcfb2jH/76Nu8ai6Xl6OMS/kr9rH5zoQdsfnFl97vufKj6bwS\niV6nqlKr+CMny6SxnGPb15l+8Ape62im9MZaRw1NEDPjTrETo8gYbEvs/AmQ351k\nKSUjB6G00j0uYODP0gmHu81I8E3CwnqIiru6z1kZ1q+PsAewnjHxgsHA3y6mbWwZ\nDrXYfiYaRQM9sHmklCitD38m5agI/pboPGiUU+6DOogrFZYJsuB6jC511pzrp1Zk\nj5ZPaK49l8KEj8C8QMALXL32h7M1bKwYUH+E4EzNktMg6TO8UpmvMrUpsyUqtEj5\ncuHKZPfmghCN6J3Cioj6OGaK/GP5Afl4/Xtcd/p2h/rs37EOeZVXtL0m79YB0esW\nCruOC7XFxYpVq9Os6pFLKcwZpDIlTirxZUTQAs6qzkm06p98g7BAe+dDq6dso499\niYH6TKX/1Y7DzkvgtdizjkXPdsDtQCv9Uw+wp9U7DbGKogPeMa3Md+pvez7W35Ei\nEua++tgy/BBjFFFy3l3WFpO9KWgz7zpm7AeKJt8T11dleCfeXkkUAKIAf5qoIbap\nsZWwpbkNFhHax2xIPEDgfg1azVY80ZcFuctL7TlLnMQ/0lUTbiSw1nH69MG6zO0b\n9f6BQdgAmD06yK56mDcYBZUCAwEAAaOCATgwggE0MA4GA1UdDwEB/wQEAwIBhjAP\nBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTkrysmcRorSCeFL1JmLO/wiRNxPjAf\nBgNVHSMEGDAWgBRge2YaRQ2XyolQL30EzTSo//z9SzBgBggrBgEFBQcBAQRUMFIw\nJQYIKwYBBQUHMAGGGWh0dHA6Ly9vY3NwLnBraS5nb29nL2dzcjEwKQYIKwYBBQUH\nMAKGHWh0dHA6Ly9wa2kuZ29vZy9nc3IxL2dzcjEuY3J0MDIGA1UdHwQrMCkwJ6Al\noCOGIWh0dHA6Ly9jcmwucGtpLmdvb2cvZ3NyMS9nc3IxLmNybDA7BgNVHSAENDAy\nMAgGBmeBDAECATAIBgZngQwBAgIwDQYLKwYBBAHWeQIFAwIwDQYLKwYBBAHWeQIF\nAwMwDQYJKoZIhvcNAQELBQADggEBADSkHrEoo9C0dhemMXoh6dFSPsjbdBZBiLg9\nNR3t5P+T4Vxfq7vqfM/b5A3Ri1fyJm9bvhdGaJQ3b2t6yMAYN/olUazsaL+yyEn9\nWprKASOshIArAoyZl+tJaox118fessmXn1hIVw41oeQa1v1vg4Fv74zPl6/AhSrw\n9U5pCZEt4Wi4wStz6dTZ/CLANx8LZh1J7QJVj2fhMtfTJr9w4z30Z209fOU0iOMy\n+qduBmpvvYuR7hZL6Dupszfnw0Skfths18dG9ZKb59UhvmaSGZRVbNQpsg3BZlvi\nd0lIKO2d1xozclOzgjXPYovJJIultzkMu34qQb9Sz/yilrbCgj8=\n-----END CERTIFICATE-----\n";
const char* grpc_uri = "https://some.grpc-server.com";

// ------------------------------------------------------------------------------------------

void app_main()
{
    store_nvs_init();

    esp_read_mac(bt_mac, ESP_MAC_BT);
    LOGI("MAC Address: " MAC_FMT, MAC_LIST(bt_mac));

    wifi_init();
    wifi_set_max_reconnect_attempts(WIFI_INFINITE_CONN_ATTEMPTS);
    wifi_set_all(WIFI_SSID, WIFI_PSWD, 3, WIFI_CONTEXT_PRIMARY);
    wifi_enable();
    wifi_connect();

    time_init(SECONDS_IN_HOUR);
    time_set_timezone_id(TIMEZONE);

    grpc_init_t grpc_cfg = {
        .grpc_core = 1;
        .grpc_stack_size = 8000;
        .grpc_prio = 10;
        .http2_core = 1;
        .http2_stack_size = 22000;
        .http2_prio = 11;
    };

    grpc_init(grpc_cfg);

    grpc_conn_data_t grpc_dat = {
        .ca = grpc_ca;
        .uri = grpc_uri;
    };

    grpc_configure_connection(grpc_dat);

    grpc_connect();

    util_print_tasks();

    // @TEST: GRPC
    for(;;)
    {
        static bool pinged = false;
        static bool conn_prior = false;

        bool conn = grpc_connected();

        if(conn && !conn_prior)
        {
            pinged = true;
            session_test = false;
        }

        if(conn)
        {
            if(!pinged)
            {
                int64_t rtt = 0;
                bool ret = grpc_ping(1000, &rtt);
                if(ret)
                {
                    pinged = true;
                    int rtt_ms = rtt / 1000;
                    LOGI("ping time: %d", rtt_ms);
                }
            }

            if(!session_test)
            {
                Message m = {
                    .id = "test_id",
                    .x = 10,
                    .x = 15,
                };

                uint8_t pb[1024] = {0};
                int len = 0;

                len = testpb_message_create(&m, pb,sizeof(pb));
                grpc_call_proc(TESTPB_PATH,TESTPB_CREATE, pb, len);

                len = testpb_message_get(m.id, pb,sizeof(pb));
                grpc_call_proc(TESTPB_PATH,TESTPB_GET, pb, len);

                session_test = true;
            }
        }

        conn_prior = conn;
        delay(100);
    }
}
