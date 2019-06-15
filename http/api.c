//
// Created by Donal on 2019-06-14.
//
#include "api.h"

#define BASE_URL "http://127.0.0.1:8080/api"

char *getSealBase64(char *sn) {
    char *url = joinString(BASE_URL, "/v1/seal/getFindBySn");
    cJSON *param = cJSON_CreateObject();
    cJSON_AddStringToObject(param, "sn", sn);
    char *out = cJSON_PrintUnformatted(param);
    cJSON_Delete(param);
    char *obj[1024] = {0};
    URLEncode(out, strlen(out), obj, 1024);
    char *c = joinString("?json=", obj);
    url = joinString(url, c);
    ft_http_init();
    ft_http_client_t *client = ft_http_new();
    char *ret = ft_http_sync_request(client, url, M_POST);
    printf("%s\n", ret);
    int error_code = ft_http_get_error_code(client);
    ft_http_destroy(client);
    ft_http_exit(client);
    ft_http_deinit();
    if (error_code == ERR_OK && ret != NULL) {
        cJSON *json = cJSON_Parse(ret);
        cJSON *json_code;
        json_code = cJSON_GetObjectItem(json, "code");
        if (0 == json_code->valueint) {
            cJSON *json_data = cJSON_GetObjectItem(json, "data");
            cJSON *json_base64 = cJSON_GetObjectItem(json_data, "sealBase64");
            return json_base64->valuestring;
        }
    }
    return "";
}

char *getSealListInfoBySn(char *sn) {
    char *url = joinString(BASE_URL, "/v1/seal/getSealListInfoBySn");
    cJSON *param = cJSON_CreateObject();
    cJSON_AddStringToObject(param, "sn", sn);
    char *out = cJSON_PrintUnformatted(param);
    cJSON_Delete(param);
    char *obj[1024] = {0};
    URLEncode(out, strlen(out), obj, 1024);
    char *c = joinString("?json=", obj);
    url = joinString(url, c);
    ft_http_init();
    ft_http_client_t *client = ft_http_new();
    char *ret = ft_http_sync_request(client, url, M_POST);
    int error_code = ft_http_get_error_code(client);
    ft_http_destroy(client);
    ft_http_exit(client);
    ft_http_deinit();
    if (error_code == ERR_OK && ret != NULL) {
        cJSON *json = cJSON_Parse(ret);
        cJSON *json_code;
        json_code = cJSON_GetObjectItem(json, "code");
        if (0 == json_code->valueint) {
            cJSON *json_data = cJSON_GetObjectItem(json, "data");
            return json_data->valuestring;
        }
    }
    return "";
}

char *joinString(char *s1, char *s2) {
    char *result = malloc(strlen(s1) + strlen(s2) + 1);//+1 for the zero-terminator
    if (result == NULL) exit(1);
    strcpy(result, s1);
    strcat(result, s2);
    return result;
}


int URLEncode(const char *str, const int strSize, char *result, const int resultSize) {
    int i;
    int j = 0;//for result index
    char ch;

    if ((str == NULL) || (result == NULL) || (strSize <= 0) || (resultSize <= 0)) {
        return 0;
    }

    for (i = 0; (i < strSize) && (j < resultSize); ++i) {
        ch = str[i];
        if (((ch >= 'A') && (ch < 'Z')) ||
            ((ch >= 'a') && (ch < 'z')) ||
            ((ch >= '0') && (ch < '9'))) {
            result[j++] = ch;
        } else if (ch == ' ') {
            result[j++] = '+';
        } else if (ch == '.' || ch == '-' || ch == '_' || ch == '*') {
            result[j++] = ch;
        } else {
            if (j + 3 < resultSize) {
                sprintf(result + j, "%%%02X", (unsigned char) ch);
                j += 3;
            } else {
                return 0;
            }
        }
    }

    result[j] = '\0';
    return j;
}