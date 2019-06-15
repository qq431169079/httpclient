//
// Created by Donal on 2019-06-14.
//
#include "api.h"

#define BASE_URL "http://127.0.0.1:8080/api"

void releaseHttp(ft_http_client_t *);

int getSealBase64(char *sn, char **pOut) {
    char *url = joinString(BASE_URL, "/v1/seal/getSealBase64BySn");
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
    char *result = ft_http_sync_request(client, url, M_POST);
    int error_code = ft_http_get_error_code(client);
    if (error_code == ERR_OK) {
        int nOutLen = strlen(result);
        char *pTmp = (char *) malloc(nOutLen + 1);
        memcpy(pTmp, result, nOutLen);
        pTmp[nOutLen] = 0;
        *pOut = pTmp;
    }
    releaseHttp(client);
    return error_code;
}

int getSealListInfoBySn(char *sn, char **pOut) {
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
    char *result = ft_http_sync_request(client, url, M_POST);
    int error_code = ft_http_get_error_code(client);
    if (error_code == ERR_OK) {
        int nOutLen = strlen(result);
        char *pTmp = (char *) malloc(nOutLen + 1);
        memcpy(pTmp, result, nOutLen);
        pTmp[nOutLen] = 0;
        *pOut = pTmp;
    }
    releaseHttp(client);
    return error_code;
}

char *joinString(char *s1, char *s2) {
    char *result = malloc(strlen(s1) + strlen(s2) + 1);//+1 for the zero-terminator
    if (result == NULL) exit(1);
    strcpy(result, s1);
    strcat(result, s2);
    return result;
}

void releaseHttp(ft_http_client_t *client) {
    ft_http_destroy(client);
    ft_http_exit(client);
    ft_http_deinit();
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