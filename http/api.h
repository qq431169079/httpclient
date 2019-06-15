//
// Created by Donal on 2019-06-14.
//
#include "http.h"
#include "cJSON.h"
#include<stdio.h>
#include<stdlib.h>
#include<string.h>

#ifndef UNTITLED_API_H
#define UNTITLED_API_H

int URLEncode(const char *, const int, char *, const int);

char *joinString(char *, char *);

char *getSealBase64(char *);

char *getSealListInfoBySn(char *);

#endif //UNTITLED_API_H
