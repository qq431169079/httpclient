#include "http/api.h"

int main() {
    char* ret;
    getSealBase64("8129455902011118", &ret);
    printf("结果ret:\n%s\n", ret);
    printf("ret:\n%d\n", strlen(ret));

    getSealListInfoBySn("8129455902011118", &ret);
    printf("结果ret:\n%s\n", ret);
    return 0;
}