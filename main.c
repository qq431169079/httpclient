#include "http/api.h"

int main() {

    char *ret ;
    ret = getSealBase64("8129455902011118");
    printf("结果ret:\n%s\n", ret);

    ret = getSealListInfoBySn("8129455902011118");
    printf("结果ret:\n%s\n", ret);
    return 0;
}