#include <stdio.h>
#include <stdlib.h>

int compare(const void *a, const void *b) {
    return *(int *)a > *(int *)b;
}

int main() {
    int a[10] = {5,6,9,0,2,3,7,1,8,4};
    qsort(a, sizeof(a)/sizeof(a[0]), sizeof(a[0]), compare);
    for(int i = 0; i < 10; i++) {
        printf("%d ", a[i]);
    }
    printf("\n");
}