#include <stdio.h>
int a[10] = {5,6,9,0,2,3,7,1,8,4};

void swap(int *a, int *b) {
    int temp = *a;
    *a = *b;
    *b = temp;
}

int main() {
    for(int i = 9; i > 0; i--) {
        for(int j = 0; j < i; j++) {
            if(a[j] > a[j+1]) {
                swap(&a[j], &a[j+1]);
            }
        }
    }
    for(int i = 0; i < 10; i++) {
        printf("%d ", a[i]);
    }
    printf("\n");
}