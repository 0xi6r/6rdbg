#include <stdio.h>
#include <unistd.h>

int global_var = 42;

int add_numbers(int a, int b) {
    int result = a + b;
    printf("Adding %d + %d = %d\n", a, b, result);
    return result;
}

int main() {
    int local_var = 10;
    
    printf("Hello from test program!\n");
    printf("Global var: %d\n", global_var);
    printf("Local var: %d\n", local_var);
    
    int sum = add_numbers(5, 7);
    printf("Sum: %d\n", sum);
    
    // Loop to allow debugging
    for (int i = 0; i < 3; i++) {
        printf("Loop iteration %d\n", i);
        sleep(1);
    }
    
    printf("Program finished.\n");
    return 0;
}