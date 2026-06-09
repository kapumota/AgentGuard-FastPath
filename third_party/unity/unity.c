#include "unity.h"

int unity_tests_run = 0;
int unity_tests_failed = 0;
const char *unity_current_test = "";

void UnityBegin(const char *name) {
    unity_tests_run = 0;
    unity_tests_failed = 0;
    unity_current_test = "";
    printf("### Unity: %s\n", name);
}

int UnityEnd(void) {
    printf("Pruebas ejecutadas: %d\n", unity_tests_run);
    printf("Pruebas fallidas: %d\n", unity_tests_failed);
    if (unity_tests_failed == 0) {
        printf("Resultado: pruebas unitarias superadas\n");
        return 0;
    }
    printf("Resultado: pruebas unitarias fallidas\n");
    return 1;
}

void UnityDefaultTestRun(unity_test_func_t func, const char *name) {
    unity_current_test = name;
    unity_tests_run += 1;
    printf("[unidad] %s\n", name);
    func();
}

void UnityFail(const char *message, const char *file, int line) {
    unity_tests_failed += 1;
    fprintf(stderr, "Fallo en %s:%d durante %s: %s\n", file, line, unity_current_test, message);
}
