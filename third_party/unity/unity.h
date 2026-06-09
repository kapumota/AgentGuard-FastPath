#ifndef AGFAST_UNITY_H
#define AGFAST_UNITY_H

#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef void (*unity_test_func_t)(void);
extern int unity_tests_run;
extern int unity_tests_failed;
extern const char *unity_current_test;

void UnityBegin(const char *name);
int UnityEnd(void);
void UnityDefaultTestRun(unity_test_func_t func, const char *name);
void UnityFail(const char *message, const char *file, int line);

#define UNITY_BEGIN() UnityBegin(__FILE__)
#define UNITY_END() UnityEnd()
#define RUN_TEST(func) UnityDefaultTestRun(func, #func)

#define TEST_ASSERT_TRUE(value) do { if (!(value)) { UnityFail("se esperaba verdadero", __FILE__, __LINE__); return; } } while (0)
#define TEST_ASSERT_FALSE(value) do { if ((value)) { UnityFail("se esperaba falso", __FILE__, __LINE__); return; } } while (0)
#define TEST_ASSERT_NOT_NULL(value) do { if ((value) == NULL) { UnityFail("se esperaba puntero no nulo", __FILE__, __LINE__); return; } } while (0)
#define TEST_ASSERT_EQUAL_INT(expected, actual) do { if ((int)(expected) != (int)(actual)) { char msg[160]; snprintf(msg, sizeof(msg), "enteros distintos: esperado=%d actual=%d", (int)(expected), (int)(actual)); UnityFail(msg, __FILE__, __LINE__); return; } } while (0)
#define TEST_ASSERT_EQUAL_UINT64(expected, actual) do { if ((uint64_t)(expected) != (uint64_t)(actual)) { char msg[192]; snprintf(msg, sizeof(msg), "uint64 distintos: esperado=%llu actual=%llu", (unsigned long long)(uint64_t)(expected), (unsigned long long)(uint64_t)(actual)); UnityFail(msg, __FILE__, __LINE__); return; } } while (0)
#define TEST_ASSERT_GREATER_OR_EQUAL_UINT64(minimum, actual) do { if ((uint64_t)(actual) < (uint64_t)(minimum)) { char msg[192]; snprintf(msg, sizeof(msg), "valor menor al minimo: minimo=%llu actual=%llu", (unsigned long long)(uint64_t)(minimum), (unsigned long long)(uint64_t)(actual)); UnityFail(msg, __FILE__, __LINE__); return; } } while (0)
#define TEST_ASSERT_DOUBLE_WITHIN(delta, expected, actual) do { if (fabs((double)(expected) - (double)(actual)) > (double)(delta)) { char msg[192]; snprintf(msg, sizeof(msg), "dobles fuera de rango: esperado=%.6f actual=%.6f delta=%.6f", (double)(expected), (double)(actual), (double)(delta)); UnityFail(msg, __FILE__, __LINE__); return; } } while (0)

#endif
