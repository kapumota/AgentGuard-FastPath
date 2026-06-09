#include "unity.h"

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

/* Tests unitarios para helpers de riesgo. */

typedef struct {
    bool watched_process;
    uint64_t sensitive_files;
    uint64_t blocked_destinations;
    uint64_t network_after_file;
    uint64_t unique_destinations;
    uint64_t event_volume;
} risk_features_t;

static uint64_t riskScore(const risk_features_t *features) {
    uint64_t score = 0u;
    if (features->watched_process) { score += 10u; }
    if (features->sensitive_files > 0u) { score += 25u; }
    if (features->blocked_destinations > 0u) { score += 35u; }
    if (features->network_after_file > 0u) { score += 30u; }
    if (features->unique_destinations >= 10u) { score += 15u; }
    if (features->event_volume >= 100u) { score += 10u; }
    return score > 100u ? 100u : score;
}

static const char *riskLevel(uint64_t score) {
    if (score >= 80u) { return "critical"; }
    if (score >= 60u) { return "high"; }
    if (score >= 30u) { return "medium"; }
    if (score > 0u) { return "low"; }
    return "none";
}

static void testRiskScoreForNoSignalsIsZero(void) {
    risk_features_t features = {0};
    TEST_ASSERT_EQUAL_UINT64(0u, riskScore(&features));
}

static void testRiskScoreForSensitiveAndBlockedIsHigh(void) {
    risk_features_t features = {0};
    features.sensitive_files = 1u;
    features.blocked_destinations = 1u;
    TEST_ASSERT_EQUAL_UINT64(60u, riskScore(&features));
    TEST_ASSERT_TRUE(strcmp(riskLevel(riskScore(&features)), "high") == 0);
}

static void testRiskScoreIsCappedAtOneHundred(void) {
    risk_features_t features = {0};
    features.watched_process = true;
    features.sensitive_files = 3u;
    features.blocked_destinations = 2u;
    features.network_after_file = 2u;
    features.unique_destinations = 20u;
    features.event_volume = 200u;
    TEST_ASSERT_EQUAL_UINT64(100u, riskScore(&features));
}

static void testRiskLevels(void) {
    TEST_ASSERT_TRUE(strcmp(riskLevel(0u), "none") == 0);
    TEST_ASSERT_TRUE(strcmp(riskLevel(10u), "low") == 0);
    TEST_ASSERT_TRUE(strcmp(riskLevel(30u), "medium") == 0);
    TEST_ASSERT_TRUE(strcmp(riskLevel(60u), "high") == 0);
    TEST_ASSERT_TRUE(strcmp(riskLevel(80u), "critical") == 0);
}

static void testHighUniqueDestinationsIncreaseRisk(void) {
    risk_features_t features = {0};
    features.unique_destinations = 10u;
    TEST_ASSERT_EQUAL_UINT64(15u, riskScore(&features));
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(testRiskScoreForNoSignalsIsZero);
    RUN_TEST(testRiskScoreForSensitiveAndBlockedIsHigh);
    RUN_TEST(testRiskScoreIsCappedAtOneHundred);
    RUN_TEST(testRiskLevels);
    RUN_TEST(testHighUniqueDestinationsIncreaseRisk);
    return UNITY_END();
}
