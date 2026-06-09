#include "unity.h"

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

/* Tests unitarios autocontenidos para invariantes probabilísticos. */

#define BLOOM_BITS 1024u
#define BLOOM_BYTES (BLOOM_BITS / 8u)
#define CMS_DEPTH 3u
#define CMS_WIDTH 128u
#define HLL_REGISTERS 64u
#define SPACE_K 3u
#define ODD_BITS 128u
#define ODD_BYTES (ODD_BITS / 8u)

static uint64_t testHash64(uint64_t value, uint64_t seed) {
    uint64_t x = value + seed + 0x9e3779b97f4a7c15ULL;
    x ^= x >> 30;
    x *= 0xbf58476d1ce4e5b9ULL;
    x ^= x >> 27;
    x *= 0x94d049bb133111ebULL;
    x ^= x >> 31;
    return x;
}

typedef struct { uint8_t bits[BLOOM_BYTES]; } bloom_t;

typedef struct { uint32_t table[CMS_DEPTH][CMS_WIDTH]; } cms_t;

typedef struct { uint8_t registers[HLL_REGISTERS]; } hll_t;

typedef struct { uint64_t key; uint32_t count; bool used; } space_item_t;

typedef struct { space_item_t items[SPACE_K]; } space_saving_t;

typedef struct { uint8_t bits[ODD_BYTES]; } odd_sketch_t;

static void bloomAdd(bloom_t *bloom, uint64_t value) {
    for (uint64_t i = 0; i < 4u; ++i) {
        uint64_t pos = testHash64(value, i) % BLOOM_BITS;
        bloom->bits[pos / 8u] = (uint8_t)(bloom->bits[pos / 8u] | (uint8_t)(1u << (pos % 8u)));
    }
}

static bool bloomMaybeContains(const bloom_t *bloom, uint64_t value) {
    for (uint64_t i = 0; i < 4u; ++i) {
        uint64_t pos = testHash64(value, i) % BLOOM_BITS;
        if ((bloom->bits[pos / 8u] & (uint8_t)(1u << (pos % 8u))) == 0u) {
            return false;
        }
    }
    return true;
}

static void cmsAdd(cms_t *cms, uint64_t key) {
    for (uint64_t row = 0; row < CMS_DEPTH; ++row) {
        uint64_t pos = testHash64(key, row + 11u) % CMS_WIDTH;
        cms->table[row][pos] += 1u;
    }
}

static uint32_t cmsEstimate(const cms_t *cms, uint64_t key) {
    uint32_t best = UINT32_MAX;
    for (uint64_t row = 0; row < CMS_DEPTH; ++row) {
        uint64_t pos = testHash64(key, row + 11u) % CMS_WIDTH;
        if (cms->table[row][pos] < best) {
            best = cms->table[row][pos];
        }
    }
    return best == UINT32_MAX ? 0u : best;
}

static void hllAdd(hll_t *hll, uint64_t value) {
    uint64_t hash = testHash64(value, 123u);
    uint64_t idx = hash % HLL_REGISTERS;
    uint8_t rank = (uint8_t)((hash >> 8) & 31u);
    rank = (uint8_t)(rank == 0u ? 1u : rank);
    if (rank > hll->registers[idx]) {
        hll->registers[idx] = rank;
    }
}

static uint64_t hllNonZeroRegisters(const hll_t *hll) {
    uint64_t count = 0u;
    for (size_t i = 0; i < HLL_REGISTERS; ++i) {
        if (hll->registers[i] != 0u) {
            count += 1u;
        }
    }
    return count;
}

static void spaceSavingAdd(space_saving_t *ss, uint64_t key) {
    size_t min_index = 0u;
    for (size_t i = 0; i < SPACE_K; ++i) {
        if (ss->items[i].used && ss->items[i].key == key) {
            ss->items[i].count += 1u;
            return;
        }
    }
    for (size_t i = 0; i < SPACE_K; ++i) {
        if (!ss->items[i].used) {
            ss->items[i].used = true;
            ss->items[i].key = key;
            ss->items[i].count = 1u;
            return;
        }
    }
    for (size_t i = 1; i < SPACE_K; ++i) {
        if (ss->items[i].count < ss->items[min_index].count) {
            min_index = i;
        }
    }
    ss->items[min_index].key = key;
    ss->items[min_index].count += 1u;
}

static bool spaceSavingContains(const space_saving_t *ss, uint64_t key) {
    for (size_t i = 0; i < SPACE_K; ++i) {
        if (ss->items[i].used && ss->items[i].key == key) {
            return true;
        }
    }
    return false;
}

static void oddSketchToggle(odd_sketch_t *odd, uint64_t key) {
    uint64_t pos = testHash64(key, 777u) % ODD_BITS;
    odd->bits[pos / 8u] = (uint8_t)(odd->bits[pos / 8u] ^ (uint8_t)(1u << (pos % 8u)));
}

static int oddSketchMatches(const odd_sketch_t *a, const odd_sketch_t *b) {
    int matches = 0;
    for (size_t i = 0; i < ODD_BYTES; ++i) {
        uint8_t same = (uint8_t)~(a->bits[i] ^ b->bits[i]);
        for (int bit = 0; bit < 8; ++bit) {
            if ((same & (uint8_t)(1u << bit)) != 0u) {
                matches += 1;
            }
        }
    }
    return matches;
}

static void testBloomInsertedElementIsFound(void) {
    bloom_t bloom;
    memset(&bloom, 0, sizeof(bloom));
    bloomAdd(&bloom, 101u);
    TEST_ASSERT_TRUE(bloomMaybeContains(&bloom, 101u));
}

static void testBloomNormallyRejectsAbsentElement(void) {
    bloom_t bloom;
    memset(&bloom, 0, sizeof(bloom));
    bloomAdd(&bloom, 101u);
    bloomAdd(&bloom, 202u);
    TEST_ASSERT_FALSE(bloomMaybeContains(&bloom, 99999u));
}

static void testCmsNeverUnderestimatesInsertedFrequency(void) {
    cms_t cms;
    memset(&cms, 0, sizeof(cms));
    for (int i = 0; i < 17; ++i) { cmsAdd(&cms, 700u); }
    TEST_ASSERT_GREATER_OR_EQUAL_UINT64(17u, cmsEstimate(&cms, 700u));
}

static void testCmsDifferentKeysRemainUsable(void) {
    cms_t cms;
    memset(&cms, 0, sizeof(cms));
    for (int i = 0; i < 5; ++i) { cmsAdd(&cms, 10u); }
    for (int i = 0; i < 3; ++i) { cmsAdd(&cms, 20u); }
    TEST_ASSERT_GREATER_OR_EQUAL_UINT64(5u, cmsEstimate(&cms, 10u));
    TEST_ASSERT_GREATER_OR_EQUAL_UINT64(3u, cmsEstimate(&cms, 20u));
}

static void testHllEmptySetIsNearZero(void) {
    hll_t hll;
    memset(&hll, 0, sizeof(hll));
    TEST_ASSERT_EQUAL_UINT64(0u, hllNonZeroRegisters(&hll));
}

static void testHllRepeatedElementsDoNotGrowAsUnique(void) {
    hll_t repeated;
    hll_t unique;
    memset(&repeated, 0, sizeof(repeated));
    memset(&unique, 0, sizeof(unique));
    for (int i = 0; i < 100; ++i) {
        hllAdd(&repeated, 42u);
        hllAdd(&unique, (uint64_t)i);
    }
    TEST_ASSERT_TRUE(hllNonZeroRegisters(&repeated) < hllNonZeroRegisters(&unique));
}

static void testSpaceSavingKeepsFrequentItem(void) {
    space_saving_t ss;
    memset(&ss, 0, sizeof(ss));
    for (int i = 0; i < 30; ++i) { spaceSavingAdd(&ss, 1001u); }
    for (int i = 0; i < 10; ++i) { spaceSavingAdd(&ss, (uint64_t)(2000 + i)); }
    TEST_ASSERT_TRUE(spaceSavingContains(&ss, 1001u));
}

static void testOddSketchSimilarInputsMatchMore(void) {
    odd_sketch_t a;
    odd_sketch_t b;
    odd_sketch_t c;
    memset(&a, 0, sizeof(a));
    memset(&b, 0, sizeof(b));
    memset(&c, 0, sizeof(c));
    for (uint64_t i = 0; i < 16u; ++i) {
        oddSketchToggle(&a, i);
        oddSketchToggle(&b, i);
        oddSketchToggle(&c, i + 100u);
    }
    TEST_ASSERT_TRUE(oddSketchMatches(&a, &b) > oddSketchMatches(&a, &c));
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(testBloomInsertedElementIsFound);
    RUN_TEST(testBloomNormallyRejectsAbsentElement);
    RUN_TEST(testCmsNeverUnderestimatesInsertedFrequency);
    RUN_TEST(testCmsDifferentKeysRemainUsable);
    RUN_TEST(testHllEmptySetIsNearZero);
    RUN_TEST(testHllRepeatedElementsDoNotGrowAsUnique);
    RUN_TEST(testSpaceSavingKeepsFrequentItem);
    RUN_TEST(testOddSketchSimilarInputsMatchMore);
    return UNITY_END();
}
