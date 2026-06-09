#include "unity.h"

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

/* Tests unitarios autocontenidos para un modelo de grafo mínimo. */

#define GRAPH_MAX_NODES 32u
#define GRAPH_MAX_EDGES 64u
#define GRAPH_NAME_SIZE 64u

typedef enum { GRAPH_NODE_PROCESS = 1, GRAPH_NODE_FILE = 2, GRAPH_NODE_DESTINATION = 3 } graph_node_type_t;

typedef struct { int id; graph_node_type_t type; char name[GRAPH_NAME_SIZE]; bool used; } graph_node_t;

typedef struct { int from; int to; char relation[GRAPH_NAME_SIZE]; bool used; } graph_edge_t;

typedef struct { graph_node_t nodes[GRAPH_MAX_NODES]; graph_edge_t edges[GRAPH_MAX_EDGES]; } graph_model_t;

static void graphInit(graph_model_t *graph) { memset(graph, 0, sizeof(*graph)); }

static bool graphAddNode(graph_model_t *graph, int id, graph_node_type_t type, const char *name) {
    for (size_t i = 0; i < GRAPH_MAX_NODES; ++i) {
        if (graph->nodes[i].used && graph->nodes[i].id == id) { return true; }
    }
    for (size_t i = 0; i < GRAPH_MAX_NODES; ++i) {
        if (!graph->nodes[i].used) {
            graph->nodes[i].used = true;
            graph->nodes[i].id = id;
            graph->nodes[i].type = type;
            snprintf(graph->nodes[i].name, sizeof(graph->nodes[i].name), "%s", name);
            return true;
        }
    }
    return false;
}

static const graph_node_t *graphFindNode(const graph_model_t *graph, int id) {
    for (size_t i = 0; i < GRAPH_MAX_NODES; ++i) {
        if (graph->nodes[i].used && graph->nodes[i].id == id) { return &graph->nodes[i]; }
    }
    return NULL;
}

static bool graphAddEdge(graph_model_t *graph, int from, int to, const char *relation) {
    if (graphFindNode(graph, from) == NULL || graphFindNode(graph, to) == NULL) { return false; }
    for (size_t i = 0; i < GRAPH_MAX_EDGES; ++i) {
        if (!graph->edges[i].used) {
            graph->edges[i].used = true;
            graph->edges[i].from = from;
            graph->edges[i].to = to;
            snprintf(graph->edges[i].relation, sizeof(graph->edges[i].relation), "%s", relation);
            return true;
        }
    }
    return false;
}

static int graphCountEdgesFrom(const graph_model_t *graph, int from) {
    int count = 0;
    for (size_t i = 0; i < GRAPH_MAX_EDGES; ++i) {
        if (graph->edges[i].used && graph->edges[i].from == from) { count += 1; }
    }
    return count;
}

static int graphTraverseLimited(const graph_model_t *graph, int from, int limit) {
    int emitted = 0;
    for (size_t i = 0; i < GRAPH_MAX_EDGES && emitted < limit; ++i) {
        if (graph->edges[i].used && graph->edges[i].from == from) { emitted += 1; }
    }
    return emitted;
}

static void testGraphInsertProcessNode(void) {
    graph_model_t graph;
    const graph_node_t *node = NULL;
    graphInit(&graph);
    TEST_ASSERT_TRUE(graphAddNode(&graph, 501, GRAPH_NODE_PROCESS, "python"));
    node = graphFindNode(&graph, 501);
    TEST_ASSERT_NOT_NULL(node);
    TEST_ASSERT_EQUAL_INT(GRAPH_NODE_PROCESS, node->type);
}

static void testGraphInsertProcessFileRelation(void) {
    graph_model_t graph;
    graphInit(&graph);
    TEST_ASSERT_TRUE(graphAddNode(&graph, 501, GRAPH_NODE_PROCESS, "python"));
    TEST_ASSERT_TRUE(graphAddNode(&graph, 1001, GRAPH_NODE_FILE, "/etc/passwd"));
    TEST_ASSERT_TRUE(graphAddEdge(&graph, 501, 1001, "open"));
    TEST_ASSERT_EQUAL_INT(1, graphCountEdgesFrom(&graph, 501));
}

static void testGraphInsertProcessDestinationRelation(void) {
    graph_model_t graph;
    graphInit(&graph);
    TEST_ASSERT_TRUE(graphAddNode(&graph, 501, GRAPH_NODE_PROCESS, "python"));
    TEST_ASSERT_TRUE(graphAddNode(&graph, 2001, GRAPH_NODE_DESTINATION, "203.0.113.10"));
    TEST_ASSERT_TRUE(graphAddEdge(&graph, 501, 2001, "connect"));
    TEST_ASSERT_EQUAL_INT(1, graphCountEdgesFrom(&graph, 501));
}

static void testGraphRejectEdgeWithMissingNode(void) {
    graph_model_t graph;
    graphInit(&graph);
    TEST_ASSERT_TRUE(graphAddNode(&graph, 501, GRAPH_NODE_PROCESS, "python"));
    TEST_ASSERT_FALSE(graphAddEdge(&graph, 501, 9999, "connect"));
}

static void testGraphFindMissingPid(void) {
    graph_model_t graph;
    graphInit(&graph);
    TEST_ASSERT_TRUE(graphAddNode(&graph, 501, GRAPH_NODE_PROCESS, "python"));
    TEST_ASSERT_TRUE(graphFindNode(&graph, 9999) == NULL);
}

static void testGraphTraversalLimit(void) {
    graph_model_t graph;
    graphInit(&graph);
    TEST_ASSERT_TRUE(graphAddNode(&graph, 501, GRAPH_NODE_PROCESS, "python"));
    for (int i = 0; i < 8; ++i) {
        TEST_ASSERT_TRUE(graphAddNode(&graph, 2000 + i, GRAPH_NODE_DESTINATION, "destino"));
        TEST_ASSERT_TRUE(graphAddEdge(&graph, 501, 2000 + i, "connect"));
    }
    TEST_ASSERT_EQUAL_INT(3, graphTraverseLimited(&graph, 501, 3));
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(testGraphInsertProcessNode);
    RUN_TEST(testGraphInsertProcessFileRelation);
    RUN_TEST(testGraphInsertProcessDestinationRelation);
    RUN_TEST(testGraphRejectEdgeWithMissingNode);
    RUN_TEST(testGraphFindMissingPid);
    RUN_TEST(testGraphTraversalLimit);
    return UNITY_END();
}
