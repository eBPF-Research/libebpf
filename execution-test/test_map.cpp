#include "libebpf_execution.h"
#include "libebpf_map.h"
#include <algorithm>
#include <catch2/catch_test_macros.hpp>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <map>
#include <random>
#include <string>
#include <vector>

struct hashmap_value {
    int a;
    uint64_t b;
    char c[10];
};

TEST_CASE("Test hash map") {
    ebpf_execution_context_t *ctx = ebpf_execution_context__create();
    REQUIRE(ctx != nullptr);
    struct ebpf_map_attr attr {
        .type = EBPF_MAP_TYPE_HASH, .key_size = 4, .value_size = sizeof(hashmap_value), .max_ents = 100, .flags = 0,
    };
    int id = ebpf_execution_context__map_create(ctx, "my_map", &attr);
    REQUIRE(id >= 0);
    // Insert
    for (int i = 1; i <= 10; i++) {
        hashmap_value val{
            .a = i,
            .b = ((uint64_t)i << 32) | i,
        };
        std::string str = std::to_string(i);
        strcpy(val.c, str.c_str());
        REQUIRE(ebpf_execution_context__map_elem_update(ctx, id, &i, &val, 0) == 0);
    }
    // Query
    std::vector<int> vec;
    for (int i = 1; i <= 10; i++)
        vec.push_back(i);
    std::mt19937 gen;
    gen.seed(std::random_device()());
    std::shuffle(vec.begin(), vec.end(), gen);
    for (int x : vec) {
        hashmap_value out_buf;
        REQUIRE(ebpf_execution_context__map_elem_lookup(ctx, id, &x, &out_buf) == 0);
        REQUIRE(out_buf.a == x);
        REQUIRE(out_buf.b == ((((uint64_t)x) << 32) | x));
        std::string str = std::to_string(x);
        REQUIRE(str == out_buf.c);
    }
    // Delete
    // Delete the first 3 elements
    for (int i = 0; i < 3; i++) {
        int x = vec[i];
        REQUIRE(ebpf_execution_context__map_elem_delete(ctx, id, &x) == 0);
    }
    // Check if we deleted successfully?
    for (int i = 0; i < 3; i++) {
        int x = vec[i];
        hashmap_value buf;
        REQUIRE(ebpf_execution_context__map_elem_lookup(ctx, id, &x, &buf) == -ENOENT);
    }
    // Iterate over the remained elements
    std::map<int, hashmap_value> map;
    int *key = nullptr;
    int next_key;
    while (ebpf_execution_context__map_get_next_key(ctx, id, key, &next_key) == 0) {
        hashmap_value buf;
        REQUIRE(ebpf_execution_context__map_elem_lookup(ctx, id, &next_key, &buf) == 0);
        map[next_key] = buf;
        key = &next_key;
    }
    REQUIRE(map.size() == vec.size() - 3);
    for (int i = 3; i < vec.size(); i++) {
        int x = vec[i];
        auto itr = map.find(x);
        REQUIRE(itr != map.end());
        auto &val = itr->second;
        REQUIRE(val.a == x);
        REQUIRE(val.b == ((((uint64_t)x) << 32) | x));
        std::string str = std::to_string(x);
        REQUIRE(str == val.c);
    }
    REQUIRE(ebpf_execution_context__map_destroy(ctx, id) == 0);
    ebpf_execution_context__destroy(ctx);
}

TEST_CASE("Test array map") {
    ebpf_execution_context_t *ctx = ebpf_execution_context__create();
    REQUIRE(ctx != nullptr);
    struct ebpf_map_attr attr {
        .type = EBPF_MAP_TYPE_ARRAY, .key_size = 4, .value_size = 8, .max_ents = 100, .flags = 0,
    };
    int id = ebpf_execution_context__map_create(ctx, "my_map", &attr);
    REQUIRE(id >= 0);

    for (uint32_t i = 0; i < 100; i++) {
        uint64_t x = ((uint64_t)i << 32) | i;
        REQUIRE(ebpf_execution_context__map_elem_update(ctx, id, &i, &x, 0) == 0);
    }
    uint32_t key;
    REQUIRE(ebpf_execution_context__map_get_next_key(ctx, id, nullptr, &key) == 0);
    REQUIRE(key == 0);
    for (uint32_t i = 0; i < 99; i++) {
        REQUIRE(ebpf_execution_context__map_get_next_key(ctx, id, &i, &key) == 0);
        REQUIRE(key == i + 1);
    }
    key = 99;
    REQUIRE(ebpf_execution_context__map_get_next_key(ctx, id, &key, &key) == -ENOENT);
    REQUIRE(ebpf_execution_context__map_destroy(ctx, id) == 0);
    REQUIRE(ebpf_execution_context__map_get_next_key(ctx, id, &key, &key) < 0);
    ebpf_execution_context__destroy(ctx);
}
