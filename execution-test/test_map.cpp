#include "libebpf_execution.h"
#include "libebpf_map.h"
#include <catch2/catch_test_macros.hpp>
#include <cerrno>
#include <cstdint>

TEST_CASE("Test array map") {
    ebpf_execution_context_t *ctx = ebpf_execution_context__create();
    REQUIRE(ctx != nullptr);
    struct ebpf_map_attr attr {
        .type = BPF_MAP_TYPE_ARRAY, .key_size = 4, .value_size = 8, .max_ents = 100, .flags = 0,
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
