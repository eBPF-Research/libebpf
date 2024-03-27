#include "libebpf_execution.h"
#include "libebpf_map.h"
#include "libebpf_map_ringbuf.h"
#include <algorithm>
#include <catch2/catch_test_macros.hpp>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <map>
#include <random>
#include <set>
#include <string>
#include <vector>
#include <thread>
extern "C" {
#include "libebpf_execution_internal.h"
}
struct hashmap_value {
    int a;
    uint64_t b;
    char c[10];
};

TEST_CASE("Test hash map") {
    ebpf_state_t *ctx = ebpf_state__create();
    REQUIRE(ctx != nullptr);
    struct ebpf_map_attr attr {
        .type = EBPF_MAP_TYPE_HASH, .key_size = 4, .value_size = sizeof(hashmap_value), .max_ents = 100, .flags = 0,
    };
    int id = ebpf_state__map_create(ctx, "my_map", &attr);
    REQUIRE(id >= 0);
    // Insert
    for (int i = 1; i <= 10; i++) {
        hashmap_value val{
            .a = i,
            .b = ((uint64_t)i << 32) | i,
        };
        std::string str = std::to_string(i);
        strcpy(val.c, str.c_str());
        REQUIRE(ebpf_state__map_elem_update(ctx, id, &i, &val, 0) == 0);
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
        REQUIRE(ebpf_state__map_elem_lookup(ctx, id, &x, &out_buf) == 0);
        REQUIRE(out_buf.a == x);
        REQUIRE(out_buf.b == ((((uint64_t)x) << 32) | x));
        std::string str = std::to_string(x);
        REQUIRE(str == out_buf.c);
    }
    // Delete
    // Delete the first 3 elements
    for (int i = 0; i < 3; i++) {
        int x = vec[i];
        REQUIRE(ebpf_state__map_elem_delete(ctx, id, &x) == 0);
    }
    // Check if we deleted successfully?
    for (int i = 0; i < 3; i++) {
        int x = vec[i];
        hashmap_value buf;
        REQUIRE(ebpf_state__map_elem_lookup(ctx, id, &x, &buf) == -ENOENT);
    }
    // Iterate over the remained elements
    std::map<int, hashmap_value> map;
    int *key = nullptr;
    int next_key;
    while (ebpf_state__map_get_next_key(ctx, id, key, &next_key) == 0) {
        hashmap_value buf;
        REQUIRE(ebpf_state__map_elem_lookup(ctx, id, &next_key, &buf) == 0);
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
    REQUIRE(ebpf_state__map_destroy(ctx, id) == 0);
    ebpf_state__destroy(ctx);
}

TEST_CASE("Test array map") {
    ebpf_state_t *ctx = ebpf_state__create();
    REQUIRE(ctx != nullptr);
    struct ebpf_map_attr attr {
        .type = EBPF_MAP_TYPE_ARRAY, .key_size = 4, .value_size = 8, .max_ents = 100, .flags = 0,
    };
    int id = ebpf_state__map_create(ctx, "my_map", &attr);
    REQUIRE(id >= 0);

    for (uint32_t i = 0; i < 100; i++) {
        uint64_t x = ((uint64_t)i << 32) | i;
        REQUIRE(ebpf_state__map_elem_update(ctx, id, &i, &x, 0) == 0);
    }
    uint32_t key;
    REQUIRE(ebpf_state__map_get_next_key(ctx, id, nullptr, &key) == 0);
    REQUIRE(key == 0);
    for (uint32_t i = 0; i < 99; i++) {
        REQUIRE(ebpf_state__map_get_next_key(ctx, id, &i, &key) == 0);
        REQUIRE(key == i + 1);
    }
    key = 99;
    REQUIRE(ebpf_state__map_get_next_key(ctx, id, &key, &key) == -ENOENT);
    REQUIRE(ebpf_state__map_destroy(ctx, id) == 0);
    REQUIRE(ebpf_state__map_get_next_key(ctx, id, &key, &key) < 0);
    ebpf_state__destroy(ctx);
}

static int handle_event(void *ctx, void *data, int len) {
    auto &vec = *(std::vector<std::vector<uint8_t> > *)ctx;
    std::vector<uint8_t> curr((uint8_t *)data, (uint8_t *)data + len);
    vec.push_back(curr);
    return 0;
}

bool operator<(const std::vector<uint8_t> &a, const std::vector<uint8_t> &b) {
    if (a.size() != b.size())
        return a.size() < b.size();
    return memcmp(a.data(), b.data(), a.size()) < 0;
}

TEST_CASE("Test ringbuf map") {
    ebpf_state_t *ctx = ebpf_state__create();
    REQUIRE(ctx != nullptr);
    struct ebpf_map_attr attr {
        .type = EBPF_MAP_TYPE_RINGBUF, .max_ents = 256 * 1024, .flags = 0,
    };
    int id = ebpf_state__map_create(ctx, "my_map", &attr);
    REQUIRE(id >= 0);

    std::mt19937 gen;
    gen.seed(std::random_device()());
    std::uniform_int_distribution<uint8_t> rand_bytes(100, 255);

    std::vector<std::vector<uint8_t> > rand_data;
    // Generate 10 pieces of random sized data
    for (int i = 1; i <= 10; i++) {
        size_t size = rand_bytes(gen);
        std::vector<uint8_t> curr;
        for (int j = 1; j <= size; j++)
            curr.push_back(rand_bytes(gen));
        rand_data.push_back(curr);
    }
    auto priv_data = ebpf_state__get_ringbuf_map_private_data(ctx, id);
    REQUIRE(priv_data != nullptr);
    auto producer = std::thread([=]() {
        std::vector<void *> buffers;
        // Produce data
        for (const auto &section : rand_data) {
            auto buffer = ringbuf_map_reserve(priv_data, section.size());
            REQUIRE(buffer != nullptr);
            buffers.push_back(buffer);
        }
        for (size_t i = 0; i < buffers.size(); i++) {
            memcpy(buffers[i], rand_data[i].data(), rand_data[i].size());
        }
        for (size_t i = 0; i < buffers.size(); i++) {
            // Discard if i is even
            ringbuf_map_submit(priv_data, buffers[i], i % 2 == 0);
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
    });
    auto consumer = std::thread([=]() {
        std::vector<std::vector<uint8_t> > received_buffer;
        // There should be five pieces of random data
        while (received_buffer.size() < 5) {
            ringbuf_map_fetch_data(priv_data, &received_buffer, handle_event);
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        // Compare if the received data are equal to the sended ones
        std::set<std::vector<uint8_t> > s1, s2;
        for (auto x : received_buffer)
            s1.insert(x);
        for (int i = 0; i < 5; i++)
            s2.insert(rand_data[i * 2 + 1]);
        REQUIRE(s1.size() == s2.size());
        for (const auto &x : s1) {
            REQUIRE(s2.count(x) == 1);
        }
    });
    producer.join();
    consumer.join();

    REQUIRE(ebpf_state__map_destroy(ctx, id) == 0);

    ebpf_state__destroy(ctx);
}

TEST_CASE("Test hashmap kernel helpers") {
    ebpf_state_t *ctx = ebpf_state__create();
    REQUIRE(ctx != nullptr);
    struct ebpf_map_attr attr {
        .type = EBPF_MAP_TYPE_HASH, .key_size = 4, .value_size = sizeof(hashmap_value), .max_ents = 100, .flags = 0,
    };
    int id = ebpf_state__map_create(ctx, "my_map", &attr);
    REQUIRE(id >= 0);
    {
        int key = 111;
        hashmap_value value{ .a = 233, .b = 456, .c = "aaaa" };
        REQUIRE(ebpf_state__map_elem_update(ctx, id, &key, &value, 0) == 0);
    }
    int key = 111;
    hashmap_value *buf = (hashmap_value *)ctx->map_ops[EBPF_MAP_TYPE_HASH].elem_lookup_from_helper(ctx->maps[id], &key);
    REQUIRE(buf != nullptr);
    REQUIRE(ebpf_state__map_elem_delete(ctx, id, &key) == 0);
    buf->a = 112;
    buf->b = 233;
    ebpf_state__destroy(ctx);
}
