typedef unsigned long long uint64_t;
static const uint64_t (*add_func)(uint64_t a, uint64_t b) = (void*)3;

int main() {
    uint64_t b = add_func(1, 5);
    uint64_t a = 7385/b;
}