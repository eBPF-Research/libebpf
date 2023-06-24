
# ffi:

for arm32 and arm64 compatible, this is ok:

```
static uint64_t
gather_bytes(uint64_t a, uint64_t b, uint64_t c, uint64_t d, uint64_t e)
{
    return (((uint64_t)a) << (uint64_t)32) | (((uint32_t)b) << (uint64_t)24) | (((uint32_t)c) << (uint64_t)16) | (((uint16_t)d) << (uint64_t)8) | (uint64_t)e;
}
```

this is not ok:

```
static uint64_t
gather_bytes(uint8_t a, uint8_t b, uint8_t c, uint8_t d, uint8_t e)
{
    return (((uint64_t)a) << (uint64_t)32) | (((uint32_t)b) << (uint64_t)24) | (((uint32_t)c) << (uint64_t)16) | (((uint16_t)d) << (uint64_t)8) | (uint64_t)e;
}
```

all args for helpers should be uint64_t to keep correct.

## more source code are from

- https://elixir.bootlin.com/linux/v5.7
