file(GLOB srcfiles
    "${PROJECT_SOURCE_DIR}/src/*.c")
file(GLOB headerfiles
		"${PROJECT_SOURCE_DIR}/src/*.h")

set(sources
${srcfiles}
)

set(exe_sources
    example/main.c
		${sources}
)

set(headers
    include/
    ${headerfiles}
)

set(test_sources
  src/tmp_test.cpp
)
