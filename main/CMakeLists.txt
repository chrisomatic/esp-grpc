
set(
    srcs 
        "main.c"
        "grpc.c"
        "generated/test.pb.c"
        "testpb.c"
    )

set(include_dirs ".")

idf_component_register(
                    SRCS         "${srcs}"
                    INCLUDE_DIRS "${include_dirs}"
                    )

message(STATUS "component lib: '${COMPONENT_LIB}'")

