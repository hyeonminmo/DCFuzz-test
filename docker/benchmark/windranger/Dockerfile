ARG FUZZER_PREFIX
FROM $FUZZER_PREFIX/windranger

COPY targetBuild/benchmark-project /benchmark/project
COPY targetBuild/target/line /benchmark/target/line
COPY targetBuild/build_bench_common.sh /benchmark/build_bench_common.sh
COPY targetBuild/seed/empty /benchmark/seed/empty
COPY targetBuild/triage /benchmark/triage

ENV ASAN_OPTIONS=allocator_may_return_null=1,detect_leaks=0
WORKDIR /benchmark

RUN echo "****************build windranger**************************"

COPY windranger/build_bench_windranger.sh /benchmark/build_bench_windranger.sh
RUN ./build_bench_windranger.sh

