#!/bin/sh
./components/nanopb/generator-bin/protoc --proto_path=main/proto --nanopb_out=main/generated test.proto
