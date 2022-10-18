@echo off
.\components\nanopb\generator-bin\protoc.bat --proto_path=main\proto --nanopb_out=main\generated test.proto
