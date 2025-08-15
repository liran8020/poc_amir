#!/bin/bash
rm -f ./out/*
echo ./filescanner -scanner="John Doe" -laptop="DELL-XPS15" -out="./out" -p=8 --bulk=200 -limit=500
./filescanner -scanner="John Doe" -laptop="DELL-XPS15" -out="./out" -p=8 --bulk=200 -limit=500
