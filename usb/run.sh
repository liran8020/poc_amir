#!/bin/bash
rm -f ./out/*
sudo ./filescanner -scanner="John Doe" -laptop="DELL-XPS15" -out="./out" -p=20 --bulk=1000
