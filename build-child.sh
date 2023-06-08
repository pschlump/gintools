#!/bin/bash

X=$(pwd)
for i in $* ; do
	cd $i
	go build
	cd $X
done


