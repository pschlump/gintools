#!/bin/bash

# This file is MIT Licensed.
# Copyright (C) Philip Schlump, 2017.

export GIT_COMMIT=`git rev-list -1 HEAD` 
echo "GIT_COMMIT=$GIT_COMMIT"

export GIT_TAG=`git tag | tail -1`
if [ -z "$GIT_TAG" ] ; then
	export GIT_TAG="$GIT_COMMIT"
fi
echo "GIT_TAG=$GIT_TAG"
		
export BUILD_DATE="$(date)"

export GIT_AN_APP_SERVER_REVISION="$GIT_COMMIT"

cat >gitcommit.go <<ZZcc
package main

// Do Not Edit This File -- It was authomatically generated.
// Generation Date: $(date)
// Generation On: $(hostname)

// Copyright (C) Philip Schlump 2015-2023.
// MIT Licensed

var GitCommit string = "$GIT_COMMIT"
var Version string = "$GIT_TAG"
var BuildDate string = "$BUILD_DATE"

/* vim: set noai ts=4 sw=4: */
ZZcc
