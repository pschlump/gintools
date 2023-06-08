#!/bin/bash

echo "Input" >/tmp/,a
echo "$1" "$2" "$3" "$4" >>/tmp/,a

cd "$1"

pwd >>/tmp/,a

ls >>/tmp/,a
 
/usr/local/bin/pdftoppm "$2" "$3" "$4"

echo "After" >>/tmp/,a
ls >>/tmp/,a
