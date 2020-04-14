#!/bin/sh

egrep "warning|error" $1 > /tmp/warn
sort /tmp/warn | grep -v "/event/" | uniq > /tmp/warn_sort
grep "warning:" /tmp/warn_sort
grep "error:" /tmp/warn_sort

warn=$(grep "warning:" /tmp/warn_sort | wc -l)
printf "Warnings:\t%s\n" "$warn"
err=$(grep "error:" /tmp/warn_sort | wc -l)
printf "Errors:\t\t%s\n" "$err"
