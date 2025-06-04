#!/bin/bash 

LOGFILE="$1"

#This shell will log EVERYTHING until the user exits it 
script -q -f "$LOGFILE"