#! /bin/sh
java -Xmx4096M -cp .:lib/ECLA.jar:lib/DTNConsoleConnection.jar core.DTNSim $*
