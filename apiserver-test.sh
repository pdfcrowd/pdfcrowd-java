#!/bin/bash

set -e

javac -classpath . apiserver.java
java -classpath . apiserver $1 $2 $3


