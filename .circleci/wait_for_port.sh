#!/bin/bash
echo "Waiting for port $1"

counter=0
timeout=20

while ! nc -z localhost $1; do
  echo -n "."
  sleep 1
  let "counter+=1"
  if [[ "$counter" -gt $timeout ]]; then
    echo "TIMEOUT!!"
    exit 1
  fi
done
echo

echo "Port ready"
