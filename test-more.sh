#!/usr/bin/env bash
export PATH=${PATH}:`go env GOPATH`/bin
go build && go install
killall password-hasher

password-hasher &
pid=$!

stats=$(curl --silent 'http://localhost:8090/stats')

total=$(echo "$stats" | jq -r .total)
avg=$(echo "$stats" | jq -r .average)

[[ $total -eq 0 ]] && [[ avg -eq 0 ]] && \
echo "No stats ok"

id=$(curl --silent --data "password=angryMonkey" 'http://localhost:8090/hash')
sleep 5
hash=$(curl --silent "http://localhost:8090/hash/$id")

[[ "$hash" == "ZEHhWB65gUlzdVwtDQArEyx+KVLzp/aTaRaPlBzYRIFj6vjFdqEb0Q5B8zVKCZ0vKbZPZklJz0Fd7su2A+gf7Q==" ]] && \
echo "Hash ok"

stats=$(curl --silent 'http://localhost:8090/stats')

total=$(echo "$stats" | jq -r .total)
avg=$(echo "$stats" | jq -r .average)
[[ $total -eq 1 ]] && [[ avg -ne 0 ]] && \
echo "Stats ok"

for i in {2..100}
do
  id=$(curl --silent --data "password=$id" 'http://localhost:8090/hash')
  [[ "$id" == "$i" ]] && echo "ID ok"
done

stats=$(curl --silent 'http://localhost:8090/stats')

total=$(echo "$stats" | jq -r .total)
avg=$(echo "$stats" | jq -r .average)
[[ $total -eq 100 ]] && [[ avg -ne 0 ]] && \
echo "Stats 100 ok"

sleep 3
for j in {1..3}
do
    for i in {2..100}
    do
      curl --silent "http://localhost:8090/hash/$i"
    done
done

curl --silent "http://localhost:8090/shutdown"

sleep 1
wait $pid
