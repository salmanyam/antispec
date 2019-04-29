#!/bin/bash

for file in examples/*; do
	python produce-anti-spec-full.py examples/"$(basename "$file")" >> data/examples-output.txt
done

for file in cqe-challenges/*; do
	python produce-anti-spec-full.py cqe-challenges/"$(basename "$file")" >> data/challenges-output.txt
done
