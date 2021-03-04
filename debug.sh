#!/bin/bash

touch bill_validator.log
gnome-terminal -e "tail -f bill_validator.log"
python3 bill_validator.py $1
