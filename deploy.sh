#!/bin/bash

cd deployment/
tar cf - * | ssh root@$1 '(cd /; tar xf - )'