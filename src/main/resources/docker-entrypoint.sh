#!/bin/bash

sleep 10

java -cp app:app/lib/* -Dspring.profiles.active=prod cloud.popush.GangwayClientApplication
