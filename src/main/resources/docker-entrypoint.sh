#!/bin/bash

java -cp app:app/lib/* -Dspring.profiles.active=prod cloud.popush.GangwayClientApplication
