#!/bin/bash

# es-snapshot.sh
#   Script to automate snapshot creation for all indices
#
# Requirements:
#   curl
#   jq
#   send_nsca
#
# Author:
#   Eduardo Hernacki <eduardohki@gmail.com>
#
# Version:
#   1.0 - 2016/11/07

# Nagios Information
NSCA_BIN="/usr/local/nagios/bin/send_nsca"
NSCA_CFG="/usr/local/nagios/etc/send_nsca.cfg"
NSCA_PORT=5667
NAGIOS_SERVER="nagios_server"
NAGIOS_HOST="monitored_host"
NAGIOS_SERVICE="service_name"

# ES Information
ES_HOST="localhost"
REPO="backup_local"

# Create Snapshot of all Indices
SNAPSHOT=$(date +%Y-%m-%d_%H:%M:%S)
EXEC=$(curl -XPUT "$ES_HOST:9200/_snapshot/$REPO/$SNAPSHOT?wait_for_completion=true")

# Capture Snapshot Information
STATE=$(echo $EXEC | jq -r ".snapshot.state")
DURATION=$(echo $EXEC | jq -r ".snapshot.duration_in_millis")
SHARDS_TOTAL=$(echo $EXEC | jq -r ".snapshot.shards.total")
SHARDS_FAILED=$(echo $EXEC | jq -r ".snapshot.shards.failed")

# Create EXITCODE in case of unknown error
EXITCODE=3

# Check Execution Status
if [ "$STATE" != "SUCCESS" ]; then
  OUTPUT="CRITICAL: Elasticsearch Snapshot \"$SNAPSHOT\" failed!"
  LONGOUTPUT="Duration: ${DURATION}ms, Total Shards: $SHARDS_TOTAL, Failed Shards: $SHARDS_FAILED"
  EXITCODE=2
else
  OUTPUT="OK: Elasticsearch Snapshot \"$SNAPSHOT\" successfully created"
  LONGOUTPUT="Duration: ${DURATION}ms, Total Shards: $SHARDS_TOTAL"
  EXITCODE=0
fi

# Send Status to Nagios
echo "$NAGIOS_HOST|$NAGIOS_SERVICE|$EXITCODE|$OUTPUT\n$LONGOUTPUT\n" | $NSCA_BIN -H $NAGIOS_SERVER -p $NSCA_PORT -c $NSCA_CFG -d '|'
