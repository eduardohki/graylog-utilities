#!/usr/bin/env bash

# es-snapshot-curator.sh
#   Script to run elasticsearch-curator snapshot routines
#   and send results to Nagios
#
# Requirements:
#   elasticsearch-curator 4.3
#
# Author:
#   Eduardo Hernacki <eduardohki@gmail.com>
#
# Version:
#   1.0 - 2017/05/12

# Nagios Information
NSCA_BIN="/usr/local/nagios/bin/send_nsca"
NSCA_CFG="/usr/local/nagios/etc/send_nsca.cfg"
NSCA_PORT=5667
NAGIOS_SERVER="nagios_server"
NAGIOS_HOST="monitored_host"
NAGIOS_SERVICE="service_name"

# Curator Config Files
CURATOR_CONFIG="/etc/elasticsearch/curator.yml"
CURATOR_ACTION="/etc/elasticsearch/snapshot.yml"

# Run Curator to perform snapshot rotation and execution
curator --config $CURATOR_CONFIG $CURATOR_ACTION 2>&1
STATUS=$?

# Create EXITCODE in case of unknown error
EXITCODE=3

# Check Execution Status
if [ "$STATUS" != 0 ]; then
  OUTPUT="CRITICAL: Elasticsearch Snapshot Routines failed!"
  LONGOUTPUT="See logs for detais"
  EXITCODE=2
else
  OUTPUT="OK: Elasticsearch Snapshot Routines executed successfully"
  LONGOUTPUT="See logs for detais"
  EXITCODE=0
fi

# Send Status to Nagios
echo "$NAGIOS_HOST|$NAGIOS_SERVICE|$EXITCODE|$OUTPUT\n$LONGOUTPUT\n" | $NSCA_BIN -H $NAGIOS_SERVER -p $NSCA_PORT -c $NSCA_CFG -d '|'
