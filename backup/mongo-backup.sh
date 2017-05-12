#!/bin/bash

# mongo-backup.sh
#   Script to automate MongoDB Backups
#
# Requirements:
#   mongodump
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

# Backup destination
DUMP_DIR="/mnt/backup/mongodb"

# Log destination
LOG_FILE=$DUMP_DIR/backup.log

# Record start timestamp in log file
echo "[$(date +%Y/%m/%d\ %H:%M:%S)] Starting mongodump" >> $LOG_FILE

# Save mongodump inside specified dir
mongodump --host localhost --out $DUMP_DIR >> $LOG_FILE 2>&1

# Checks the dump execution
if [ $? -eq 0 ]; then
  echo "[$(date +%Y/%m/%d\ %H:%M:%S)] mongodump successfully created" >> $LOG_FILE
  OUTPUT="OK: MongoDB Dump successfully created"
  EXITCODE=0
else
  echo "[$(date +%Y/%m/%d\ %H:%M:%S)] mongodump finished with errors" >> $LOG_FILE
  OUTPUT="CRITICAL: Errors creating MongoDB Dump! Please verify the log \"$LOG_FILE\" for more details"
  EXITCODE=2
fi

# Send Status to Nagios
echo "$NAGIOS_HOST|$NAGIOS_SERVICE|$EXITCODE|$OUTPUT\n" | $NSCA_BIN -H $NAGIOS_SERVER -p $NSCA_PORT -c $NSCA_CFG -d '|'
