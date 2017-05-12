#!/usr/bin/env python
#
# check_es_cluster_status.py:
#   Plugin Nagios para monitorar o stauts do cluster do Elastisearch
#
# Requisitos:
#	- python "requests" module
#	- python "json" module
#
# Autor: Eduardo Hernacki <eduardo.hernacki@openux.com.br>
#
# Versao 1.0 - 15/08/2016 - Versao inicial
#

import requests
import json

# fetch json from es
url = "http://localhost:9200/_cluster/health/"
try:
	r = requests.get(url)
except requests.exceptions.RequestException:
	print 'CRITICAL: erro na consulta do status do Elasticsearch!'
        quit(2)

if r.status_code != requests.codes.ok:
	print 'CRITICAL: erro na consulta do status do Elasticsearch!'
	quit(2)

# decode json
status = json.loads(r.text)

# check status
if status['status'] != 'green':
	print 'CRITICAL: o cluster \"' + status['cluster_name'] + '\" esta com o status \"' + status['status'] + '\"!'
	quit(2)
else:
	print 'OK: o cluster \"' + status['cluster_name'] + '\" esta com o status \"' + status['status'] + '\"'
	quit(0)
