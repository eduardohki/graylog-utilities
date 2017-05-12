#!/usr/bin/env python
#
# check_es_indices.py:
#   Plugin Nagios para monitorar o tamanho dos indices do Elastisearch
#
# Requisitos:
#	- python "requests" module
#	- python "json" module
#
# Autor: Eduardo Hernacki <eduardo.hernacki@openux.com.br>
#
# Versao 1.0 - 18/08/2016 - Versao inicial
#

import requests
import json

# function to convert from byte to gigabyte
def byte_to_gigabyte(size):
        size = float(size) / float(1024)/ float(1024) / float(1024)
        return '{0:.2f} GB'.format(size)

# fetch json from es
url = "http://localhost:9200/_stats/store"
try:
        r = requests.get(url)
except requests.exceptions.RequestException:
        print 'CRITICAL - erro na consulta do status do Elasticsearch!'
        quit(2)

if r.status_code != requests.codes.ok:
        print 'CRITICAL - erro na consulta do status do Elasticsearch!'
        quit(2)

# decode json
store_data = json.loads(r.text)

# get size of all indices
total_size_in_bytes = byte_to_gigabyte(store_data['_all']['total']['store']['size_in_bytes'])


# get size of each index
total_indices = 0
long_output = 'Listagem dos indices:'
total_size_per_index = {}
for name, data in store_data.iteritems():
        if name == 'indices':
                for index, stats in data.iteritems():
                        size = byte_to_gigabyte(stats['total']['store']['size_in_bytes'])
                        long_output += '\n%s: %s' % (index, size)
                        total_indices += 1

print 'OK - Volume Total dos %s Indices: %s' % (total_indices, total_size_in_bytes)
print long_output
quit(0)
