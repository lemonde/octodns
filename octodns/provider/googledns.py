#
#
#

from __future__ import absolute_import, division, print_function, \
    unicode_literals

import logging
from collections import defaultdict
from googleapiclient import discovery
from oauth2client.client import GoogleCredentials
from ..record import Record
from .base import BaseProvider

# Disable warning: `file_cache is unavailable when using oauth2client`
logging.getLogger('googleapiclient.discovery_cache').setLevel(logging.ERROR)


class GoogleProvider(BaseProvider):
    '''
    Google DNS provider

    google:
        class: octodns.provider.googledns.GoogleProvider
    '''
    SUPPORTS_GEO = False
    # https://cloud.google.com/dns/overview#supported_dns_record_types
    SUPPORTS = set(('A', 'AAAA', 'CAA', 'CNAME', 'MX', 'NAPTR', 'NS', 'PTR',
                    'SPF', 'SRV', 'TXT'))
    MIN_TTL = 60
    TIMEOUT = 30

    def __init__(self, id, project_id, credentials, *args, **kwargs):
        self.log = logging.getLogger('GoogleProvider[{}]'.format(project_id))

        super(GoogleProvider, self).__init__(id, *args, **kwargs)

        self.credentials = GoogleCredentials.get_application_default()
        self.client = discovery.build(
            'dns', 'v1', credentials=self.credentials
        )

        self.project_id = project_id
        self._zones = None
        self._zone_records = {}

    def populate(self, zone, target=False, lenient=False):
        self.log.debug('populate: name=%s, target=%s, lenient=%s', zone.name,
                       target, lenient)
        before = len(zone.records)
        records = self.zone_records(zone)
        if records:
            values = defaultdict(lambda: defaultdict(list))
            for record in records:
                name = zone.hostname_from_fqdn(record['name'])
                _type = record['type']
                if _type in self.SUPPORTS:
                    values[name][record['type']].append(record)

            for name, types in values.items():
                for _type, records in types.items():
                    data_for = getattr(self, '_data_for_{}'.format(_type))
                    data = data_for(_type, records)
                    record = Record.new(zone, name, data, source=self,
                                        lenient=lenient)
                    zone.add_record(record)

        self.log.info('populate:   found %s records',
                      len(zone.records) - before)

    @property
    def zones(self):
        if self._zones is None:
            zones = {}
            request = self.client.managedZones().list(project=self.project_id)
            while request is not None:
                response = request.execute()

                for managed_zone in response['managedZones']:
                    zones[format(managed_zone['dnsName'])] = managed_zone['id']

                request = self.client.managedZones().list_next(
                    previous_request=request, previous_response=response
                )
            self._zones = zones

        return self._zones

    def _data_for_multiple(self, _type, records):
        return {
            'ttl': records[0]['ttl'],
            'type': _type,
            'values': [r['rrdatas'][0] for r in records],
        }

    _data_for_A = _data_for_multiple
    _data_for_AAAA = _data_for_multiple
    _data_for_SPF = _data_for_multiple

    def _data_for_TXT(self, _type, records):
        return {
            'ttl': records[0]['ttl'],
            'type': _type,
            'values': [r['rrdatas'][0].replace(';', '\;') for r in records],
        }

    def _data_for_CNAME(self, _type, records):
        only = records[0]
        return {
            'ttl': only['ttl'],
            'type': _type,
            'value': '{}'.format(only['rrdatas'][0])
        }

    def _data_for_MX(self, _type, records):
        values = []
        for r in records:
            values.append({
                'preference': r['priority'],
                'exchange': '{}'.format(r['rrdatas'][0]),
            })
        return {
            'ttl': records[0]['ttl'],
            'type': _type,
            'values': values,
        }

    def _data_for_SRV(self, _type, records):
        return {
            'ttl': records[0]['ttl'],
            'type': _type,
            'values': ['{}'.format(r['rrdatas'][0]) for r in records],
        }

    def _data_for_NAPTR(self, _type, records):
        return {
            'ttl': records[0]['ttl'],
            'type': _type,
            'values': ['{}'.format(r['rrdatas'][0]) for r in records],
        }

    def _data_for_NS(self, _type, records):
        return {
            'ttl': records[0]['ttl'],
            'type': _type,
            'values': ['{}'.format(r['rrdatas'][0]) for r in records],
        }

    def _contents_for_multiple(self, record):
        for value in record.values:
            yield {'rrdatas': [value]}

    _contents_for_A = _contents_for_multiple
    _contents_for_AAAA = _contents_for_multiple
    _contents_for_NS = _contents_for_multiple
    _contents_for_SPF = _contents_for_multiple

    def _contents_for_TXT(self, record):
        for value in record.values:
            yield {'content': value.replace('\;', ';')}

    def _contents_for_CNAME(self, record):
        yield {'content': record.value}

    def _contents_for_MX(self, record):
        for value in record.values:
            yield {
                'priority': value.preference,
                'content': value.exchange
            }

    def _apply_Create(self, change):
        new = change.new
        zone_id = self.zones[new.zone.name]
        contents_for = getattr(self, '_contents_for_{}'.format(new._type))
        for content in contents_for(change.new):
            content.update({
                "name": new.fqdn,
                "type": new._type,
                "ttl": new.ttl,
            })
            change_body = {
                "kind": "dns#change",
                "additions": [
                    content
                ]
            }
            request = self.client.changes().create(
                project=self.project_id, managedZone=zone_id, body=change_body
            )
            request.execute()

    def _apply_Delete(self, change):
        existing = change.existing
        zone_id = self.zones[existing.zone.name]
        for record in self.zone_records(existing.zone):
            contents_for = getattr(
                self, '_contents_for_{}'.format(existing._type)
            )
            for content in contents_for(change.existing):
                content.update({
                    "name": existing.fqdn,
                    "type": existing._type,
                    "ttl": existing.ttl,
                })
                change_body = {
                    "kind": "dns#change",
                    "deletions": [
                        content
                    ]
                }
                request = self.client.changes().create(
                    project=self.project_id,
                    managedZone=zone_id,
                    body=change_body
                )
                request.execute()

    def zone_records(self, zone):
        if zone.name not in self._zone_records:
            zone_id = self.zones.get(zone.name, False)
            if not zone_id:
                return []

        zone_id = self.zones.get(zone.name, False)
        request = self.client.resourceRecordSets().list(
            project=self.project_id, managedZone=zone_id
        )
        records = []
        while request is not None:
            response = request.execute()
            for resource_record_set in response['rrsets']:
                records.append(resource_record_set)

            request = self.client.resourceRecordSets().list_next(
                previous_request=request, previous_response=response
            )

        self._zone_records[zone.name] = records

        return self._zone_records[zone.name]

    def _apply(self, plan):
        desired = plan.desired
        changes = plan.changes
        self.log.debug('_apply: zone=%s, len(changes)=%d', desired.name,
                       len(changes))

        name = desired.name
        if name not in self.zones:
            self.log.debug('_apply:   no matching zone, creating')
            zone_id = self.zones.get(name, False)
            self.zones[name] = zone_id
            self._zone_records[name] = {}

        for change in changes:
            class_name = change.__class__.__name__
            getattr(self, '_apply_{}'.format(class_name))(change)

        # clear the cache
        self._zone_records.pop(name, None)
