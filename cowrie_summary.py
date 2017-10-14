import json
from dateutil import parser
import datetime
import os
import collections
import argparse
import logging


#Should have used python 3.6! - some statistical helpers from stack overflow examples
def mean(data):
        """Return the sample arithmetic mean of data."""
        n = len(data)
        if n < 1:
            raise ValueError('mean requires at least one data point')
        return sum(data) / n  # in Python 2 use sum(data)/float(n)

def _ss(data):
    """Return sum of square deviations of sequence data."""
    c = mean(data)
    ss = sum((x-c)**2 for x in data)
    return ss

def stddev(data, ddof=0):
    """Calculates the population standard deviation
    by default; specify ddof=1 to compute the sample
    standard deviation."""
    n = len(data)
    if n < 2:
        raise ValueError('variance requires at least two data points')
    ss = _ss(data)
    pvar = ss/(n-ddof)
    return pvar**0.5



# we use OTX
from OTXv2 import OTXv2, IndicatorTypes

# neo4j
from py2neo import Graph, Node, Relationship, NodeSelector


log = logging.getLogger('cowrie')
log.setLevel(logging.DEBUG)
sh = logging.StreamHandler()
log.addHandler(sh)


#define the neo4j types - we setup indexes on each
TYPES = ['IP', 'Credentials', 'ASN', 'ShellToken', 'File', 'RemoteEndpoint', 'OTXtag', 'Country']

#connect to the neo
neo = Graph(bolt=True, host='localhost', user='neo4j', password='neo')
# selector = NodeSelector(neo)


def add_relationship(tx, source, rtype, ntype, node_names):
    """
    helper to add relationships from a set
    :param tx: neo4j transaction
    :param source: source node
    :param rtype: rel type
    :param ntype: node type
    :param node_names: list of node names to create
    :return:
    """
    assert ntype in TYPES,'Uknown type :{}'.format(ntype)
    map(lambda _: tx.merge(Relationship(source, rtype, Node(ntype, label=_))), node_names)


def add_mirai_hashes_and_creds():
    """
    Helper to read Mirai hashes from disk and add them to the graph

    It expects two files - ./mirai_hash_sha256.csv and ./mirai_creds.csv
    """

    tx = neo.begin()
    n = Node('KnownVirus',name='Mirai')

    with open('./mirai_hash_sha256.csv', 'r') as mh:
        hashes = mh.read().lower().split('\n')
        for hash in hashes:
            tx.merge(Relationship(Node('File', label=hash), 'IDENTIFIEDAS', n))

    with open('./mirai_creds.csv', 'r') as mh:
        for cred in mh.read().split('\n'):
            tx.merge(Relationship(Node('Credentials', label=cred), 'USEDBY', n))

    tx.merge(n)
    tx.commit()

# helpers to parse bash commands into individual tokens
import bashlex

def get_cmd_tokens(cmd):
    """
    helper to unwrap the bashlex format into a flat list
    """
    for _ in bashlex.parse(cmd):
        if _.kind == 'list':
            for __ in _.parts:
                yield __
        else:
            yield _

def parse_cmds(events):
    """
    take a list of cowrie events (with input and timestamp fields) and return a set of bash tokens
    """
    cmds = set()
    last_cmd = []

    for _cmd in map(lambda _:_['input'], sorted(events, key=lambda k:k['timestamp'])):
        try:
            #a bit of a hack to handle multiple line commands
            if last_cmd:
                cmd = ';\n'.join(last_cmd + cmd)
            else:
                cmd = _cmd

            #filter out bash operators such as || and ;
            for token in filter(lambda _:_.kind != 'operator', get_cmd_tokens(cmd)):

                assert token.kind =='command', token.kind
                for wn in token.parts:
                    cmds.add(wn.word)
            last_cmd = []
        except:
            last_cmd.append(_cmd)
    return cmds


class OTX_Cache(object):
    """
    helper to lookup an IP in OTX and cache the result to disk

    put your otx_key in otx_key.secret
    """
    CACHE_DIR = './otx_cache'

    def __init__(self):
        otx_key = open('otx_key.secret', 'r').read().strip()
        self.otx = OTXv2(otx_key)
        if not os.path.exists(self.CACHE_DIR):
            os.mkdir(self.CACHE_DIR)

    def get_ip(self, ip):

        cached = os.path.join(self.CACHE_DIR, '{}.json'.format(ip))

        try:
            with open(cached, 'r') as r:
                result = json.load(r)
        except IOError:

            log.warning('Checking online')
            result = self.otx.get_indicator_details_by_section(IndicatorTypes.IPv4, ip, 'general')
            with open(cached, 'w') as w:
                json.dump(result, w, indent=1, sort_keys=True)
        return result

    def lookup_ip(self, ip):
        result = self.get_ip(ip)

        if result['validation']:
            log.debug(result['validation'])

        tags = set()
        for pulse in result['pulse_info']['pulses']:
            tags.update([_.lower() for _ in pulse['tags']])

        return result['country_name'], tags

def add_to_graph(tx, otx, IP, events):

    # get all timestamps in a list
    dates = map(lambda _:_['timestamp'], events)

    #find the earliest and latest timestamp
    min_dt = parser.parse(min(dates))
    max_dt = parser.parse(max(dates))
    seen_span = (max_dt - min_dt).total_seconds()

    #get OTX data
    data = otx.get_ip(IP)
    country, tags = otx.lookup_ip(IP)

    #use session closed event to calculate "contact" duration
    durations = map(lambda _:_['duration'], filter(lambda _:_['eventid'] == 'cowrie.session.closed', events))

    #IP is unique in our graph... so let's create a node for it
    ip = Node('IP',
              name=IP,
              earliest_seen=min_dt.isoformat(),
              latest_seen=max_dt.isoformat(),
              duration_mean=mean(durations) if len(durations) > 0 else 0,
              duration_stddev=stddev(durations, 1) if len(durations) > 1 else 0,
              seen_span_seconds=seen_span,
              connections=len(durations),
              event_count=len(events)
              )

    tx.merge(ip)

    #add a relationship to Class B and Class C netblocks
    tx.merge(Relationship(ip, "NETWORKED", Node('ClassB', name='.'.join(IP.split('.')[:2]))))
    tx.merge(Relationship(ip, "NETWORKED", Node('ClassC', name='.'.join(IP.split('.')[:3]))))

    try:
        #If we got ASN data from OTX, add that
        tx.merge(Relationship(ip, "NETWORKED",  Node('ASN', name=data['asn'])))
    except KeyError:
        pass


    #collect data from the observed events
    credentials = set()
    commands = []
    downloads = set()
    redirect = set()

    for event in events:

        #credentials used to login to the honeypot
        creds = []

        try:
            creds.append(event['username'].strip())
        except KeyError:
            pass

        try:
            creds.append(event['password'].strip())
        except KeyError:
            pass

        if creds:
            credentials.add(':'.join(creds))

        #shell commands run on the honeypot
        if event['eventid'] in ['cowrie.command.failed', 'cowrie.command.success']:
            commands.append(event)

        #files downloaded
        if event['eventid'] in ['cowrie.session.file_download']:
            downloads.add(event['shasum'])

        #tcpip redirect requests
        if event['eventid'] in ['cowrie.direct-tcpip.request']:
            redirect.add('{}:{}'.format(event['dst_ip'],event['dst_port']))

    #instead of taking each line of commands, parse them into tokens instead
    # ie "tftp; wget; /bin/busybox ZUIHH" -> {'tftp', 'wget', '/bin/busybox', 'ZUIHH'}
    cmds = parse_cmds(commands)

    #add the relationships from this IP to each of the "observables"
    add_relationship(tx, ip, 'USED', 'Credentials', credentials)
    add_relationship(tx, ip, 'RAN', 'ShellToken', cmds)
    add_relationship(tx, ip, 'DOWNLOADED', 'File', downloads)
    add_relationship(tx, ip, 'FORWARDED', 'RemoteEndpoint', redirect)

    #OTX data
    add_relationship(tx, ip, 'TAGGED', 'OTXtag', tags)
    tx.merge(Relationship(ip, 'LOCATED', Node('Country', name=country)))





def get_args():

    parser = argparse.ArgumentParser()

    parser.add_argument('--summary', action='store_true')
    parser.add_argument('--build_graph', action='store_true')
    parser.add_argument('--query_graph', action='store_true')
    parser.add_argument('--data', type=file, nargs='*')

    return parser.parse_args()


def load_json(files):

    data = []

    for f in files:
        for line in f:
            data.append(json.loads(line))

    return data



def graph_data(ips, otx, max_summary=199, top=True):
    tx = neo.begin()
    c=0

    for ip, events in sorted(ips.iteritems(), key=lambda k:len(k[1]), reverse=top)[:max_summary]:
        log.info('[{}] {} had {:,}'.format(c, ip, len(events)))
        log.info(otx.lookup_ip(ip))
        add_to_graph(tx, otx, ip, events)
        c+= 1

        if c % 100:
            tx.commit()
            tx = neo.begin()

    log.info('starting commit')
    tx.commit()
    log.info('commit done')

if __name__ == '__main__':

    args = get_args()
    otx = OTX_Cache()
    if args.summary or args.build_graph:
        data = load_json(args.data)

        ips = collections.defaultdict(list)
        events = collections.Counter()

        for _ in data:
            ips[_['src_ip']].append(_)
            events[_['eventid']] += 1


        if args.summary:

            log.info('{} unique ips from {} records'.format(len(ips), len(data)))
            earliest = parser.parse('2018-01-01T12:00:00Z')
            latest = parser.parse('2010-01-01T12:00:00Z')

            for eventid, count in sorted(events.iteritems(), key=lambda k:k[1], reverse=True):
                log.info('{:,}\t{}'.format(count, eventid))

            s = open('summary.csv','w')

            s.write(','.join(['ip','events','earliest','latest']) + '\n')
            for ip, data in ips.iteritems():

                dates = map(lambda _:parser.parse(_['timestamp']), data)

                min_dt = min(dates)
                max_dt = max(dates)
                earliest = min(min_dt, earliest)
                latest = max(max_dt, latest)

                s.write('{},{},{},{}\n'.format(ip,len(data),min_dt.isoformat(),max_dt.isoformat()))

            s.close()
            log.info('earliest: {}'.format(earliest.isoformat()))
            log.info('latest: {}'.format(latest.isoformat()))
            log.info('Total seconds: {}'.format((latest - earliest).total_seconds()))


        if args.build_graph:

            neo.delete_all()
            add_mirai_hashes_and_creds()
            for t in TYPES:
                neo.run('CREATE CONSTRAINT ON ({0}:{0}) ASSERT {0}.name IS UNIQUE'.format(t))

            graph_data(ips, otx, max_summary=6000, top=True)

    if args.query_graph:
        import cowrie_queries
        cowrie_queries.exec_queries(cowrie_queries, neo)



