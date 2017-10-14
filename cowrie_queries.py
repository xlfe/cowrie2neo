from py2neo import database
from inspect import getmembers, isfunction


def no_query_ips(neo):

    for r in neo.run("""
    
MATCH (cred:Credentials)<-[:USED]-(ip:IP)
WITH cred, count(ip) AS count
order by count desc
limit 10

match (cred:Credentials)<-[:USED]-(ip:IP)
RETURN cred, ip
    """):
        print r


def count_by_ip(neo, typ):

    q = 'match (_:{})<-[*]-(ip:IP) WITH _, count(ip) as count order by count desc return _.label, count'.format(typ)

    for r in neo.run(q):
        print '{:>6,}\t{}'.format(r['count'], r['_.label'])


def rel_summary(neo):

    q= 'match () <-[r]-(ip:IP) with type(r) as r, count(distinct ip) as count order by count desc return r, count'

    for r in neo.run(q):
        # print '{:>6,}\t{}'.format(r['count'], r['r'])
        yield r['r'], r['count']

def event_count_with_rel(neo, rel):

    q= 'MATCH () <-[r:{}]-(ip:IP) WITH distinct ip WITH sum(ip.event_count) as events return events'.format(rel)

    for r in neo.run(q):
        return r['events']

def count_twohops(neo, endpoint):

    q= """
    MATCH (ip:IP) -[:USED] - (cred:Credentials) - [:USEDBY] - (virus:KnownVirus)  
    WITH distinct ip 
    WITH sum(ip.event_count) as count, count(ip) as ips 
    RETURN count, ips
    """

MIRAI_DOWNLOADS = 'MATCH (ip:IP) - [:DOWNLOADED] - (hash:File) - [:IDENTIFIEDAS] - (`Mirai`)'

def query_count_hosts_with_mirai_downloads():
    """
    Snippet 1 - Count the number of hosts that downloaded files, where the file hash matched a Mirai variant from Virus Total
    Also count the number of total events these hosts represent
    """
    return MIRAI_DOWNLOADS + """
    WITH distinct ip 
    WITH sum(ip.event_count) as count, count(ip) as ips 
    RETURN count, ips
    """

def query_duration_summary_hosts_with_mirai_downloads():
    """
    Snippet 2 - Summary of the duration of contact for those hosts that downloaded files,
    where the file hash matched a Mirai variant from Virus Total
    """
    return MIRAI_DOWNLOADS + """
    WITH distinct ip 
    order by ip.duration_mean asc
    RETURN ip.name, ip.connections, ip.seen_span_seconds,
        ip.duration_mean, ip.duration_stddev
    """

def run_tags(neo):
    for rel, count in rel_summary(neo):
        print ('{} {} {}'.format(rel, count, event_count_with_rel(neo, rel)))
    # count_by_ip(neo, 'OTXtag')
    # count_by_ip(neo, 'File')

def exec_queries(obj, neo):
    """
    helper that runs all queries in this file
    """

    for name, func in getmembers(obj):
        if isfunction(func):

            if name.startswith('query_'):

                doc = getattr(func, '__doc__', None)
                if doc:
                    print ''
                    print doc
                results =  [_ for _ in neo.run(func())]
                print '\t'.join(results[0].keys())
                for r in results:
                    print '\t'.join([str(_) for _ in r.values()])

                print '\n\n--\n'

            elif name.startswith('run_'):
                func(neo)
