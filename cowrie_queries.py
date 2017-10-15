from py2neo import database
from inspect import getmembers, isfunction


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


MIRAI_DOWNLOADS = 'MATCH (ip:IP) - [:DOWNLOADED] - (hash:File) - [:IDENTIFIEDAS] - (`Mirai`)'

def query_count_hosts_with_mirai_downloads():
    """
    Snippet 01 - Count the number of hosts that downloaded files, where the file hash matched a Mirai variant from Virus Total
    Also count the number of total events these hosts represent
    """
    return MIRAI_DOWNLOADS + """
    WITH distinct ip 
    WITH sum(ip.event_count) as count, count(ip) as ips 
    RETURN count, ips
    """

def query_duration_summary_hosts_with_mirai_downloads():
    """
    Snippet 02 - Count known Mirai hosts with average connection duration less than 60s
    """
    return MIRAI_DOWNLOADS + """
    WITH distinct ip
    order by ip.duration_mean asc 
    RETURN ip.name, ip.duration_mean, ip.connections
    """


def query_duration_all_hosts():
    """
    Snippet 03 - Duration of all hosts
    """
    return """
    MATCH (ip:IP)
    WITH distinct ip
    order by ip.duration_mean asc 
    RETURN ip.name, ip.duration_mean, ip.event_count, ip.connections
    """

def query_count_all_hosts_using_any_mirai_credentials():
    """
    Snippet 04 - Count of the hosts using known Mirai credentials
    """

    return """
    MATCH (ip:IP) -[:USED] - (cred:Credentials) - [:USEDBY] - (`Mirai`)
    WITH distinct ip 
    WITH sum(ip.event_count) as count, count(ip) as ips 
    RETURN count, ips
    """

def query_count_all_credentials_used_by_any_hosts_using_mirai_credentials():
    """
    Snippet 05 - Count all the credentials used by any host using known Mirai credentials
    """

    return """
    MATCH (ip:IP) -[:USED] - (cred:Credentials) - [:USEDBY] - (`Mirai`)
    
    MATCH (ip:IP) - [:USED] - (a:Credentials)
    with count(distinct ip) as ips, count(distinct a) as total_creds
    
    return total_creds, ips
    
    """

def query_tags_of_known_mirai_hosts():
    """
    Snippet 06 - Count the tags against IPs of known mirai hosts
    """

    return MIRAI_DOWNLOADS + """
    MATCH (ip:IP) - [r:TAGGED] - (tag:OTXtag)
    with tag, count(distinct ip) as ip_count
    return tag.label, ip_count
    """

# great examples from neo4j documentation https://neo4j.com/developer/guide-build-a-recommendation-engine/
def query_mirai_collaborative_filtering_on_file_hash():
    """
    Snippet 07 - Find file hashes of files VirusTotal didn't identify as Mirai,
    but were downloaded by hosts that also downloaded a File VirusTotal did identify as Mirai
    """
    return """
    MATCH (`Mirai`)<-[:IDENTIFIEDAS]-(file:File),
          (file:File)<-[:DOWNLOADED]-(ip:IP)-[:DOWNLOADED]->(potential:File)
    WHERE NOT (potential)-[:IDENTIFIEDAS]->(`Mirai`)
    RETURN distinct potential.label
"""

def query_mirai_collaborative_filtering_on_credentials_creds_list():
    """
    Snippet 08 - count the number of hosts that use credentials used by other Mirai hosts but dont use any known Mirai creds
    """
    return """
   MATCH (:KnownVirus) - [:USEDBY] - (cred:Credentials) - [:USED] - (ip:IP)
   MATCH (ip) -[:USED]-> (other:Credentials)
        WHERE   NOT    (other) -[:USEDBY]-(:KnownVirus)
        WITH other as bad_cred, count(distinct ip) as ips
        order by ips desc
        where ips >1
    return bad_cred.label, ips
    limit 10
        
    """


def query_mirai_collaborative_filtering_on_credentials_ips():
    """
    Snippet 09 - count the number of hosts that use credentials used by other Mirai hosts but dont use any known Mirai creds
    """
    return """
   MATCH (:KnownVirus) - [:USEDBY] - (cred:Credentials) - [:USED] - (ip:IP)
   MATCH (ip) -[:USED]-> (other:Credentials)
        WHERE   NOT    (other) -[:USEDBY]-(:KnownVirus)
        WITH other as bad_cred, count(distinct ip) as ips
        where ips > 20
    MATCH (new_bad) -[:USED] ->(bad_cred)
    where not (new_bad) -[:USED]->(:Credentials)-[:USEDBY]-(:KnownVirus)
    return new_bad.name
        
    """

def query_mirai_creds_with_forwarding_count():
    """
    Snippet 10a - count of hosts using mirai creds for port forwarding
    """
    return """
    MATCH (ip) - [r:FORWARDED] - (dest:RemoteEndpoint)
    WHERE (ip) -[:USED]->(:Credentials)- [:USEDBY] -(:KnownVirus)
    with distinct ip
    return count(ip) as ips, sum(ip.event_count) as events
    """

def query_all_forwarding_count():
    """
    Snippet 10b - count of hosts not using mirai credentials for port forwarding
    """
    return """
    MATCH (ip:IP) - [r:FORWARDED] - (dest:RemoteEndpoint)
        WHERE NOT (ip) -[:USED]->(:Credentials)- [:USEDBY] -(:KnownVirus)
    with distinct ip
    return count(ip) as ips, sum(ip.event_count) as events
    """

def query_mirai_creds_with_forwarding():
    """
    Snippet 11a - find hosts using Mirai credentials with port forwarding
    """

    return """
    MATCH 
            (ip) - [r:FORWARDED] - (dest:RemoteEndpoint)
    WHERE (ip) -[:USED]->(:Credentials)- [:USEDBY] -(:KnownVirus)
    with split(dest.label,':')[1] as dst_port
    return dst_port, count(dst_port) as count
    """


def query_all_forwarding():
    """
    Snippet 11b - find hosts port forwarding but not using Mirai creds
    """

    return """
    MATCH (ip:IP) - [r:FORWARDED] - (dest:RemoteEndpoint)
        WHERE NOT (ip) -[:USED]->(:Credentials)- [:USEDBY] -(:KnownVirus)
    with split(dest.label,':')[1] as dst_port
    return dst_port, count(dst_port) as count
    """


def query_ips_not_mirai_not_otx_tagged():
    """
    Snippet 12 - list ips that are not identified as mirai and not forwarding
    """
    return """
   MATCH (ip:IP)
   
   where NOT (ip) - [:USED] - (:Credentials) - [:USEDBY] - (:KnownVirus) 
   AND NOT (ip) - [:TAGGED] - ()
   with distinct ip
   match (ip) - [rel] -(ep)
   with type(rel) as rel, ep.label as ep, count(distinct ip) as ips
   order by rel asc, ips desc
   return rel, ep, ips
   """

UNKNOWN = 'MATCH (ip:IP) -[:DOWNLOADED] - (file {label:"2d84ed8889e51086dee0112a0cfe9b02d720be83ceeae2f5e2c03fff9a6df0df"})'

def query_unknown_download():
    """
    Snippet 13 - examine the activity of those 50 hosts
    downloading unidentified file 2d84ed8889e51086dee0112a0cfe9b02d720be83ceeae2f5e2c03fff9a6df0df
    """
    return UNKNOWN + """
   match (ip) - [rel] -(ep)
   with type(rel) as rel, ep.label as ep, count(distinct ip) as ips
   order by rel asc, ips desc
   return rel, ep, ips
    """

def query_find_other_downloads():
    """
    Snippet 14 - find any other hosts that ran many of the same commands as our unidentified sample but did not download
    the file
    """
    return UNKNOWN + """
   match (ip) - [:FORWARDED] - >(cmd)<- [:FORWARDED] - (other:IP)
   WHERE NOT (other) -[:DOWNLOADED] - (file {label:"2d84ed8889e51086dee0112a0cfe9b02d720be83ceeae2f5e2c03fff9a6df0df"})
   with distinct other, count(distinct cmd) as cmds
   order by cmds desc
   return distinct other.name, cmds
   limit 10
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
    funcs = {}
    other = []

    for name, func in getmembers(obj):
        if isfunction(func):

            if name.startswith('query_'):
                assert func.__doc__
                funcs[func.__doc__] = func

            elif name.startswith('run_'):
                other.append(func)

    for doc, func in sorted(funcs.iteritems(),key=lambda k:k[0]):
        print ''
        print doc
        results =  [_ for _ in neo.run(func())]
        print '\t'.join(results[0].keys())
        for r in results:
            print '\t'.join([str(_) for _ in r.values()])

        print '\n\n--\n'

    [_(neo) for _ in other]

