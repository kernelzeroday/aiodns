#!/usr/bin/env python3
# encoding: utf-8

import asyncio
import aiodns
import json
from netaddr import *
from optparse import OptionParser
from ipaddress import ip_address
from colorama import init, Fore, Style
from random import randint
import uvloop
import time


init(autoreset=True)


def gen_ips(outfile='ips.list', n=1000):
    """
    generate random ips for testing
    :param outfile: write to
    :param n: how many ips
    :return:
    """
    for i in range(n):
        ip = ".".join(map(str, (randint(0, 255)
                                for _ in range(4))))
        with open(outfile, 'a') as f:
            f.write(ip + "\n")


class SwarmResolver:
    """ A simple class which will resolve a list of domains asyncrionously """

    def __init__(self, num_workers=5, nameservers=['8.8.8.8', '8.8.4.4'], loop=None, qtype="A"):
        #self.loop = loop or asyncio.get_event_loop()
        self.loop = uvloop.new_event_loop()
        asyncio.set_event_loop(loop)
        assert self.loop is not None

        self.num_workers = num_workers
        self.nameservers = nameservers
        self.qtype = qtype
        self.results = {}

    # Creates a task queue made up of all the domains within the passed list.
    # Will startup an event loop and split up the list amongst num_workers worth of workers.
    # Returns the list of domains within domain_list as well as the results of their dns lookup.
    def resolve_list(self, domain_list, output, json_output):
        """
        task creator
        :param domain_list: list of domains or ips in this case to resolve
        :param output: name of log file
        :param json_output: json output or not
        :return: results of ptr queries
        """
        tasks = []
        q = asyncio.Queue()

        for domain in domain_list:
            q.put_nowait(domain)

        for i in range(self.num_workers):
            tasks.append(self.do_work(q, output, json_output))
        self.loop.run_until_complete(asyncio.wait(tasks))
        return (self.results)

    # Will asynchronously perform a DNS lookup for the qtype and for the domains within the current shared Queue.
    # Will populate the shared results dictionary with results for each performed dns lookup.
    async def do_work(self, work_queue, output, json_output):

        def writer(data):
            """
             Logger function
            :param data: data to write to file
            :return: -
            """
            with open(output, 'a') as ff:
                ff.write(str(data) + "\n")

        resolver = aiodns.DNSResolver(loop=self.loop, nameservers=self.nameservers, timeout=2, tries=1)
        results = []

        while not work_queue.empty():

            domain = await work_queue.get()

            try:
                _domain = str(domain)
            except:
                pass
            try:
                res = await resolver.query(ip_address(domain).reverse_pointer, 'PTR')
                self.results[domain] = res
            except aiodns.error.DNSError as e:
                error_code = e.args[0]
                if error_code == aiodns.error.ARES_ECONNREFUSED:
                    self.results[domain] = "CONNECTION_REFUSED"
                elif error_code == aiodns.error.ARES_ENODATA:
                    self.results[domain] = "NODATA"
                elif error_code == aiodns.error.ARES_ENOTFOUND:
                    self.results[domain] = "NXDOMAIN"
                elif error_code == aiodns.error.ARES_EREFUSED:
                    self.results[domain] = "REFUSED"
                elif error_code == aiodns.error.ARES_ESERVFAIL:
                    self.results[domain] = "SERVFAIL"
                elif error_code == aiodns.error.ARES_ETIMEOUT:
                    self.results[domain] = "TIMEOUT"
                else:
                    self.results[domain] = "UNKNOWN_STATUS"

            except Exception as e:
                print(_domain + ' error: ' + str(e))
            else:

                res = str(res)
                res = res.strip('<ares_query_ptr_result> ')
                res = res.split(',')
                try:
                    name = res[0].strip('name=')
                except:
                    pass
                try:
                    name = res[0].strip('(name=')
                except:
                    pass
                ttl = res[1]
                ttl_ = ''
                for i in ttl:
                    if i.isdigit():
                        ttl_ += i

                # aliases = res[2].strip('aliases=')
                if json_output:
                    ret = json.loads(json.dumps({"ip": domain, "name": name, "ttl": ttl_}))
                else:
                    ret = Fore.GREEN + 'IP : ' + Fore.RESET + domain + Fore.RED + ' | ' + 'PTR: ' + Style.BRIGHT +\
                          Fore.RESET + name + Style.RESET_ALL +\
                          Fore.BLUE + ' | TTL: ' + Fore.RESET + ttl_

                #writer(ret)
                #print(ret)
                results.append(ret)

            work_queue.task_done()
            for ii in results:
                writer(ii)
                print(ii)

    # Helper for handling exceptions.
    async def handle_exception():
        try:
            await bug()
        except Exception:
            print("exception consumed")


class Resolver:
    """
    Wrapper class for swarm resolver
    """
    def setUp(self, domains, output, json_output, num_workers=100):
        """

        :param domains: list of ips to query
        :param output: name of output file
        :param json_output: json output or not
        :param num_workers: number of async workers
        :return:
        """
        self.loop = asyncio.new_event_loop()
        self.domains = domains
        self.num_workers = num_workers
        self.output = output
        self.swarm = SwarmResolver(qtype="PTR", num_workers=num_workers, loop=self.loop)
        self.json_output = json_output

    def tearDown(self):
        self.swarm = None

    def test_domain_list_resolve_ns(self):
        self.swarm.resolve_list(self.domains, self.output, self.json_output)


def line_gen(list_file):
    """

    :param list_file: list of ip addresses / ip blocks , one per line
    example list file:
            1.2.3.4
            2.3.4.5
            1.1.1.1/24
    :return: list of ips to query
    """
    domains = []
    with open(list_file, 'r') as f:
        f = f.readlines()
        for line in f:
            line = line.strip("\n\r")
            if line != '':
                try:
                    line = IPAddress(line)
                except:
                    try:
                        line = IPNetwork(line)
                    except:
                        pass
                    else:
                        # Expand if net block
                        for i in IPNetwork(line).iter_hosts():
                            domains.append(str(i))
                else:
                    domains.append(str(line))
        return domains


def main():
    usage = "Asynchronously resolve PTR records from list or cli."
    usage += "./ptr_async.py <--list ips.list>/<--query 8.8.8.8>"
    parser = OptionParser(usage)
    parser.add_option("-q", "--query",
                      type="str", dest="query", help='Query single ip or network'
                                                     'Example: "1.2.3.4"')
    parser.add_option("-l", "--list", dest='query_list', help='List of queries')
    parser.add_option("-n", "--num_workers", dest='num_workers', type='int', help='Async workers')
    parser.add_option("-o", "--output", dest='output', help='Output file')
    parser.add_option("-j", '--json', dest='json_output', action='store_true', help='Output in json')
    parser.add_option("-g", "--gen_ips", dest='gen_ips', action='store_true', help='Generate a list of ips to '
                                                                                   'test with.')

    (options, args) = parser.parse_args()

    if len(args) > 1:
        parser.error("No argument given. Run --help for usage.")
    if options.gen_ips:
        print('Writing 1000 ips to ips.list ...')
        gen_ips()
        exit(0)
    if options.num_workers:
        detect_num_workers = False
        num_workers = options.num_workers
    else:
        num_workers = 0
        detect_num_workers = True

    if options.output:
        output = options.output
    else:
        output = 'ptr.log'
    if options.json_output:
        json_output = options.json_output
    else:
        json_output = False
    if options.query_list:
        infile = options.query_list
        try:
            domains = line_gen(infile)
        except:
            print('Error parsing %s' % infile)
        else:
            if detect_num_workers:
                for i in domains:
                    num_workers += 1
            print('Using %d workers ...' % num_workers)
            print(Fore.RED + 'Resolving ptr records from list %s ... ' % infile)
            s = Resolver()
            s.setUp(domains, output, json_output, num_workers)
            t = time.process_time()
            s.test_domain_list_resolve_ns()
            elapsed_time = time.process_time() - t
            print(Fore.YELLOW + "--------------------------------------------------------------------------")
            print("Finished! Process time: " + str(elapsed_time))

        exit(0)

    if options.query:
        num_workers = 1
        query = options.query
        print(Fore.RED + "Querying %s..." % query)
        domain = [query]
        s = Resolver()
        s.setUp(domain, output, json_output, num_workers)
        s.test_domain_list_resolve_ns()
    else:
        print('Please supply a query <-q> Example: "1.2.3.4"')
        exit(1)


if __name__ == "__main__":
    main()
