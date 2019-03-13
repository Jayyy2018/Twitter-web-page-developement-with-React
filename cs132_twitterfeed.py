################################################################
################################################################
################################################################
################################################################

# [Import Statements]

################################################################
################################################################
################################################################
################################################################

import base64, datetime, json, os, random, signal, socketserver, subprocess, sys
DEV_NULL = open(os.devnull, 'w')
if subprocess.call(["pip3", "show", "requests"], stdout=DEV_NULL):
    subprocess.call(["pip3", "install", "--upgrade", "requests"])
import requests
from http.server import BaseHTTPRequestHandler

################################################################
################################################################
################################################################
################################################################

# [Prompting]

################################################################
################################################################
################################################################
################################################################

GREEN='\033[92m'
RED='\033[91m'
END='\033[0m'
def print_green(msg):
    """
    Print a pretty green message to stdout

    Args:
        msg: A string to print in color
    Returns:
        None
    """
    print("%s%s%s" % (GREEN, msg, END))


def print_red(msg):
    """
    Print a pretty red message to stdout

    Args:
        msg: A string to print in color
    Returns:
        None
    """
    print("%s%s%s" % (RED, msg, END))

################################################################
################################################################
################################################################
################################################################

# [Credential]

################################################################
################################################################
################################################################
################################################################

batch_pull_cred_index = 0
backup_pull_cred_index = 1
consumer_key = ['0sVMm9FTJjMcIXlwcOlTbiZL9', 'CxNW4dbGgBhpPvt0YRn6tOgPg']
consumer_secret = ['GmuYTOfVUGiFjWxtP2rVf0gC2ox2vlQaRtzy4ZMno9piYvHOVO', 'xnv05OUBTvpwZyw2n8ujWxLiYpRQiMY766paD7ojqXloaqlylt']
access_token_key = ['2890024349-9m6NYBsn7I0YFtAUWSKrKJ3EH3131CesVJyCHDO', '4846560701-JDwgLQHKAdZiASRnpwdAHQSx9qzDvSX25JLDcQU']
access_token_secret = ['DRGmpniGzRiD3uFYI9t48v17C6KIcfNUsVtLOjh9KOCi1', 'Y6gG4tpZiReGydRHigSWFZTszCW31iKpRxuKTj8whKpAP']

################################################################
################################################################
################################################################
################################################################

# [URLs]

################################################################
################################################################
################################################################
################################################################

base_url = 'https://api.twitter.com/'
auth_url = '{}oauth2/token'.format(base_url)
search_url = '{}1.1/search/tweets.json'.format(base_url)

################################################################
################################################################
################################################################
################################################################

# [Authorization]

################################################################
################################################################
################################################################
################################################################

def obtain_access_token(cred_index=batch_pull_cred_index):
    key_secret = '{}:{}'.format(consumer_key[cred_index], consumer_secret[cred_index]).encode('ascii')
    b64_encoded_key = base64.b64encode(key_secret).decode('ascii')

    auth_headers = {
                        'Authorization': 'Basic {}'.format(b64_encoded_key),
                        'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8'
                                                    }

    auth_data = {
                        'grant_type': 'client_credentials'
                                    }

    auth_resp = requests.post(auth_url, headers=auth_headers, data=auth_data)
    access_token = auth_resp.json()['access_token']
    return access_token

access_tokens = (obtain_access_token(), obtain_access_token(cred_index=backup_pull_cred_index))

################################################################
################################################################
################################################################
################################################################

# [Search]

################################################################
################################################################
################################################################
################################################################

topic = None
def consolidat_topic():
    global topic, more_frequent
    default_topic = "pizza"
    argc = len(sys.argv)
    if argc == 1:
        print_green("[OK] Topic default to %s" % default_topic)
        topic = default_topic
    elif argc == 2:
        topic = sys.argv[1].strip()
        if topic == '-r':
            print_green("[OK] Tweets will be more repetitive")
            more_frequent = True
            sys.argv.pop(1)
            consolidat_topic()
    elif argc == 3:
        if sys.argv[1] == '-r':
            print_green("[OK] Tweets will be more repetitive")
            more_frequent = True
            sys.argv.pop(1)
            consolidat_topic()
    else:
        print_red("ERROR: Correct Usage: cs132_twitterfeed <topic>")
        sys.exit(1)
    print_green("[OK] Will be pulling tweets about %s" % topic)
consolidat_topic()


def get_tweets(num_tweets, cred_index=batch_pull_cred_index):
    access_token = access_tokens[cred_index]
    search_headers = {
        'Authorization': 'Bearer {}'.format(access_token)
    }

    search_params = {
        'q': topic,
        'result_type': 'recent',
        'count': num_tweets
    }
    print_green("Pulling using credential set %d" % cred_index)
    search_resp = requests.get(search_url, headers=search_headers, params=search_params)
    return search_resp.json()

################################################################
################################################################
################################################################
################################################################

# [Caching]
# prevent get rate limited

################################################################
################################################################
################################################################
################################################################
buf_time = 10  # how long to start a new pull
num_tweets_to_select = 26  # number of tweets sent as response
more_frequent = False
cached_tweets = dict()

def make_timestamp():
    return datetime.datetime.timestamp(datetime.datetime.now())


def exceed_buffer_time_from_last_pull(timestamp):
    last_pull_time = datetime.datetime.fromtimestamp(float(timestamp))
    time_diff = datetime.datetime.now() - last_pull_time
    return time_diff.total_seconds() > buf_time * 60


def on_department_machine():
    return os.path.isfile('/course/cs1320/bin/cs132_twitterfeed')


def parse_cached_tweets(cached_filepath, in_memory=False):
    if in_memory: # cached in memory
        timestamp = cached_tweets['timestamp']
        if exceed_buffer_time_from_last_pull(timestamp):
            return False
        return json.loads(cached_tweets['tweets'])

    if os.stat(cached_filepath).st_size == 0:
        return False

    with open(cached_filepath) as tweets_lib:
        timestamp = tweets_lib.readline()
        if exceed_buffer_time_from_last_pull(timestamp):
            return False
        return json.load(tweets_lib)


def cache_pulled_tweets(cached_filepath, in_memory=False):
    num_tweets_to_pull = calculate_tweets_pull()
    new_tweets = get_tweets(num_tweets_to_pull, cred_index=(backup_pull_cred_index if in_memory else batch_pull_cred_index))

    if in_memory:
        cached_tweets['timestamp'] = make_timestamp()
        cached_tweets['tweets'] = json.dumps(new_tweets)
    else:
        with open(cached_filepath, 'w+') as tweets_lib:
            tweets_lib.write("%d\n" % make_timestamp())
            json.dump(new_tweets, tweets_lib)
        subprocess.call(['chmod', '664', cached_filepath])
        subprocess.call(['chgrp', 'cs-1320ta', cached_filepath])
        subprocess.call(['setfacl', '-m', 'g:cs-1320student:rw', cached_filepath])

    return new_tweets


def cached_get_tweets():
    in_memory = not on_department_machine()
    cached_filepath = None if in_memory else os.path.join('/course/cs1320/bin/tweets_lib', topic)

    if (in_memory and cached_tweets) or (not in_memory and os.path.isfile(cached_filepath)):
        last_pulled_tweets = parse_cached_tweets(cached_filepath, in_memory)
        if last_pulled_tweets: # use cached tweets
            print_green("[OK] Generate a pack of tweets from cache")
            return select_tweets(last_pulled_tweets)
    # regenerate a cache
    newly_pulled_tweets = cache_pulled_tweets(cached_filepath, in_memory)
    print_green("[OK] Generate a pack of tweets from a new search")
    return select_tweets(newly_pulled_tweets)


def calculate_tweets_pull():
    factor = 1 if more_frequent else 20
    return buf_time * num_tweets_to_select * factor


def select_tweets(tweets):
    tweets_to_send = {'search_metadata': tweets['search_metadata'], 'statuses': random.sample(tweets['statuses'], num_tweets_to_select)}
    return tweets_to_send

################################################################
################################################################
################################################################
################################################################

# [server]

################################################################
################################################################
################################################################
################################################################

portnum = 8081
class TweetsFeeder(BaseHTTPRequestHandler):
    def do_GET(self):
        print("<----- Request Start ----->")
        print("request_path :", self.path)
        print("self.headers :", self.headers)
        print("<----- Request End ------->\n")

        if self.path == '/feed/start':
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Methods", "GET")
            self.end_headers()
            print_green("[OK] Sending a pack of tweets")
            self.wfile.write(json.dumps(cached_get_tweets()).encode('utf-8'))


orig_sigint_handler = None
def start_server():
    def probe_port():
        global portnum;
        try:
            return socketserver.TCPServer(("", portnum), TweetsFeeder)
        except OSError:
            portnum += 1
            return probe_port()

    global orig_sigint_handler 
    clean_process_on_port()
    print_green("[OK] Starting the server")
    httpd = probe_port()
    print_green("[OK] Type CTRL-C to stop server")
    orig_sigint_handler = signal.signal(signal.SIGINT, stop_server)
    print_green("[OK] Server has been started")
    print_green("[OK] Server is listening to http://localhost:%s/feed/start" % portnum)
    httpd.serve_forever()


def stop_server(sig, frame):
    # stop pulling new tweets
    signal.signal(signal.SIGINT, orig_sigint_handler)
    # shutdown the server
    print_green("[OK] server stopped")
    sys.exit(0)


def clean_process_on_port():
    if os.name != 'nt':
        try:
            pid = int(subprocess.check_output(["lsof", "-t", "-i:%d" % portnum]).strip())
            subprocess.call(["kill", str(pid)])
            print_green("[OK] Cleared process %d on %d" % (pid, portnum))
        except subprocess.CalledProcessError:
            print_green("[OK] No process on %s" % portnum)

start_server()
