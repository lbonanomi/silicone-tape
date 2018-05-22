#!/opt/bb/bin/python

# Webhook
from flask import Flask, request

# GHE
import simplejson as json
import base64
import requests
from requests.auth import HTTPBasicAuth
import sys

# Nag emails
import smtplib
from email.mime.text import MIMEText

# Hostname-finding
import dns.resolver
from IPy import IP

# Username finding
import pwd

#
#

base_url = 'https://bbgithub.dev.bloomberg.com/api/v3'

repo_email = 'lbonanomi2@bloomberg.net'

token_file = '/home/lbonanomi2/.ssh/.ghe_token'


def gitcat(url, plain_user):
        try:
                ghe_request = requests.get(url, auth=plain_user, verify=False)
                resp = json.loads(ghe_request.text)

                clear = base64.b64decode(resp['content']).lower()

                # Do this instead of stripping punctuation outright to preserve domain names and dotted-quads
                #

                for punc in ("(", ")", "'", "/", ",", ":", "#", '"', '[', ']' '$', '{', '}', '='):
                        clear = clear.replace(punc, ' ')

                text = clear.split()

                return(text)
        except Exception as e:
                return()


def token(candidate):
                acid = requests.get(base_url + '/user', auth=HTTPBasicAuth('', candidate), verify=False)

                if acid.status_code == 200:
                        return(1)
                else:
                        return(0)


def get_sweet_sha(repo_name):
        url = base_url + '/repos/' + repo_name + '/commits'
        ghe_request = requests.get(url, auth=plain_user, verify=False)
        return(ghe_request.json()[0]['parents'][0]['sha'])


def rebase(sha, repo_name):

        print "REBASING!!"

        url = base_url + '/repos/' + repo_name + '/git/refs/heads/master'
        payload = json.dumps({ "sha":sha, "force":True })
        requests.patch(url, auth=plain_user, data=payload, verify=False)


def nag(pusher, mail_text):
        msg = MIMEText(mail_text)

        msg['Subject'] = 'About Your GitHub Edit...'
        msg['From'] = repo_email
        msg['To'] = pusher

        s = smtplib.SMTP('localhost')
        s.sendmail(repo_email, pusher, msg.as_string())
        s.quit()


def resolve(candidate):

        if candidate == "localhost":
                return(0)

        resolver = dns.resolver.Resolver()

        try:
                for duck in resolver.query(candidate, "A"):
                        if IP(str(duck)).iptype() == "PRIVATE":
                                return(1)

        except Exception as e:
                return(0)


def finger(candidate):
        try:
                pwd.getpwnam(candidate)
                return(1)
        except Exception as e:
                return(0)


try:
        with open(token_file) as token_file:
                token_value = token_file.readline().strip()

except IOError:
        print "Can't find a GHE credential file"
        sys.exit(1)


plain_user = HTTPBasicAuth('', token_value)


app = Flask(__name__)
@app.route("/", methods=['POST'])
def verify_traffic():
        data = request.get_json()

        hashes = {}

        rewind_to = get_sweet_sha(data['repository']['full_name'])

        url = base_url + '/repos/' + data['repository']['full_name'] + '/contents?ref=' + rewind_to
        for rewind_hash in requests.get(url, auth=plain_user, verify=False).json():
                hashes[rewind_hash['sha']] = rewind_hash['path']


        url = base_url + '/repos/' + data['repository']['full_name'] + '/contents?ref=' + 'master'
        print "MASTER_URL: " + url


        for master_hash in requests.get(url, auth=plain_user, verify=False).json():
                if master_hash['sha'] not in hashes:
                        content_url = base_url + '/repos/' + data['repository']['full_name'] + '/contents/' + master_hash['path']

                        try:
                                data['commits'][0]['added']

                                if len(data['commits'][0]['added']) > 0:
                                        content_url = base_url + '/repos/' + data['repository']['full_name'] + '/contents/' + data['commits'][0]['added'][0]
                                        changed_file = data['commits'][0]['added'][0]
                        except IndexError:
                                continue

                        try:
                                data['commits'][0]['modified']

                                if len(data['commits'][0]['modified']) > 0:
                                        content_url = base_url + '/repos/' + data['repository']['full_name'] + '/contents/' + data['commits'][0]['modified'][0]
                                        changed_file = data['commits'][0]['modified'][0]
                        except IndexError:
                                continue


                        uniq_words = {}

                        for word in gitcat(content_url, plain_user):
                                uniq_words[word] = word


                        for word in uniq_words:
                                # Auth-token hunt:
                                #

                                if len(word) == 40:
                                        if token(word):
                                                nag(data['pusher']['email'], "Your edit of " + changed_file + " mentioned an active application token and has been automatically rebased back to the previous version.")
                                                rebase(rewind_to, data['repository']['full_name'])


                                # Internal-hostname hunt
                                #

                                if len(word) > 3:
                                        if resolve(word):
                                                nag(data['pusher']['email'], "This push mentions internal hostname \"" + word + "\".")


                                # Named-user hunt
                                #

                                if finger(word):
                                        nag(data['pusher']['email'], "This push mentions username \"" + word + "\".")

        return("")

if __name__ == "__main__":
        app.run(host='0.0.0.0', port=8008)

