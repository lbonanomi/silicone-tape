#!/bin/python

# Webhook
from flask import Flask, request

# GHE
import simplejson as json
import base64
import requests
from requests.auth import HTTPBasicAuth
import sys

# Password hunt
import re
import string
from subprocess import check_output

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

base_url = 'https://MY.GHE.URL/api/v3'

repo_email = 'sending@email_address.com'

token_file = '/flat_file/containing/auto_token'


def gitcat(url, plain_user):
        try:
                ghe_request = requests.get(url, auth=plain_user, verify=False)
                resp = json.loads(ghe_request.text)

                clear = base64.b64decode(resp['content']).lower()

                # Do this instead of stripping punctuation outright to preserve domain names and dotted-quads
                #

                for punc in ("(", ")", "'", "/", ",", ":", "#", '"', '[', ']' '$', '{', '}', '='):
                        clean = clear.replace(punc, ' ')

                clean = clean.split()
                clear = clear.split("\n")

                return clean, clear             # Return a tuple of cleaned-up data and mostly-raw data

        except Exception as e:
                return None, None


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


def crescentwrench(bad_word_array):
        bad_keywords = []
        bad_word_regexes = []

        # Get all keywords from the badwords array into a list for quick-filter of input
        #

        for bad_word in bad_word_array:
                bad_keywords.append(bad_word.keys()[0])

        for bad_words in bad_word_array:
                for phrase in bad_words:
                        for this_bad_word in bad_words[phrase]:
                                bad_word_regex = (phrase + "\s+.*" + this_bad_word).replace('$username', '\S*').replace('$password', '\S+').replace(' ', '\s+')
                                bad_word_regexes.append(bad_word_regex)

        return(bad_keywords, bad_word_regexes)


def bowlder(source, bad_keywords, bad_word_regexes):
        linenumber = 0
        trouble_lines = {}

        for lined in source:
                linenumber = linenumber + 1

                lined = lined.strip("\n")

                for bad_keyword in bad_keywords:
                        if bad_keyword in lined:                                                                                                                                                                                                                                                        # Fast-check for keywords
                                for phrase in bad_word_regexes:                                                                                                                                                                                                                                 #
                                        if re.search(phrase, lined):                                                                                                                                                                                                                            # Confirmed that there is a suspicious idiom here.
                                                for bad_word in bad_word_array:                                                                                                                                                                                                                 # Foreach rule in rules array...
                                                        if bad_word.keys()[0] == bad_keyword:                                                                                                                                                                                           # If the rule matches the keyword that triggered this line's analysis...
                                                                for bad_word_pattern in bad_word[bad_keyword]:                                                                                                                                                                  # Extract every member of the rules set
                                                                        bad_word_pattern_regex = bad_word_pattern.replace('$username', '(\S*)').replace('$password', '(\S+)').replace(' ', '\s+')       # Regenerate a regex to find just-one rule to test

                                                                        if re.search(bad_word_pattern_regex, lined):
                                                                                password_extract = re.search(bad_word_pattern_regex, lined)

                                                                                # THIS IS INSANELY DANGEROUS. I AM WELL-AWARE.

                                                                                try:
                                                                                        acid = 'eval echo "' + password_extract.group(2) + '"'

                                                                                        if len(check_output(acid, shell=True)) > 1:
                                                                                                trouble_lines[linenumber] = "static-password-inline"
                                                                                        else:
                                                                                                # Was it set elsewhere?
                                                                                                waddle = password_extract.group(2).replace('$', '') + "\s*="

                                                                                                relinenumber = 0

                                                                                                for relined in source:
                                                                                                        relinenumber = relinenumber + 1

                                                                                                        relined = relined.strip("\n")

                                                                                                        if re.search(waddle, relined):
                                                                                                                if not re.search('=\$(.*)', relined):   # Don't freak-out about VAR=$(command capture)
                                                                                                                        trouble_lines[relinenumber] = "static-password-def"

                                                                                except Exception:
                                                                                        acid = 'eval echo "' + password_extract.group(1) + '"'

                                                                                        if len(check_output(acid, shell=True)) > 1:
                                                                                                trouble_lines[linenumber] = "static-password-inline"
                                                                                        else:
                                                                                                waddle = password_extract.group(1).replace('$', '') + "\s*="

                                                                                                relinenumber = 0

                                                                                                for relined in source:
                                                                                                        relinenumber = relinenumber + 1

                                                                                                        relined = relined.strip("\n")

                                                                                                        if re.search(waddle, relined):
                                                                                                                if not re.search('=\$(.*)', relined):
                                                                                                                        trouble_lines[relinenumber] = "static-password-def"


        return(trouble_lines)


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


                        # Make a bad-words list:

                        global bad_word_array

                        bad_word_array = [ {'ldapsearch': [ '-w $password' ] }, {'curl': [ '--user $username:$password', '-u $username:$password' ] } ]

                        (bad_keywords, bad_word_regexes) = crescentwrench(bad_word_array)

                        clean_data, clear_data = gitcat(content_url, plain_user)

                        password_problems = bowlder(clear_data, bad_keywords, bad_word_regexes)

                        for erroring_line in password_problems:
                                print "Line: " + str(erroring_line) + " " + password_problems[erroring_line] + "\n"
                                nag(data['pusher']['email'], "Your edit of " + changed_file + " mentions a password-like string  at line " + str(erroring_line) + ". PLEASE look at this, I am a very stupid but very paranoid bot")

                        uniq_words = {}

                        for word in clean_data:
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

