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

                #clear = base64.b64decode(resp['content']).lower()
                clear = base64.b64decode(resp['content'])

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

        # Get all top-level dictionary keys from input array into a list to use as a quick-filter of input
        #

        for bad_word in bad_word_array:
                bad_keywords.append(bad_word.keys()[0])


        for bad_words in bad_word_array:
                for phrase in bad_words:
                        for this_bad_word in bad_words[phrase]:

                                if '(' in this_bad_word:
                                        # Lets call this a function method and not massage it
                                        bad_word_regex = (phrase + "\s*" + this_bad_word ).replace('$username', '\S*').replace('$password', '\S+').replace(' ', '\s+')

                                else:
                                        bad_word_regex  = (phrase + "\s+.*?" + this_bad_word).replace('$username', '\S*').replace('$password', '\S+').replace(' ', '\s+')

                                bad_word_regexes.append(bad_word_regex)

        return(bad_keywords, bad_word_regexes)


def bowlder(source, bad_keywords, bad_word_regexes):
        linenumber = 0
        trouble_lines = {}

        for lined in source:
                linenumber = linenumber + 1

                lined = lined.strip("\n")

                for bad_keyword in bad_keywords:
                        if bad_keyword in lined:                                                                                                                                                        # Fast-check for keywords
                                for phrase in bad_word_regexes:                                                        											#
                                        if re.search(phrase, lined):                                                        										# Confirmed that there is a suspicious idiom here.
                                                for bad_word in bad_word_array:                                                        									# Foreach rule in rules array...
                                                        if bad_word.keys()[0] == bad_keyword:                                                        				        		# If the rule matches the keyword that triggered this line's analysis...
                                                                for bad_word_pattern in bad_word[bad_keyword]:                                                        					# Extract every member of the rules set
                                                                        bad_word_pattern_regex = bad_word_pattern.replace('$username', '(\S*)').replace('$password', '(\S+)').replace(' ', '\s+')       # Regenerate a regex to find just-one rule to test

                                                                        if re.search(bad_word_pattern_regex, lined):

                                                                                buffer_array = []
                                                                                password_extract = re.search(bad_word_pattern_regex, lined)

                                                                                for num in range(1,11):                                                        						# I'm not crazy about this, but regex gags trying to handle functions.
                                                                                        try:                                                        						        #
                                                                                                value = password_extract.group(num).replace('(', '').replace(')', '')           

                                                                                                buffer_array.append(value)
                                                                                        except IndexError:
                                                                                                continue

                                                                                grouping = buffer_array.pop()

                                                                                try:
                                                                                        acid = 'eval echo "' + str(grouping) + '"'

                                                                                        if len(grouping) > 0:

                                                                                                try:
                                                                                                        acidtest = check_output(acid, shell=True)

                                                                                                        if len(acidtest) > 1:
                                                                                                                trouble_lines[linenumber] = "static-password-inline"
                                                                                                        else:
                                                                                                                # Is this a password defined elsewhere in-file?
                                                                                                                waddle = grouping.replace('$', '') + "\s*="

                                                                                                                relinenumber = 0

                                                                                                                for relined in source:
                                                                                                                        relinenumber = relinenumber + 1

                                                                                                                        relined = relined.strip("\n")

                                                                                                                        if re.search(waddle, relined):
                                                                                                                                if not re.search('=\$(.*)', relined):   # Don't freak-out about VAR=$(command capture)
                                                                                                                                        trouble_lines[relinenumber] = "static-password-def"

                                                                                                # If the eval fails, escalate to a reviewer
                                                                                                #

                                                                                                except Exception as acid_test_exception:
                                                                                                        if str(acid_test_exception).find("returned non-zero exit status") != -1:
                                                                                                                trouble_lines[linenumber] = "indigestible"

                                                                                except Exception as e:
                                                                                        trouble_lines[linenumber] = "indigestible"

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

        ##########################
        # Make a bad-words list: #
        ##########################

        global bad_word_array

        bad_word_array = [
                {'ldapsearch':		[ '-w $password' ] },
                {'curl':		[ '--user $username:$password', '-u $username:$password' ] },
                {'wget':		[ '--password', '--http-password', '--ftp-password', '--proxy-password' ] },
                {'HTTPBasicAuth':	[ '(($username)\s*,\s*($password))' ] }
        ]


        (bad_keywords, bad_word_regexes) = crescentwrench(bad_word_array)


        for master_hash in requests.get(url, auth=plain_user, verify=False).json():
                if master_hash['sha'] not in hashes:

                        mailbody = ""

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


                        clean_data, clear_data = gitcat(content_url, plain_user)


                        password_problems = bowlder(clear_data, bad_keywords, bad_word_regexes)


                        for erroring_line in password_problems:
                                nag_url = data['repository']['html_url'] + '/blob/master/' + master_hash['path'] + '#L' + str(erroring_line)

                                if password_problems[erroring_line] == 'indigestible':
                                        mailbody = mailbody + "Your edit of " + changed_file + " mentions a password-like string at line " + str(erroring_line) + " that I can't parse.  " + nag_url + "\n\n"
                                else:
                                        mailbody = mailbody + "Your edit of " + changed_file + " mentions a password-like string at line " + str(erroring_line) + " " + nag_url + ". ISSUE: " + password_problems[erroring_line] + " \n\n"


                        uniq_words = {}

                        for word in clean_data:
                                uniq_words[word] = word


                        for word in uniq_words:
                                # Auth-token hunt:
                                #
                                
                                clean_word = word.translate(None, string.punctuation)   # Ugly edge case. Please rethink how this is handled in a larger-sense.

                                if len(clean_word) == 40:
                                        if token(clean_word):
                                                nag(data['pusher']['email'], "Your edit of " + changed_file + " mentioned an active application token and has been automatically rebased back to the previous version.")
                                                rebase(rewind_to, data['repository']['full_name'])


                                # Internal-hostname hunt
                                #

                                if len(word) > 3:
                                        if resolve(word):
                                                mailbody = mailbody + "Your edit of " + changed_file + " mentions internal hostname \"" + word + "\"\n"


                                # Named-user hunt
                                #

                                if finger(word):
                                        mailbody = mailbody + "Your edit of " + changed_file + " mentions username \"" + word + "\"\n"

                        print "\n\n"
                        print mailbody

                        if (len(mailbody) > 1):
                                nag(data['pusher']['email'], mailbody)

        return("")

if __name__ == "__main__":
        app.run(host='0.0.0.0', port=8008)
