# silicone-tape

> *Nothing like making a total dickhead out of yourself. Nothing in the world like it, nosireebob.*  
> -- Hiro Protaganist, in Neal Stephenson's *Snowcrash*


## Whats this?

silicone-tape is a simple flask app for preventing embarassing "leaks" in pushes to GitHub Enterprise, with an eye towards 
preventing the author from looking silly. The author takes notes on and makes frequent pushes-to a GHE instance at work, and is resistant to requiring pull requests for diary repos and note files. This is *absolutely not* a static analyzer or a security tool, its meant to prevent the person pushing to GHE from looking like a jerk.


## What "leaks" get checked?

silicone-tape currently checks pushed data for the following conditions:

| Problem        | Action           | Likely More-Useful On  |
| ------------- |:-------------:| -----:|
| GitHub/GHE auth token raw in push | ***Recursively-rebase entire repo until no active tokens are found*** and then send user who pushed a chiding email | GitHub.com and GHE |
| Suspected plaintext password | Mail user who pushed to look and have a good think about this content. | GitHub.com and GHE |
| Explicit username reference | Send user who pushed a chiding email | GitHub.com |
| Explicit internal hostname reference| Send user who pushed a chiding email | GitHub.com |

##### Additional conditions may be added depending on awkward talks with the security team or further razzing from co-workers.


## How would I run this?

If you're using GitHub Enterprise, pop this up on any internal host that can be reached by a GHE webhook and can send email. This should work-out okay for GitHub.com too, but explicit usernames and located through system lookups and hostsnames are identified by DNS queries, so mileage is limited.
