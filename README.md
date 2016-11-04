# Leafer's Gold Stars

Leafer's Gold Stars is equal parts motivational and competitive scoreboard between friends to award and earn stars. Users are able to store a list of event items within a variety of categories to keep track of stars earned. It provides a user registration and authentication system with defense against cross-site request forgery. Registered users (anyone with a Facebook or Google account) have the ability to post, edit and delete their own items. Created by [Marie Leaf](https://twitter.com/mariesleaf). It uses SeaSurf Flask extension to prevent cross-site request forgery.

Developed CMS using the Flask framework in Python. Authentication is provided via OAuth and a PostgreSQL database is used. Deployed on Google App Engine. Google App Engine Endpoints API used to build Python backend to support web and Android-based app. iOS in development.


### Table of contents

* [Quick Start](#quick-start)
* [Creator](#creator)
* [Concepts](#concepts)
* [API Endpoints](#API Endpoints)

### Quick start

* [Download the latest release](https://github.com/mleafer/fullstacknanodegree/archive/master.zip).
* Ensure you have [Vagrant Machine](https://www.vagrantup.com/), and [Virtual Box](https://www.virtualbox.org/) installed.
* Initialize the VM via `vagrant up`
* Connect to the VM via `vagrant ssh`
* (Optional) Obtain your own [Google](https://console.developers.google.com)/[Facebook](https://developers.facebook.com/) oAuth API keys.
* (Optional) Inside the VM, export your own API keys to files: 'client_secrets.json' and 'fb_client_secrets.json'.
* Navigate to catalog directory `cd /vagrant/P3_goldstars`
* Run `python goldstars.py` to launch the server
* Go to [localhost:5000](http://localhost:5000/domains/) to use the app locally! 


### Creator

**Marie Leaf**

* <https://twitter.com/mariesleaf>
* <https://github.com/mleafer>

### Concepts 
* Iterative Development
* Mock-ups
* Frameworks + Databases
* Routing + url_for
* Templates + Forms
* CRUD Functionality
* API Endpoints + JSON Messages
* Styling with CSS + * Message Flashing
* Local Permission Systems

### API Endpoints
To access JSON endpoints use the routes below.

**Route to '/domains.json'**

`def domainsJSON()`

Returns a list of all domain names and their ID numbers.

Arguments:
- None taken

**Route to '/domains/<int:domID>/events.json'**

`def domeventsJSON(domID)`
Within specified domain, returns a list of all event names and their description, ID number, number of stars, and category.

Arguments:
- domID : ID number of domain

**Route to '/domains/<int:domID>/events/<int:eventsID>.json'**

`def eventJSON(domID, eventID)`

Returns the name, description, ID number, number of stars, and category of a specific event.

Arguments:
- domID : ID number of domain
- eventID : ID number of event