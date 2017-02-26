# Multi-user Blog

This is a multi-user basic blog. Users can request an account and need to login
to use any more than read-only on the blog. Once logged in, a user can add, edit
and comment on their posts.

## Products
- [App Engine][1]

## Language
- [Python][2]

## APIs
- [NDB Datastore API][3]
- [Users API][4]

## Dependencies
- [webapp2][5]
- [jinja2][6]
- [Twitter Bootstrap][7]

[1]: https://developers.google.com/appengine
[2]: https://python.org
[3]: https://developers.google.com/appengine/docs/python/ndb/
[4]: https://developers.google.com/appengine/docs/python/users/
[5]: http://webapp-improved.appspot.com/
[6]: http://jinja.pocoo.org/docs/
[7]: http://twitter.github.com/bootstrap/


## To run this using google app engine.

### Create and install google app engine.
### Once you have an account, fork to 'https://github.com/lowjack98/multi-user-blog.git'
### from that directory, you can intall it locally and test it using google app engine.
 execute the command '''dev_appserver.py .'''

### to load the blog in your public google app engine execute the command '''gcloud app deploy --project=<the name of your app>'''
