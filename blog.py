import os
import re
# import random
# import hashlib
import hmac
# import logging
# import time
# from string import letters

import webapp2
import jinja2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

# Define constants
SECRET = 'ninja_skills'
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASS_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')


# #### Define global functions
def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)


def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)


# #### user functions
def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val


def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)


def make_salt(length=5):
    return ''.join(random.choice(letters) for x in xrange(length))


def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(SECRET, val).hexdigest())


def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)


# #### Blog db functions
def blog_key(name='default'):
    return db.Key.from_path('blogs', name)


def users_key(group='default'):
    return db.Key.from_path('users', group)


# #### validaton functions
def valid_password(password):
    return password and PASS_RE.match(password)


def valid_email(email):
    return not email or EMAIL_RE.match(email)


def valid_username(username):
    return username and USER_RE.match(username)


# #### Define database classes
class Comments(db.Model):
    post_id = db.IntegerProperty(required=True)
    comment = db.TextProperty(required=True)
    author = db.StringProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)

    @classmethod
    def comments_post_id_author(cls, post_id, author):
        u = Comments.all().filter('post_id =', post_id).filter('author =',
                                                               author).get()
        return u

    @classmethod
    def comments_by_post(cls, post_id):
        u = Comments.all().filter('post_id =', post_id)
        return u


class Likes(db.Model):
    post_id = db.IntegerProperty(required=True)
    like_type = db.StringProperty(required=True)
    author = db.StringProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)

    @classmethod
    def by_post_id(cls, post_id, author):
        u = Likes.all().filter('post_id =', post_id).filter('author =',
                                                            author).get()
        return u

    @classmethod
    def likes_by_post(cls, post_id, like_type):
        u = Likes.all().filter('post_id =', post_id).filter('like_type =',
                                                            like_type).count()
        return u


class Post(db.Model):
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    author = db.StringProperty(required=True)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p=self)


class User(db.Model):
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    @classmethod
    def get_all_users(cls):
        u = db.GqlQuery("SELECT * FROM User ")
        usr_list = u.fetch(100)
        return 'ok'

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent=users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email=None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent=users_key(),
                    name=name,
                    pw_hash=pw_hash,
                    email=email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


# #### Define main page handler
class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))


# #### Define sub page handlers
class BlogByAuthor(BlogHandler):
    def get(self, author):
        posts = Post.all().filter('author =', author).order('-created')
        likes = Likes
        comments = Comments
        self.render('front.html', posts=posts, likes=likes,
                    comments=comments)


class BlogFront(BlogHandler):
    def get(self):
        posts = Post.all().order('-created')
        likes = Likes
        comments = Comments
        self.render('front.html', posts=posts, likes=likes,
                    comments=comments)


class DeleteComment(BlogHandler):
    def get(self, comment_id):
        ckey = db.Key.from_path('Comments', int(comment_id))
        c = db.get(ckey)
        key = db.Key.from_path('Post', int(c.post_id), parent=blog_key())
        post = db.get(key)
        if not self.user:
            self.redirect("/login")
        if not c:
            message = "This comment does not exist."
            self.render("error.html", message=message, user=self.user)
        if not post:
            message = "Could not find post associated with this comment."
            self.render("error.html", message=message, user=self.user)
        if self.user.name == post.author:
            message = "You can not delete comments on posts you created."
            self.render("error.html", message=message, user=self.user)
        if self.user.name != c.author:
            message = "You can not delete comments you did not created."
            self.render("error.html", message=message, user=self.user)
        self.render("comment.html", post=post, user=self.user,
                    comment=c.comment, action='Delete')

    def post(self, comment_id):
        ckey = db.Key.from_path('Comments', int(comment_id))
        c = db.get(ckey)
        key = db.Key.from_path('Post', int(c.post_id), parent=blog_key())
        post = db.get(key)
        if not self.user:
            self.redirect("/login")
        if not c:
            message = "This comment does not exist."
            self.render("error.html", message=message, user=self.user)
        if not post:
            message = "Could not find post associated with this comment."
            self.render("error.html", message=message, user=self.user)
        if self.user.name == post.author:
            message = "You can not delete comments on posts you created."
            self.render("error.html", message=message, user=self.user)
        if self.user.name != c.author:
            message = "You can not delete comments you did not created."
            self.render("error.html", message=message, user=self.user)
        else:
            c.delete()
            time.sleep(0.5)
            self.redirect('/blog')


class DeletePost(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        if post and self.user:
            if self.user.name == post.author or self.user.name == 'admin':
                self.render("delete.html", post=post, user=self.user)
            else:
                message = "You can not delete posts you did not create."
                self.render("error.html", message=message, user=self.user)
        elif not self.user:
            self.redirect("/login")
        else:
            message = "This post does not exist."
            self.render("error.html", message=message, user=self.user)

    def post(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        if post and self.user:
            if self.user.name == post.author or self.user.name == 'admin':
                post.delete()
                time.sleep(0.5)
                self.redirect('/blog')
            else:
                message = "You can not edit posts you did not create."
                self.render("error.html", message=message, user=self.user)
        elif not self.user:
            self.redirect("/login")
        else:
            message = "This post does not exist."
            self.render("error.html", message=message, user=self.user)


class EditComment(BlogHandler):
    def get(self, comment_id):
        ckey = db.Key.from_path('Comments', int(comment_id))
        c = db.get(ckey)
        key = db.Key.from_path('Post', int(c.post_id), parent=blog_key())
        post = db.get(key)
        if not self.user:
            self.redirect("/login")
        if not c:
            message = "This comment does not exist."
            self.render("error.html", message=message, user=self.user)
        if not post:
            message = "Could not find post associated with this comment."
            self.render("error.html", message=message, user=self.user)
        if self.user.name == post.author:
            message = "You can not comment on posts you created."
            self.render("error.html", message=message, user=self.user)
        self.render("comment.html", post=post, user=self.user,
                    comment=c.comment, action='Edit')

    def post(self, comment_id):
        ckey = db.Key.from_path('Comments', int(comment_id))
        c = db.get(ckey)
        key = db.Key.from_path('Post', int(c.post_id), parent=blog_key())
        post = db.get(key)
        comment = self.request.get('comment')
        if not self.user:
            self.redirect("/login")
        if not c:
            message = "This comment does not exist."
            self.render("error.html", message=message, user=self.user)
        if not post:
            message = "Could not find post associated with this comment."
            self.render("error.html", message=message, user=self.user)
        if self.user.name == post.author:
            message = "You can not comment on posts you created."
            self.render("error.html", message=message, user=self.user)
        if comment:
            c.comment = comment
            c.put()
            time.sleep(0.5)
            self.redirect('/blog/%s' % str(post.key().id()))
        else:
            error = "Enter a comment, please!"
            self.render("comment.html", post=post, user=self.user,
                        comment=comment, error=error, action='Edit')


class EditPost(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        if post and self.user:
            if self.user.name == post.author or self.user.name == 'admin':
                self.render("editpost.html", post=post, user=self.user)
            else:
                message = "You can not edit posts you did not create."
                self.render("error.html", message=message, user=self.user)
        elif not self.user:
            self.redirect("/login")
        else:
            message = "This post does not exist."
            self.render("error.html", message=message, user=self.user)

    def post(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        if post and self.user:
            if self.user.name == post.author or self.user.name == 'admin':
                post.subject = self.request.get('subject')
                post.content = self.request.get('content')
                if post.subject and post.content:
                    post.put()
                    time.sleep(0.5)
                    self.redirect('/blog/%s' % post_id)
                else:
                    error = "Enter a title and content, please!"
                    self.render("editpost.html", post=post, user=self.user,
                                error=error)
            else:
                message = "You can not edit posts you did not create."
                self.render("error.html", message=message, user=self.user)
        elif not self.user:
            self.redirect("/login")
        else:
            message = "This post does not exist."
            self.render("error.html", message=message, user=self.user)


class LikePost(BlogHandler):
    # get should never be used unless user forces it. redirect if that happens
    def get(self, route_id):
        if self.user:
            self.redirect("/blog")
        else:
            self.redirect("/login")

    def post(self, route_id):
        post_id = route_id.split("/")[1]
        like_type = route_id.split("/")[0]
        if not self.user:
            self.redirect("/login")
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        hasLiked = Likes.by_post_id(post.key().id(), self.user.name)
        if not post:
            message = "This post does not exist."
            self.render("error.html", message=message, user=self.user)
        if self.user.name == post.author:
            message = "You can not '"+like_type+"' posts you created."
            self.render("error.html", message=message, user=self.user)
        if not hasLiked:
            like = Likes(post_id=post.key().id(), author=self.user.name,
                         like_type=like_type)
            like.put()
            time.sleep(0.5)
            message = ("You have just '" + like_type + "' the post titled: " +
                       post.subject + ".")
            self.render("message.html", message=message, user=self.user)
        else:
            message = "You have already 'Liked/Disliked' this post."
            self.render("error.html", message=message, user=self.user)


class Login(BlogHandler):
    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/welcome')
        else:
            message = 'Invalid login'
            self.render('login-form.html', message=message)


class Logout(BlogHandler):
    def get(self):
        if self.user:
            prev_user = self.user.name
            self.logout()
            self.user = ''
            self.render('goodbye.html', username=prev_user)
        else:
            self.redirect('/signup')


class MainPage(BlogHandler):

    def get(self):
        self.write('Hello, Udacity!')


class NewComment(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        if not self.user:
            self.redirect("/login")
        if post:
            self.render("comment.html", post=post, user=self.user,
                        action='Add')
        else:
            message = "This post does not exist."
            self.render("error.html", message=message, user=self.user)

    def post(self, post_id):
        if not self.user:
            self.redirect('/login')
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        comment = self.request.get('comment')
        if post:
            if comment:
                c = Comments(post_id=post.key().id(), comment=comment,
                             author=self.user.name)
                c.put()
                time.sleep(0.5)
                self.redirect('/blog/%s' % str(post.key().id()))
            else:
                error = "Enter a comment, please!"
                self.render("newcomment.html", post=post, user=self.user,
                            comment=comment, error=error)
        else:
            message = "This post does not exist."
            self.render("error.html", message=message, user=self.user)


class NewPost(BlogHandler):
    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect("/login")

    def post(self):
        if not self.user:
            self.redirect('/blog')

        subject = self.request.get('subject')
        content = self.request.get('content')
        author = self.user.name

        if subject and content:
            p = Post(parent=blog_key(), subject=subject, content=content,
                     author=author)
            p.put()
            time.sleep(0.5)
            self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = "Enter a title and content, please!"
            self.renderkey()("newpost.html", subject=subject, content=content,
                             error=error)


class PostPage(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        likes = Likes
        comments = Comments
        if not post:
            self.error(404)
            return

        self.render("permalink.html", post=post, user=self.user, likes=likes,
                    comments=comments)


class Signup(BlogHandler):
    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username=self.username,
                      email=self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError


class Welcome(BlogHandler):
    def get(self):
        if self.user:
            self.render('welcome.html', username=self.user.name)
        else:
            self.redirect('/signup')


# #### Define helper classes
class Register(Signup):
    def done(self):
        # make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username=msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/welcome')


app = webapp2.WSGIApplication([('/', BlogFront),
                               ('/blog/?', BlogFront),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/author/([a-zA-Z0-9]+)', BlogByAuthor),
                               ('/blog/comment/add/([a-zA-Z0-9]+)',
                                NewComment),
                               ('/blog/comment/delete/([a-zA-Z0-9]+)',
                                DeleteComment),
                               ('/blog/comment/edit/([a-zA-Z0-9]+)',
                                EditComment),
                               ('/blog/delete/([a-zA-Z0-9]+)', DeletePost),
                               ('/blog/(dislike/[a-zA-Z0-9]+)', LikePost),
                               ('/blog/edit/([a-zA-Z0-9]+)', EditPost),
                               ('/blog/(like/[a-zA-Z0-9]+)', LikePost),
                               ('/blog/new', NewPost),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/signup', Register),
                               ('/welcome', Welcome),
                               ],
                              debug=True)
