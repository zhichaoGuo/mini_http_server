import os
import logging
import secrets
import shutil
import tarfile
import zipfile
import datetime
import mimetypes
from logging.handlers import TimedRotatingFileHandler

import humanize
from flask import render_template, abort, request, session, send_file, redirect, url_for, jsonify, Flask
from flask_login import login_required, logout_user, login_user, LoginManager
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from wtforms import StringField, PasswordField, validators, Form

from config import Config

app = Flask(__name__)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Strict',
)
conf = Config()
# -------------  setting logger   -----------------
logger = logging.getLogger("http.server")
logger.setLevel(logging.WARNING)
formatter = logging.Formatter(conf.log_format)
handler = TimedRotatingFileHandler(conf.log_path, when="D", interval=1, backupCount=15, encoding="UTF-8",
                                   delay=False, utc=True)
handler.setFormatter(formatter)
logger.addHandler(handler)
app.secret_key = conf.secret_key

# -------------  setting database  -----------------
app.config['SQLALCHEMY_DATABASE_URI'] = conf.sql_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
db = SQLAlchemy(app)
ctx = app.app_context()
ctx.push()
db.create_all()

# -------------  setting login   -----------------
loginManager = LoginManager(app)
loginManager.session_protection = "strong"
loginManager.login_view = 'login'


@loginManager.user_loader
def load_user(user_id):
    db.create_all()
    new = datetime.datetime.now()
    username = str(User.query.get(int(user_id)))
    user = User.query.filter_by(username=username).first()
    if user:
        old = user.last_login_time
        # 登录超时 3600s -> 1h
        if (new - old).seconds > 3600:
            user.is_login = False
            db.session.add(user)
            db.session.commit()
            session.clear()
            logout_user()
            app.logger.info('%s online time out, auto logout,last login time is:%s' % (username, old))
            return None
        return User.query.get(int(user_id))
    return User.query.get(int(user_id))


# Routing

@app.route('/', endpoint='root')
@login_required
@app.route('/<path:element>')
@login_required
def view(element=""):
    path = os.path.realpath(os.path.join(app.config["FOLDER"], element))
    if (os.path.join(os.path.commonprefix((path, app.config["FOLDER"])), "") != app.config["FOLDER"]) \
            or not os.path.exists(path):
        return abort(404)

    session["CSRF-TOKEN"] = secrets.token_hex()
    if request.args.get("delete"):
        location = request.args.get("location")
        path = os.path.join(path, location)
        logger.info('%s %s %s %s %s', session.get('username'), request.remote_addr, 'DELETE', path, 'OK')
        if os.path.isdir(path):
            shutil.rmtree(path)
        else:
            os.remove(path)
        return redirect(request.url.split('?')[0])
    if os.path.isdir(path):
        return render_template("listing.template", element=get_element(path, not len(element)))

    elif request.args.get("download"):
        return send_file(path, as_attachment=True)

    elif request.args.get("embed"):
        return send_file(path, as_attachment=False)

    return render_template("file.template", element=get_element(path))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        if session.get('username') is not None:
            logger.info('%s %s %s', session.get('username'), request.remote_addr, 'Login!')
            return redirect(url_for('root'))
        login_form = LoginFrom()
        return render_template("login.template", form=login_form)
    elif request.method == 'POST':
        data = request.get_json()
        username = data['username']
        password = data['password']
        app.logger.debug('user:%s try to login!' % username)
        # 前端已加防范，后端再防一手
        if username is None:
            logger.warning('%s %s %s', request.remote_addr, 'Login', 'login with out username!')
            return jsonify({
                'code': 1,
                'message': '请输入用户名',
                'data': '', })
        if password is None:
            logger.warning('%s %s %s', request.remote_addr, 'Login', 'login with out password!')
            return jsonify({
                'code': 1,
                'message': '请输入密码',
                'data': '', })
        user = User.query.filter_by(username=username).first()
        if user:
            if user.check_password(password):
                user.is_login = True
                user.last_login_ip = request.remote_addr
                user.last_login_time = datetime.datetime.now()
                db.session.add_all([user])
                db.session.commit()
                login_user(user)
                session['username'] = username
                logger.info('%s %s %s', session.get('username'), request.remote_addr, 'Login!')
                return jsonify({
                    'code': 0,
                    'message': '登录成功！',
                    'data': '',
                })
            else:
                logger.warning('%s %s %s', request.remote_addr, 'Login', 'login with wrong password!')
                return jsonify({
                    'code': 1,
                    'message': '用户名或密码错误！',
                    'data': '',
                })
        else:
            logger.warning('%s %s %s', request.remote_addr, 'Login', 'login with wrong username:%s!' % username)
            return jsonify({
                'code': 1,
                'message': '用户名或密码错误！',
                'data': '',
            })
    else:
        return abort(405)


@app.route('/logout', methods=['GET'])
@login_required
def logout():
    username = session.get("username")
    session.clear()
    logout_user()
    user = User.query.filter_by(username=username).first()
    user.is_login = False
    db.session.add(user)
    db.session.commit()
    logger.info('%s %s %s', request.remote_addr, 'Logout', 'logout with username:%s!' % username)
    return redirect(url_for('login', next=request.url))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        if session.get('username') is not None:
            return redirect(url_for('root'))
        form = RegFrom()
        return render_template('register.template', form=form)
    elif request.method == 'POST':
        data = request.get_json()
        username = data['username']
        password = data['password']
        se_password = data['se_password']
        key = data['key']
        logger.info('%s %s %s', request.remote_addr, 'Register', 'Try to register with username:%s!' % username)
        if username is None:
            return jsonify({'code': 1, 'message': '用户名不能为空！', 'data': '', })
        if password is None:
            return jsonify({'code': 1, 'message': '密码不能为空！', 'data': '', })
        if password != se_password:
            return jsonify({'code': 1, 'message': '两次密码不相同！', 'data': '', })
        if key != conf.register_key:
            return jsonify({'code': 1, 'message': '邀请码不正确！', 'data': '', })
        user = User.query.filter_by(username=username).first()
        if user:
            return jsonify({'code': 1, 'message': '用户名已存在！', 'data': '', })
        new_user = User(username=username)
        new_user.set_password(password)
        new_user.last_login_ip = request.remote_addr
        db.session.add(new_user)
        db.session.commit()
        logger.info('%s %s %s', request.remote_addr, 'Register', 'Register success with username:%s!' % username)
        return jsonify({'code': 0, 'message': '注册成功！', 'data': '', })
    else:
        return abort(405)


@app.route('/upload', methods=['POST'])
@login_required
def upload():
    if "CSRF-TOKEN" not in session:
        return {"status": False, "error": "Missing CSRF Token!"}

    file = request.files.get('file')
    path = os.path.realpath(request.form.get('path'))

    if not file or not path:
        return {"status": False, "error": "Missing parameters!"}

    if os.path.join(os.path.commonprefix((path, app.config["FOLDER"])), "") != app.config["FOLDER"]:
        return {"status": False, "error": "Invalid path!"}

    try:
        os.makedirs(path, exist_ok=True)
    except OSError as err:
        return {"status": False, "error": str(err)}

    filename = secure_filename(file.filename)
    file.save(os.path.join(path, filename))
    logger.info('%s %s %s %s', session.get('username'),request.remote_addr, 'Upload', os.path.join(path, filename))
    return {"status": True}


@app.route('/zip', methods=['GET', 'POST'])
@login_required
def zip_utility():
    if "CSRF-TOKEN" not in session:
        return {"status": False, "error": "Missing CSRF Token!"}

    if request.method == "GET":
        path = os.path.realpath(request.args.get('path'))
        download_entry = request.args.get('entry')

    else:
        path = os.path.realpath(request.form.get('path'))
        download_entry = request.form.get('entry')

    if not path:
        return {"status": False, "error": "Missing parameter!"}

    if (os.path.join(os.path.commonprefix((path, app.config["FOLDER"])), "") != app.config["FOLDER"]) \
            or not os.path.exists(path) or not os.path.isfile(path):
        return {"status": False, "error": "Invalid path/file!"}

    zip_type = mimetypes.guess_type(path)
    try:
        if any(zip_type) and zip_type[0].endswith("tar") or zip_type[1] in ["gzip", "bzip2", "xz"]:
            tar_file = tarfile.open(path)

            if not download_entry:
                return {"status": True, "structure": parse_archive_infolist(tar_file.getmembers(), tar=True)}

            return send_file(tar_file.extractfile(tar_file.getmember(download_entry)),
                             download_name=download_entry, as_attachment=False)

        zip_file = zipfile.ZipFile(path)
        if not download_entry:
            return {"status": True, "structure": parse_archive_infolist(zip_file.infolist())}

        return send_file(zip_file.open(download_entry), download_name=download_entry, as_attachment=False)

    except (zipfile.BadZipFile, ValueError, OSError, Exception) as e:
        return {"status": False, "error": str(e)}


# Jinja Template Filters

@app.template_filter()
def datetime_format(value):
    dt = datetime.datetime.fromtimestamp(value)
    return dt.strftime('%d-%m-%Y %H:%M:%S')


@app.template_filter()
def datetime_humanize(value):
    dt = datetime.datetime.fromtimestamp(value)
    return humanize.naturaltime(dt)


# Functions

def get_element(path: str, is_root_directory=False):
    stat_result = os.stat(path)
    element = dict(name=os.path.basename(path), basedir=path, path=path, isroot=is_root_directory,
                   size=stat_result.st_size, mtime=stat_result.st_mtime,
                   ctime=stat_result.st_birthtime if hasattr(stat_result, "st_birthtime") else stat_result.st_ctime)

    if os.path.isdir(path):
        # Directory
        element.update(dict(children=[], isdir=True))
        children = []

        try:
            dir_list = os.listdir(path)
        except OSError:
            pass  # Ignore errors
        else:
            for child_name in dir_list:
                child_path = os.path.join(path, child_name)
                child_stat_result = os.stat(child_path)
                children.append(dict(name=child_name, path=child_path, isdir=os.path.isdir(child_path),
                                     size=child_stat_result.st_size, mtime=child_stat_result.st_mtime,
                                     ctime=child_stat_result.st_birthtime
                                     if hasattr(child_stat_result, "st_birthtime")
                                     else child_stat_result.st_ctime,
                                     mime=mimetypes.guess_type(child_name)[0]))

        element["children"] = sorted(children, key=lambda y: y["ctime"], reverse=True)

    else:
        # File
        mime = mimetypes.guess_type(path)
        element.update(dict(isdir=False, basedir=os.path.dirname(path), mime=mime[0] if mime[0] else mime[1]))

    return element


def parse_archive_infolist(infolist, tar=False):
    structure = dict()

    for file_info in infolist:
        current_structure = structure
        filename = file_info.filename if not tar else file_info.name
        for element in filename.split("/"):
            if element:
                if element not in current_structure:
                    current_structure[element] = {"_size": 0, "_path": ".", "_isdir": True}

                current_structure = current_structure[element]

        current_structure.update({
            "_size": humanize.naturalsize(file_info.file_size if not tar else file_info.size),
            "_path": filename,
            "_isdir": file_info.is_dir() if not tar else file_info.isdir(),
        })

    return structure


# Output
def after_request(response):
    timestamp = datetime.datetime.now().strftime('[%d-%m-%Y %H:%M:%S]')
    logger.info('%s %s %s %s', request.remote_addr, request.method, request.full_path, response.status)
    return response


# Form
class LoginFrom(FlaskForm):
    username = StringField(u'用户名',
                           [validators.Length(min=4, max=16, message=u'用户名长度在4-16位'), validators.DataRequired()],
                           render_kw={'placeholder': u'请输入用户名'})
    password = PasswordField(u'密码', [validators.length(min=8, max=16, message=u'密码长度8-16位'), validators.DataRequired()],
                             render_kw={'placeholder': u'请输入密码'})


class RegFrom(Form):
    username = StringField(u'注册用户名(请使用公司常用英文名)', [validators.Length(min=3, max=16, message=u'用户名长度在3-16位'),
                                                  validators.DataRequired(message=u'请输入用户名')],
                           render_kw={'placeholder': u'请输入用户名'})
    password = PasswordField(u'注册密码', [validators.length(min=5, max=16, message=u'密码长度5-16位'),
                                       validators.DataRequired(message=u'请输入密码')], render_kw={'placeholder': u'请输入密码'})
    se_password = PasswordField(u'再次输入密码', [validators.length(min=5, max=16, message=u'密码长度5-16位'),
                                            validators.DataRequired(message=u'请输入确认密码')],
                                render_kw={'placeholder': u'请输入密码'})
    key = StringField(u'输入邀请码', validators=[validators.DataRequired(message=u'请输入邀请码')],
                      render_kw={'placeholder': u'输入邀请码'})


# database

class User(db.Model):  # 用户表
    __tablename__ = 'users'
    id = db.Column(db.Integer(), primary_key=True, autoincrement=True)
    username = db.Column(db.String(63), unique=True)
    password = db.Column(db.String(252))
    last_login_ip = db.Column(db.String(15))
    last_login_time = db.Column(db.DateTime(), default=datetime.datetime.now())
    is_login = db.Column(db.Boolean(), default=False)

    def __repr__(self):
        return self.username

    def set_password(self, password):
        # self.password = generate_password_hash(password)
        self.password = password

    def check_password(self, password):
        # return True
        return self.password == password
        # return check_password_hash(self.password, password)

    def is_authenticated(self):
        return True

    def is_active(self):
        return True

    def is_anonymous(self):
        return False

    def get_id(self):
        return self.id


# Main

def main():
    import argparse
    import waitress

    parser = argparse.ArgumentParser()
    parser.add_argument('--bind', default='127.0.0.1', help='Specify bind address [default: 127.0.0.1]')
    parser.add_argument('--port', default=8000, help='Specify server port [default: 8000]')
    parser.add_argument('--folder', default=os.getcwd(), help='Specify which directory to serve '
                                                              '[default: current working directory]')
    mode_args = parser.add_mutually_exclusive_group()
    mode_args.add_argument('--debug', default=False, action="store_true",
                           help='Use "flask.run" in Debug mode instead of "waitress" WSGI server')
    mode_args.add_argument('--no-output', default=False, action="store_true",
                           help='Disable server output (set logging.level >= WARNING)')

    args = parser.parse_args()

    app.secret_key = str(secrets.token_hex())
    app.config["FOLDER"] = os.path.join(os.path.realpath(os.path.expanduser(args.folder)), "")

    if not os.path.exists(app.config["FOLDER"]):
        return parser.error("folder does not exists")

    if args.debug:
        app.run(host=args.bind, port=args.port, debug=True)
        return

    elif not args.no_output:
        waitress_logger = logging.getLogger('waitress')
        waitress_logger.setLevel(logging.DEBUG)
        logger.setLevel(logging.DEBUG)
        app.after_request(after_request)

    waitress.serve(app, host=args.bind, port=args.port, ident="http.server")


if __name__ == "__main__":
    main()
