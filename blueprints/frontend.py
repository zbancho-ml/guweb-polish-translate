# -*- coding: utf-8 -*-

__all__ = ()

import bcrypt
import hashlib
import os
import time

from cmyui.logging import Ansi
from cmyui.logging import log
from cmyui.osu import Mods
from functools import wraps
from PIL import Image
from pathlib import Path
from quart import Blueprint
from quart import redirect
from quart import render_template
from quart import request
from quart import session
from quart import send_file

from constants import regexes
from objects import glob
from objects import utils
from objects.privileges import Privileges
from objects.utils import flash
from objects.utils import flash_with_customizations

VALID_MODES = frozenset({'std', 'taiko', 'catch', 'mania'})
VALID_MODS = frozenset({'vn', 'rx', 'ap'})

frontend = Blueprint('frontend', __name__)

def login_required(func):
    @wraps(func)
    async def wrapper(*args, **kwargs):
        if not session:
            return await flash('error', 'You must be logged in to access that page.', 'login')
        return await func(*args, **kwargs)
    return wrapper

@frontend.route('/home')
@frontend.route('/')
async def home():
    record = {}
    record['std-vn'] = await glob.db.fetch("SELECT scores_vn.id, scores_vn.pp, scores_vn.userid, "
                                           "maps.set_id, users.name FROM scores_vn LEFT JOIN users ON "
                                           "scores_vn.userid = users.id LEFT JOIN maps ON scores_vn.map_md5 "
                                           "= maps.md5 WHERE scores_vn.mode = 0 && maps.status=2 "
                                           "&& users.priv & 1 ORDER BY pp DESC LIMIT 1;")

    record['std-rx'] = await glob.db.fetch("SELECT scores_rx.id, scores_rx.pp, scores_rx.userid, "
                                           "maps.set_id, users.name FROM scores_rx LEFT JOIN users ON "
                                           "scores_rx.userid = users.id LEFT JOIN maps ON scores_rx.map_md5 "
                                           "= maps.md5 WHERE scores_rx.mode = 0 && maps.status=2 "
                                           "&& users.priv & 1 ORDER BY pp DESC LIMIT 1;")

    record['std-ap'] = await glob.db.fetch("SELECT scores_ap.id, scores_ap.pp, scores_ap.userid, "
                                           "maps.set_id, users.name FROM scores_ap LEFT JOIN users ON "
                                           "scores_ap.userid = users.id LEFT JOIN maps ON scores_ap.map_md5 "
                                           "= maps.md5 WHERE scores_ap.mode = 0 && maps.status=2 "
                                           "&& users.priv & 1 ORDER BY pp DESC LIMIT 1;")

    record['taiko-vn'] = await glob.db.fetch("SELECT scores_vn.id, scores_vn.pp, scores_vn.userid, "
                                           "maps.set_id, users.name FROM scores_vn LEFT JOIN users ON "
                                           "scores_vn.userid = users.id LEFT JOIN maps ON scores_vn.map_md5 "
                                           "= maps.md5 WHERE scores_vn.mode = 1 && maps.status=2 "
                                           "&& users.priv & 1 ORDER BY pp DESC LIMIT 1;")

    record['taiko-rx'] = await glob.db.fetch("SELECT scores_rx.id, scores_rx.pp, scores_rx.userid, "
                                           "maps.set_id, users.name FROM scores_rx LEFT JOIN users ON "
                                           "scores_rx.userid = users.id LEFT JOIN maps ON scores_rx.map_md5 "
                                           "= maps.md5 WHERE scores_rx.mode = 1 && maps.status=2 "
                                           "&& users.priv & 1 ORDER BY pp DESC LIMIT 1;")

    record['catch-vn'] = await glob.db.fetch("SELECT scores_vn.id, scores_vn.pp, scores_vn.userid, "
                                           "maps.set_id, users.name FROM scores_vn LEFT JOIN users ON "
                                           "scores_vn.userid = users.id LEFT JOIN maps ON scores_vn.map_md5 "
                                           "= maps.md5 WHERE scores_vn.mode = 2 && maps.status=2 "
                                           "&& users.priv & 1 ORDER BY pp DESC LIMIT 1;")

    record['catch-rx'] = await glob.db.fetch("SELECT scores_rx.id, scores_rx.pp, scores_rx.userid, "
                                           "maps.set_id, users.name FROM scores_rx LEFT JOIN users ON "
                                           "scores_rx.userid = users.id LEFT JOIN maps ON scores_rx.map_md5 "
                                           "= maps.md5 WHERE scores_rx.mode = 2 && maps.status=2 "
                                           "&& users.priv & 1 ORDER BY pp DESC LIMIT 1;")

    record['mania-vn'] = await glob.db.fetch("SELECT scores_vn.id, scores_vn.pp, scores_vn.userid, "
                                           "maps.set_id, users.name FROM scores_vn LEFT JOIN users ON "
                                           "scores_vn.userid = users.id LEFT JOIN maps ON scores_vn.map_md5 "
                                           "= maps.md5 WHERE scores_vn.mode = 3 && maps.status=2 "
                                           "&& users.priv & 1 ORDER BY pp DESC LIMIT 1;")

    record['std-vn']['pp'] = round(float(record['std-vn']['pp']), 2)
    record['std-rx']['pp'] = round(float(record['std-rx']['pp']), 2)
    record['std-ap']['pp'] = round(float(record['std-ap']['pp']), 2)
    record['taiko-vn']['pp'] = round(float(record['taiko-vn']['pp']), 2)
    record['taiko-rx']['pp'] = round(float(record['taiko-rx']['pp']), 2)
    record['catch-vn']['pp'] = round(float(record['catch-vn']['pp']), 2)
    record['catch-rx']['pp'] = round(float(record['catch-rx']['pp']), 2)
    record['mania-vn']['pp'] = round(float(record['mania-vn']['pp']), 2)

    return await render_template('home.html', record=record)


@frontend.route('/home/account/edit')
async def home_account_edit():
    return redirect('/settings/profile')

@frontend.route('/settings')
@frontend.route('/settings/profile')
@login_required
async def settings_profile():
    return await render_template('settings/profile.html')

@frontend.route('/settings/profile', methods=['POST'])
@login_required
async def settings_profile_post():
    form = await request.form

    new_name = form.get('username', type=str)
    new_email = form.get('email', type=str)

    if new_name is None or new_email is None:
        return await flash('error', 'Invalid parameters.', 'home')

    old_name = session['user_data']['name']
    old_email = session['user_data']['email']

    # no data has changed; deny post
    if (
        new_name == old_name and
        new_email == old_email
    ):
        return await flash('error', 'No changes have been made.', 'settings/profile')

    if new_name != old_name:
        if not session['user_data']['is_donator']:
            return await flash('error', 'Username changes are currently a supporter perk.', 'settings/profile')

        # Usernames must:
        # - be within 2-15 characters in length
        # - not contain both ' ' and '_', one is fine
        # - not be in the config's `disallowed_names` list
        # - not already be taken by another player
        if not regexes.username.match(new_name):
            return await flash('error', 'Your new username syntax is invalid.', 'settings/profile')

        if '_' in new_name and ' ' in new_name:
            return await flash('error', 'Your new username may contain "_" or " ", but not both.', 'settings/profile')

        if new_name in glob.config.disallowed_names:
            return await flash('error', "Your new username isn't allowed; pick another.", 'settings/profile')

        if await glob.db.fetch('SELECT 1 FROM users WHERE name = %s', [new_name]):
            return await flash('error', 'Your new username already taken by another user.', 'settings/profile')

        safe_name = utils.get_safe_name(new_name)

        # username change successful
        await glob.db.execute(
            'UPDATE users '
            'SET name = %s, safe_name = %s '
            'WHERE id = %s',
            [new_name, safe_name, session['user_data']['id']]
        )

    if new_email != old_email:
        # Emails must:
        # - match the regex `^[^@\s]{1,200}@[^@\s\.]{1,30}\.[^@\.\s]{1,24}$`
        # - not already be taken by another player
        if not regexes.email.match(new_email):
            return await flash('error', 'Your new email syntax is invalid.', 'settings/profile')

        if await glob.db.fetch('SELECT 1 FROM users WHERE email = %s', [new_email]):
            return await flash('error', 'Your new email already taken by another user.', 'settings/profile')

        # email change successful
        await glob.db.execute(
            'UPDATE users '
            'SET email = %s '
            'WHERE id = %s',
            [new_email, session['user_data']['id']]
        )

    # logout
    session.pop('authenticated', None)
    session.pop('user_data', None)
    return await flash('success', 'Your username/email have been changed! Please login again.', 'login')

@frontend.route('/settings/avatar')
@login_required
async def settings_avatar():
    return await render_template('settings/avatar.html')

@frontend.route('/settings/avatar', methods=['POST'])
@login_required
async def settings_avatar_post():
    # constants
    AVATARS_PATH = f'{glob.config.path_to_gulag}.data/avatars'
    ALLOWED_EXTENSIONS = ['.jpeg', '.jpg', '.png']

    avatar = (await request.files).get('avatar')

    # no file uploaded; deny post
    if avatar is None or not avatar.filename:
        return await flash('error', 'No image was selected!', 'settings/avatar')

    filename, file_extension = os.path.splitext(avatar.filename.lower())

    # bad file extension; deny post
    if not file_extension in ALLOWED_EXTENSIONS:
        return await flash('error', 'The image you select must be either a .JPG, .JPEG, or .PNG file!', 'settings/avatar')

    # remove old avatars
    for fx in ALLOWED_EXTENSIONS:
        if os.path.isfile(f'{AVATARS_PATH}/{session["user_data"]["id"]}{fx}'): # Checking file e
            os.remove(f'{AVATARS_PATH}/{session["user_data"]["id"]}{fx}')

    # avatar cropping to 1:1
    pilavatar = Image.open(avatar.stream)

    # avatar change success
    pilavatar = utils.crop_image(pilavatar)
    pilavatar.save(os.path.join(AVATARS_PATH, f'{session["user_data"]["id"]}{file_extension.lower()}'))
    return await flash('success', 'Your avatar has been successfully changed!', 'settings/avatar')

@frontend.route('/settings/custom')
@login_required
async def settings_custom():
    user = await glob.db.fetch('SELECT priv FROM users WHERE id=%s', session['user_data']['id'])
    user_priv = Privileges(int(user['priv']))
    if Privileges.Supporter in user_priv or Privileges.Mod in user_priv or Privileges.Nominator in user_priv or Privileges.Admin in user_priv or Privileges.Premium in user_priv:
        pass
    else:
        return await flash('error', 'You must be supporter or staff to change your background and banner!', 'settings/profile')

    profile_customizations = utils.has_profile_customizations(session['user_data']['id'])
    return await render_template('settings/custom.html', customizations=profile_customizations)

@frontend.route('/settings/custom', methods=['POST'])
@login_required
async def settings_custom_post():
    user = await glob.db.fetch('SELECT priv FROM users WHERE id=%s', session['user_data']['id'])
    user_priv = Privileges(int(user['priv']))
    if Privileges.Supporter in user_priv or Privileges.Mod in user_priv or Privileges.Nominator in user_priv or Privileges.Admin in user_priv or Privileges.Premium in user_priv:
        pass
    else:
        return await flash('error', 'You must be supporter or staff to change your background and banner!', 'settings/profile')
    files = await request.files
    banner = files.get('banner')
    background = files.get('background')
    ALLOWED_EXTENSIONS = ['.jpeg', '.jpg', '.png', '.gif']

    # no file uploaded; deny post
    if banner is None and background is None:
        return await flash_with_customizations('error', 'No image was selected!', 'settings/custom')

    if banner is not None and banner.filename:
        _, file_extension = os.path.splitext(banner.filename.lower())
        if not file_extension in ALLOWED_EXTENSIONS:
            return await flash_with_customizations('error', f'The banner you select must be either a .JPG, .JPEG, .PNG or .GIF file!', 'settings/custom')

        banner_file_no_ext = os.path.join(f'.data/banners', f'{session["user_data"]["id"]}')

        # remove old picture
        for ext in ALLOWED_EXTENSIONS:
            banner_file_with_ext = f'{banner_file_no_ext}{ext}'
            if os.path.isfile(banner_file_with_ext):
                os.remove(banner_file_with_ext)

        await banner.save(f'{banner_file_no_ext}{file_extension}')

    if background is not None and background.filename:
        _, file_extension = os.path.splitext(background.filename.lower())
        if not file_extension in ALLOWED_EXTENSIONS:
            return await flash_with_customizations('error', f'The background you select must be either a .JPG, .JPEG, .PNG or .GIF file!', 'settings/custom')

        background_file_no_ext = os.path.join(f'.data/backgrounds', f'{session["user_data"]["id"]}')

        # remove old picture
        for ext in ALLOWED_EXTENSIONS:
            background_file_with_ext = f'{background_file_no_ext}{ext}'
            if os.path.isfile(background_file_with_ext):
                os.remove(background_file_with_ext)

        await background.save(f'{background_file_no_ext}{file_extension}')

    return await flash_with_customizations('success', 'Your customisation has been successfully changed!', 'settings/custom')


@frontend.route('/settings/password')
@login_required
async def settings_password():
    return await render_template('settings/password.html')

@frontend.route('/settings/password', methods=["POST"])
@login_required
async def settings_password_post():
    form = await request.form
    old_password = form.get('old_password')
    new_password = form.get('new_password')
    repeat_password = form.get('repeat_password')

    # new password and repeat password don't match; deny post
    if new_password != repeat_password:
        return await flash('error', "Your new password doesn't match your repeated password!", 'settings/password')

    # new password and old password match; deny post
    if old_password == new_password:
        return await flash('error', 'Your new password cannot be the same as your old password!', 'settings/password')

    # Passwords must:
    # - be within 8-32 characters in length
    # - have more than 3 unique characters
    # - not be in the config's `disallowed_passwords` list
    if not 8 < len(new_password) <= 32:
        return await flash('error', 'Your new password must be 8-32 characters in length.', 'settings/password')

    if len(set(new_password)) <= 3:
        return await flash('error', 'Your new password must have more than 3 unique characters.', 'settings/password')

    if new_password.lower() in glob.config.disallowed_passwords:
        return await flash('error', 'Your new password was deemed too simple.', 'settings/password')

    # cache and other password related information
    bcrypt_cache = glob.cache['bcrypt']
    pw_bcrypt = (await glob.db.fetch(
        'SELECT pw_bcrypt '
        'FROM users '
        'WHERE id = %s',
        [session['user_data']['id']])
    )['pw_bcrypt'].encode()

    pw_md5 = hashlib.md5(old_password.encode()).hexdigest().encode()

    # check old password against db
    # intentionally slow, will cache to speed up
    if pw_bcrypt in bcrypt_cache:
        if pw_md5 != bcrypt_cache[pw_bcrypt]: # ~0.1ms
            if glob.config.debug:
                log(f"{session['user_data']['name']}'s change pw failed - pw incorrect.", Ansi.LYELLOW)
            return await flash('error', 'Your old password is incorrect.', 'settings/password')
    else: # ~200ms
        if not bcrypt.checkpw(pw_md5, pw_bcrypt):
            if glob.config.debug:
                log(f"{session['user_data']['name']}'s change pw failed - pw incorrect.", Ansi.LYELLOW)
            return await flash('error', 'Your old password is incorrect.', 'settings/password')

    # remove old password from cache
    if pw_bcrypt in bcrypt_cache:
        del bcrypt_cache[pw_bcrypt]

    # calculate new md5 & bcrypt pw
    pw_md5 = hashlib.md5(new_password.encode()).hexdigest().encode()
    pw_bcrypt = bcrypt.hashpw(pw_md5, bcrypt.gensalt())

    # update password in cache and db
    bcrypt_cache[pw_bcrypt] = pw_md5
    await glob.db.execute(
        'UPDATE users '
        'SET pw_bcrypt = %s '
        'WHERE safe_name = %s',
        [pw_bcrypt, utils.get_safe_name(session['user_data']['name'])]
    )

    # logout
    session.pop('authenticated', None)
    session.pop('user_data', None)
    return await flash('success', 'Your password has been changed! Please log in again.', 'login')


@frontend.route('/u/<id>')
async def profile_select(id):
    mode = request.args.get('mode', 'std', type=str) # 1. key 2. default value
    mods = request.args.get('mods', 'vn', type=str)
    user_data = await glob.db.fetch(
        'SELECT name, safe_name, id, priv, country, clan_id '
        'FROM users '
        'WHERE safe_name IN (%s) OR id IN (%s) LIMIT 1',
        [id, utils.get_safe_name(id)]
    )
    # no user
    if not user_data:
        return (await render_template('404.html'), 404)

    # make sure mode & mods are valid args
    if mode is not None and mode not in VALID_MODES:
        return (await render_template('404.html'), 404)
    
    if mods is not None and mods not in VALID_MODS:
        return (await render_template('404.html'), 404)

    is_staff = 'authenticated' in session and (Privileges.Admin in Privileges(int(session['user_data']['priv'])))
    if not user_data or not (user_data['priv'] & Privileges.Normal or is_staff):
        return (await render_template('404.html'), 404)
    #Get clan (and life)
    if int(user_data['clan_id']) != 0:
        clan = await glob.db.fetch("SELECT tag FROM clans WHERE id=%s", user_data['clan_id'])
        clan['tag'] = f"[{clan['tag']}] "
    else:
        clan = {}
        clan['tag'] = ""

    group_list = []
    user_priv = Privileges(int(user_data['priv']))
    if Privileges.Normal not in user_priv:
        group_list.append(["ban", "Restricted", "#000000"])
    else:
        if int(user_data['id']) in [3,4]:
            group_list.append(["crown" ,"Owner", "#e84118"])
        if Privileges.Dangerous in user_priv:
            group_list.append(["code" ,"Developer", "#9b59b6"])
        if Privileges.Admin in user_priv:
            group_list.append(["star", "Admin", "#f39c12"])
        if Privileges.Mod in user_priv:
            group_list.append(["shield-alt", "GMT", "#28a40c"])
        if Privileges.Nominator in user_priv:
            group_list.append(["music", "BN", "#1e90ff"])
        if Privileges.Alumni in user_priv:
            group_list.append(["wheelchair", "Alumni", "#ea8685"])
        if Privileges.Supporter in user_priv:
            if Privileges.Premium in user_priv:
                group_list.append(["gem", "Supporter+", "#f78fb3"])
            else:
                group_list.append(["heart", "Supporter", "#f78fb3"])
        elif Privileges.Premium in user_priv:
            group_list.append(["gem", "Supporter+", "#f78fb3"])
        if Privileges.Whitelisted in user_priv:
            group_list.append(["check", "Verified", "#28a40c"])
    
    user_data['customisation'] = utils.has_profile_customizations(user_data['id'])
    return await render_template('profile.html', user=user_data, mode=mode, mods=mods, group_list=group_list, clan=clan)


@frontend.route('/leaderboard')
@frontend.route('/lb')
@frontend.route('/leaderboard/<mode>/<sort>/<mods>')
@frontend.route('/lb/<mode>/<sort>/<mods>')
async def leaderboard(mode='std', sort='pp', mods='vn'):
    return await render_template('leaderboard.html', mode=mode, sort=sort, mods=mods)

@frontend.route('/login')
async def login():
    if 'authenticated' in session:
        return await flash('error', "You're already logged in!", 'home')

    return await render_template('login.html')

@frontend.route('/login', methods=['POST'])
async def login_post():
    if 'authenticated' in session:
        return await flash('error', "You're already logged in!", 'home')

    if glob.config.debug:
        login_time = time.time_ns()

    form = await request.form
    username = form.get('username', type=str)
    passwd_txt = form.get('password', type=str)

    if username is None or passwd_txt is None:
        return await flash('error', 'Invalid parameters.', 'home')

    # check if account exists
    user_info = await glob.db.fetch(
        'SELECT id, name, email, priv, '
        'pw_bcrypt, silence_end '
        'FROM users '
        'WHERE safe_name = %s',
        [utils.get_safe_name(username)]
    )

    # user doesn't exist; deny post
    # NOTE: Bot isn't a user.
    if not user_info or user_info['id'] == 1:
        if glob.config.debug:
            log(f"{username}'s login failed - account doesn't exist.", Ansi.LYELLOW)
        return await flash('error', 'Account does not exist.', 'login')

    # cache and other related password information
    bcrypt_cache = glob.cache['bcrypt']
    pw_bcrypt = user_info['pw_bcrypt'].encode()
    pw_md5 = hashlib.md5(passwd_txt.encode()).hexdigest().encode()

    # check credentials (password) against db
    # intentionally slow, will cache to speed up
    if pw_bcrypt in bcrypt_cache:
        if pw_md5 != bcrypt_cache[pw_bcrypt]: # ~0.1ms
            if glob.config.debug:
                log(f"{username}'s login failed - pw incorrect.", Ansi.LYELLOW)
            return await flash('error', 'Password is incorrect.', 'login')
    else: # ~200ms
        if not bcrypt.checkpw(pw_md5, pw_bcrypt):
            if glob.config.debug:
                log(f"{username}'s login failed - pw incorrect.", Ansi.LYELLOW)
            return await flash('error', 'Password is incorrect.', 'login')

        # login successful; cache password for next login
        bcrypt_cache[pw_bcrypt] = pw_md5

    # user not verified; render verify
    if not user_info['priv'] & Privileges.Verified:
        if glob.config.debug:
            log(f"{username}'s login failed - not verified.", Ansi.LYELLOW)
        return await render_template('verify.html')

    # user banned; deny post
    if not user_info['priv'] & Privileges.Normal:
        if glob.config.debug:
            log(f"{username}'s login failed - banned.", Ansi.RED)
        return await flash('error', 'Your account is restricted. You are not allowed to log in.', 'login')

    # login successful; store session data
    if glob.config.debug:
        log(f"{username}'s login succeeded.", Ansi.LGREEN)

    session['authenticated'] = True
    session['user_data'] = {
        'id': user_info['id'],
        'name': user_info['name'],
        'email': user_info['email'],
        'priv': user_info['priv'],
        'silence_end': user_info['silence_end'],
        'is_staff': user_info['priv'] & Privileges.Staff != 0,
        'is_donator': user_info['priv'] & Privileges.Donator != 0
    }

    if glob.config.debug:
        login_time = (time.time_ns() - login_time) / 1e6
        log(f'Login took {login_time:.2f}ms!', Ansi.LYELLOW)

    return await flash('success', f'Hey, welcome back {username}!', 'home')

@frontend.route('/register')
async def register():
    if 'authenticated' in session:
        return await flash('error', "You're already logged in.", 'home')

    if not glob.config.registration:
        return await flash('error', 'Registrations are currently disabled.', 'home')

    return await render_template('register.html')

@frontend.route('/register', methods=['POST'])
async def register_post():
    if 'authenticated' in session:
        return await flash('error', "You're already logged in.", 'home')

    if not glob.config.registration:
        return await flash('error', 'Registrations are currently disabled.', 'home')

    form = await request.form
    username = form.get('username', type=str)
    email = form.get('email', type=str)
    passwd_txt = form.get('password', type=str)

    if username is None or email is None or passwd_txt is None:
        return await flash('error', 'Invalid parameters.', 'home')

    if glob.config.hCaptcha_sitekey != 'changeme':
        captcha_data = form.get('h-captcha-response', type=str)
        if (
            captcha_data is None or
            not await utils.validate_captcha(captcha_data)
        ):
            return await flash('error', 'Captcha failed.', 'register')

    # Usernames must:
    # - be within 2-15 characters in length
    # - not contain both ' ' and '_', one is fine
    # - not be in the config's `disallowed_names` list
    # - not already be taken by another player
    # check if username exists
    if not regexes.username.match(username):
        return await flash('error', 'Invalid username syntax.', 'register')

    if '_' in username and ' ' in username:
        return await flash('error', 'Username may contain "_" or " ", but not both.', 'register')

    if username in glob.config.disallowed_names:
        return await flash('error', 'Disallowed username; pick another.', 'register')

    if await glob.db.fetch('SELECT 1 FROM users WHERE name = %s', username):
        return await flash('error', 'Username already taken by another user.', 'register')

    # Emails must:
    # - match the regex `^[^@\s]{1,200}@[^@\s\.]{1,30}\.[^@\.\s]{1,24}$`
    # - not already be taken by another player
    if not regexes.email.match(email):
        return await flash('error', 'Invalid email syntax.', 'register')

    if await glob.db.fetch('SELECT 1 FROM users WHERE email = %s', email):
        return await flash('error', 'Email already taken by another user.', 'register')

    # Passwords must:
    # - be within 8-32 characters in length
    # - have more than 3 unique characters
    # - not be in the config's `disallowed_passwords` list
    if not 8 <= len(passwd_txt) <= 32:
        return await flash('error', 'Password must be 8-32 characters in length.', 'register')

    if len(set(passwd_txt)) <= 3:
        return await flash('error', 'Password must have more than 3 unique characters.', 'register')

    if passwd_txt.lower() in glob.config.disallowed_passwords:
        return await flash('error', 'That password was deemed too simple.', 'register')

    # TODO: add correct locking
    # (start of lock)
    pw_md5 = hashlib.md5(passwd_txt.encode()).hexdigest().encode()
    pw_bcrypt = bcrypt.hashpw(pw_md5, bcrypt.gensalt())
    glob.cache['bcrypt'][pw_bcrypt] = pw_md5 # cache pw

    safe_name = utils.get_safe_name(username)

    # fetch the users' country
    if (
        request.headers and
        (ip := request.headers.get('X-Real-IP', type=str)) is not None
    ):
        country = await utils.fetch_geoloc(ip)
    else:
        country = 'xx'

    async with glob.db.pool.acquire() as conn:
        async with conn.cursor() as db_cursor:
            # add to `users` table.
            await db_cursor.execute(
                'INSERT INTO users '
                '(name, safe_name, email, pw_bcrypt, country, creation_time, latest_activity) '
                'VALUES (%s, %s, %s, %s, %s, UNIX_TIMESTAMP(), UNIX_TIMESTAMP())',
                [username, safe_name, email, pw_bcrypt, country]
            )
            user_id = db_cursor.lastrowid

            # add to `stats` table.
            await db_cursor.executemany(
                'INSERT INTO stats '
                '(id, mode) VALUES (%s, %s)',
                [(user_id, mode) for mode in range(8)]
            )

    # (end of lock)

    if glob.config.debug:
        log(f'{username} has registered - awaiting verification.', Ansi.LGREEN)

    # user has successfully registered
    return await render_template('verify.html')

@frontend.route('/logout')
async def logout():
    if 'authenticated' not in session:
        return await flash('error', "You can't logout if you aren't logged in!", 'login')

    if glob.config.debug:
        log(f'{session["user_data"]["name"]} logged out.', Ansi.LGREEN)

    # clear session data
    session.pop('authenticated', None)
    session.pop('user_data', None)

    # render login
    return await flash('success', 'Successfully logged out!', 'login')

# social media redirections

@frontend.route('/github')
@frontend.route('/gh')
async def github_redirect():
    return redirect(glob.config.github)

@frontend.route('/discord')
async def discord_redirect():
    return redirect(glob.config.discord_server)

@frontend.route('/youtube')
@frontend.route('/yt')
async def youtube_redirect():
    return redirect(glob.config.youtube)

@frontend.route('/twitter')
async def twitter_redirect():
    return redirect(glob.config.twitter)

@frontend.route('/instagram')
@frontend.route('/ig')
async def instagram_redirect():
    return redirect(glob.config.instagram)

# profile customisation
BANNERS_PATH = Path.cwd() / '.data/banners'
BACKGROUND_PATH = Path.cwd() / '.data/backgrounds'
@frontend.route('/banners/<user_id>')
async def get_profile_banner(user_id: int):
    # Check if avatar exists
    for ext in ('jpg', 'jpeg', 'png', 'gif'):
        path = BANNERS_PATH / f'{user_id}.{ext}'
        if path.exists():
            return await send_file(path)

    return b'{"status":404}'


@frontend.route('/backgrounds/<user_id>')
async def get_profile_background(user_id: int):
    # Check if avatar exists
    for ext in ('jpg', 'jpeg', 'png', 'gif'):
        path = BACKGROUND_PATH / f'{user_id}.{ext}'
        if path.exists():
            return await send_file(path)

    return b'{"status":404}'

@frontend.route('/score/<score_id>')
@frontend.route('/score/<score_id>/<mods>')
async def get_player_score(score_id:int=0, mods:str = "vn"):
    if score_id == 0:
        return await flash('error', "This score does not exist!", "home")
    if mods.lower() not in ["vn", "rx", "ap"]:
        return await flash('error', "Valid mods are vn, rx and ap!", "home")

    # Check score
    score = await glob.db.fetch("SELECT * FROM "
                               f"scores_{mods.lower()} "
                                "WHERE id=%s", score_id)
    if not score:
        return await flash('error', "Score not found!", "home")

    # Get user
    user = await glob.db.fetch("SELECT id, name, country, priv FROM users WHERE id=%s", score['userid'])
    


    if Privileges.Normal not in Privileges(int(user['priv'])):
        if not session:
            return (await render_template('404.html'), 404)
        elif Privileges.Admin not in Privileges(session['user_data']['priv']):
            return (await render_template('404.html'), 404)

    #Get Map
    map_info = await glob.db.fetch("SELECT artist, title, version AS diffname, creator, "
                                   "diff, mode, set_id, max_combo FROM maps WHERE md5=%s", score['map_md5'])
    if not map_info:
        log(f"Tried fetching scoreid {score_id} in {mods} (Route: /score/): Map with md5 '{score['map_md5']}' does not exist in database,"
        " that shouldn't happen unless you deleted it manually", Ansi.RED)
        return await flash('error', 'Could not display score, map does not exist in database', 'home')
    
    #Change variables and stuff like that
    try:
        map_info['diff'] = round(map_info['diff'], 2)
    except:
        map_info['diff'] = map_info['diff']
    score['grade'] = score['grade'].upper()
    user['country'] = user['country'].upper()
    user['banner'] = f"url(https://seventwentyseven.tk/banners/{user['id']});"
    map_info['banner_link'] = f"url('https://assets.ppy.sh/beatmaps/{map_info['set_id']}/covers/cover.jpg');"
    score['acc'] = round(float(score['acc']), 2)
    score['pp'] = round(float(score['pp']), 2)
    #Calculation
    grade_colors= {
        "F": "#ff5959",
        "D": "#ff5959",
        "C": "#ff56da",
        "B": "#3d97ff",
        "A": "#2bff35",
        "S": "#ffcc22",
        "SH": "#cde7e7",
        "X": "#ffcc22",
        "XH": "#cde7e7",
    }
    try:
        grade_shadow = grade_colors[score['grade'].upper()]
    except:
        grade_shadow = "#FFFFFF"

    grade_convert = {"XH": "SS", "X": "SS", "SH": "S"}
    try:
        score['grade'] = grade_convert[score['grade']]
    except:
        score['grade'] = score['grade']
    #add commas to score
    score['score'] = "{:,}".format(int(score['score']))
    #Make badges
    user_priv = Privileges(user['priv'])
    group_list = []
    if Privileges.Normal not in user_priv:
        group_list.append(["RESTRICTED", "#FFFFFF"])
    else:
        if int(user['id']) in [3,4]:
            group_list.append(["OWNER", "#e84118"])
        if Privileges.Dangerous in user_priv:
            group_list.append(["DEV", "#9b59b6"])
        elif Privileges.Admin in user_priv:
            group_list.append(["ADM", "#fbc531"])
        elif Privileges.Mod in user_priv:
            group_list.append(["GMT", "#28a40c"])
        if Privileges.Nominator in user_priv:
            group_list.append(["BN", "#1e90ff"])
        if Privileges.Alumni in user_priv:
            group_list.append(["ALU", "#ea8685"])
        if Privileges.Supporter in user_priv:
            if Privileges.Premium in user_priv:
                group_list.append(["❤❤", "#f78fb3"])
            else:
                group_list.append(["❤", "#f78fb3"])
        elif Privileges.Premium in user_priv:
            group_list.append(["❤❤", "#f78fb3"])
        if Privileges.Whitelisted in user_priv:
            group_list.append(["✓", "#28a40c"])
        
    #Get status
    async with glob.http.get(f"https://osu.seventwentyseven.tk/api/get_player_status?id={user['id']}") as resp:
        resp = await resp.json()
        if resp['player_status']['online'] == True:
            player_status = ["#38c714", "Online"]
        else:
            player_status = ["#000000", "Offline"]
    
    #Mods
        if int(score['mods']) != 0:
            score['mods'] = f"+{Mods(int(score['mods']))!r}"
    return await render_template('score.html', score=score, user=user, map_info=map_info, 
                                grade_shadow=grade_shadow, group_list=group_list, 
                                player_status=player_status, mode_mods=mods)
