# -*- coding: utf-8 -*-

__all__ = ()

import datetime
import aiohttp

import timeago
import pandas
from quart import Blueprint
from quart import render_template
from quart import session
from quart import request

from objects import glob
from objects.utils import flash, determine_plural, time_ago, get_safe_name
from objects.privileges import Privileges

admin = Blueprint('admin', __name__)

@admin.route('/')
@admin.route('/home')
@admin.route('/dashboard')
async def home():
    """Render the homepage of guweb's admin panel."""
    if not 'authenticated' in session:
        return await flash('error', 'Please login first.', 'login')
    author = await glob.db.fetch("SELECT priv FROM users WHERE id=%s", session['user_data']['id'])
    session['user_data']['priv'] = author['priv']
    author = Privileges(int(author['priv']))
    if Privileges.Admin not in author:
        return await flash('error', f'You have insufficient privileges. If you have privileges, try entering your profile to reload them.', 'home')

    # fetch data from database
    dash_data = await glob.db.fetch(
        'SELECT COUNT(id) registered, '
        '(SELECT name FROM users ORDER BY id DESC LIMIT 1) latest_user, '
        '(SELECT COUNT(id) FROM users WHERE NOT priv & 1) banned, '
        '(SELECT COUNT(id) FROM users WHERE priv & 16 OR priv & 32) supporter '
        'FROM users'
    )

    most_played = await glob.db.fetch(
        "SELECT id, set_id, CONCAT(artist, ' - ', title, ' [', version, ']') "
        "AS `map_info`, passes FROM maps ORDER BY passes DESC LIMIT 1"
    )

    recent_logs = await glob.db.fetchall(
        "SELECT `logs`.`from`, `logs`.`to`, `logs`.`msg`, `logs`.`time`, "
        "`atbl`.`name` AS `author_name`, `rtbl`.`name` AS `receiver_name` FROM "
        "`logs` LEFT JOIN users AS `atbl` ON `logs`.`from` = atbl.id LEFT JOIN "
        "users AS `rtbl` ON `logs`.`to` = rtbl.id ORDER BY time DESC LIMIT 8"
        )
    for el in recent_logs:
        if '> restricted' in el['msg']:
            el['msg'] = el['msg'].split('for "', 1)
            el['msg'] = f"Reason: {el['msg'][1][:-2]}"
            el['color'] = "red"
            el['type'] = "restricted"
            el['icon'] = "fas fa-user-slash"
            el['time'] = time_ago(datetime.datetime.utcnow(), pandas.to_datetime(el['time'], format="%Y-%m-%d %H:%M:%S"), time_limit=1) + " ago"
        elif 'note' in el['msg']:
            el['msg'] = el['msg'].split('added note:', 1)
            el['msg'] = f"Note Content: {el['msg'][1]}"
            el['color'] = "blue"
            el['type'] = "added note to"
            el['icon'] = "fas fa-sticky-note"
            el['time'] = time_ago(datetime.datetime.utcnow(), pandas.to_datetime(el['time'], format="%Y-%m-%d %H:%M:%S"), time_limit=1) + " ago"
        elif '> unrestricted' in el['msg']:
            el['msg'] = el['msg'].split('for "', 1)
            el['msg'] = f"Reason: {el['msg'][1][:-2]}"
            el['color'] = "green"
            el['type'] = "unrestricted"
            el['icon'] = "fas fa-user-check"
            el['time'] = time_ago(datetime.datetime.utcnow(), pandas.to_datetime(el['time'], format="%Y-%m-%d %H:%M:%S"), time_limit=1) + " ago"
        elif '> unsilenced' in el['msg']:
            el['msg'] = ""
            el['color'] = "lime"
            el['type'] = "unsilenced"
            el['icon'] = "fas fa-comment"
            el['time'] = time_ago(datetime.datetime.utcnow(), pandas.to_datetime(el['time'], format="%Y-%m-%d %H:%M:%S"), time_limit=1) + " ago"
        elif '> silenced' in el['msg']:
            el['msg'] = el['msg'].split("silenced (", 1)
            el['msg'] = el['msg'][1].split(') for "', 1)
            el['msg'][0] = datetime.timedelta(seconds=int(el['msg'][0][:-1]))
            el['msg'] = f"Reason: {el['msg'][1][:-2]}. | Silenced for {el['msg'][0]} hours"
            el['color'] = "orange"
            el['type'] = "silenced"
            el['icon'] = "fas fa-comment-slash"
            el['time'] = time_ago(datetime.datetime.utcnow(), pandas.to_datetime(el['time'], format="%Y-%m-%d %H:%M:%S"), time_limit=1) + " ago"
        else:
            el['color'] = "cyan"
            el['type'] = "Other"
            el['icon'] = "fas fa-question"
            el['time'] = time_ago(datetime.datetime.utcnow(), pandas.to_datetime(el['time'], format="%Y-%m-%d %H:%M:%S"), time_limit=1) + " ago"

    return await render_template(
        'admin/home.html', dash_data=dash_data, datetime=datetime, timeago=timeago, most_played=most_played,
        recent_logs=recent_logs
    )

@admin.route('/users/')
async def users():
    if not 'authenticated' in session:
        return await flash('error', 'Please login first.', 'login')
    author = await glob.db.fetch("SELECT priv FROM users WHERE id=%s", session['user_data']['id'])
    session['user_data']['priv'] = author['priv']
    author = Privileges(int(author['priv']))
    if Privileges.Admin not in author:
        return await flash('error', f'You have insufficient privileges. If you have privileges, try entering your profile to reload them.', 'home')

    #Get args
    page = request.args.get("page")
    try:
        if page.isdigit() == False:
            page = 1
        else:
            page = int(page)
    except:
        page = 1

    limit = request.args.get("limit")
    try:
        if limit.isdigit() == False:
            limit = 10
        else:
            limit = int(limit)
    except:
        limit = 10

    #Calculate page offset
    if page<1:
        page = 1
    #Get max page
    max_page = await glob.db.fetch('SELECT COUNT(id) AS user_num FROM users')
    max_page = max_page['user_num']
    max_page = int((max_page + limit - 1) // limit)
    if max_page < page:
        page = max_page

    offset=(page-1)*limit
    #Get users test
    users = await glob.db.fetchall(
        "SELECT id, name, country, priv FROM users ORDER "
        "BY id DESC LIMIT %s OFFSET %s", (limit, offset)
    )

    for i in users:
        ipriv = Privileges(int(i['priv']))
        if Privileges.Normal not in ipriv:
            i['priv'] = "Restricted"
        else:
            if int(i['id']) in [3, 4]:
                i['priv'] = "Owner"
            elif Privileges.Dangerous in ipriv:
                i['priv'] = "Developer"
            elif Privileges.Admin in ipriv:
                i['priv'] = "Admin"
            elif Privileges.Mod in ipriv:
                i['priv'] = "GMT"
            elif Privileges.Nominator in ipriv:
                i['priv'] = "BN"
            elif Privileges.Supporter in ipriv:
                if Privileges.Premium not in ipriv:
                    i['priv'] = "Supporter"
                else:
                    i['priv'] = "Premium"
            elif Privileges.Whitelisted in ipriv:
                i['priv'] = "Verified"
            elif Privileges.Verified in ipriv:
                i['priv'] = "Normal"
            elif Privileges.Normal in ipriv:
                i['priv'] = "Unverified"


    #Pager
    page_foot = []
    if page == 1:
        page_foot.append([page, " active"])
        page_foot.append([page+1, ""])
        page_foot.append([page+2, ""])
        page_foot.append([page+3, ""])
        page_foot.append([page+4, ""])
        page_foot.append([page-1, " disabled"])
        page_foot.append([page+1, ""])
    elif page == 2:
        page -= 1
        page_foot.append([page, ""])
        page_foot.append([page+1, " active"])
        page_foot.append([page+2, ""])
        page_foot.append([page+3, ""])
        page_foot.append([page+4, ""])
        page_foot.append([page-1, ""])
        page_foot.append([page+1, ""])
    elif page == max_page:
        page_foot.append([max_page-4, ""])
        page_foot.append([max_page-3, ""])
        page_foot.append([max_page-2, ""])
        page_foot.append([max_page-1, ""])
        page_foot.append([max_page, " active"])
        page_foot.append([max_page-1, ""])
        page_foot.append([max_page+1, "disabled"])
    elif page == max_page-1:
        page_foot.append([max_page-4, ""])
        page_foot.append([max_page-3, ""])
        page_foot.append([max_page-2, ""])
        page_foot.append([max_page-1, " active"])
        page_foot.append([max_page, ""])
        page_foot.append([max_page-1, ""])
        page_foot.append([max_page+1, ""])
    else:
        page_foot.append([page-2, ""])
        page_foot.append([page-1, ""])
        page_foot.append([page, " active"])
        page_foot.append([page+1, ""])
        page_foot.append([page+2, ""])
        page_foot.append([page-1, ""])
        page_foot.append([page+1, ""])

    # fetch data from database
    user_data = await glob.db.fetch(
        'SELECT COUNT(id) registered, '
        '(SELECT COUNT(id) FROM users WHERE NOT priv & 1) banned, '
        '(SELECT COUNT(id) FROM users WHERE priv & 16 OR priv & 32) supporter '
        'FROM users'
    )


    async with glob.http.get("https://osu.seventwentyseven.tk/api/get_player_count") as r:
        resp = await r.json()
    user_data['online'] = resp['counts']['online']

    return await render_template('admin/users.html', users=users, page_foot=page_foot, user_data=user_data, max_page=max_page)

@admin.route('/users/edit/<id>')
async def user_edit(id):
    """Edit User Page."""

    if not 'authenticated' in session:
        return await flash('error', 'Please login first.', 'login')
    author = await glob.db.fetch("SELECT priv FROM users WHERE id=%s", session['user_data']['id'])
    session['user_data']['priv'] = author['priv']
    author = Privileges(int(author['priv']))
    if Privileges.Admin not in author:
        return await flash('error', f'You have insufficient privileges. If you have privileges, try entering your profile to reload them.', 'home')

    user_data = await glob.db.fetch(
        'SELECT id, name, email, priv, country, silence_end, donor_end, '
        'creation_time, latest_activity, clan_id, clan_priv '
        'FROM users '
        'WHERE safe_name IN (%s) OR id IN (%s) LIMIT 1',
        [id, get_safe_name(id)]
    )
    #Permission checks
    usrprv = Privileges(int(user_data['priv']))
    admpriv = Privileges(int(session['user_data']['priv']))
    #Editing admin (Dev, owners only)
    #Editing owner (Owners only)
    if int(user_data['id']) in [3,4] and int(session['user_data']['id']) not in [3,4]:
        access_denied = {'higher_group': True, 'err_msg': "You dont have permissions to edit Owners"}
        return await render_template('admin/edit_user.html', user_data=user_data, access_denied=access_denied)
    else:
        access_denied = {'higher_group': False}
    #Editing dev (Owners only)
    if Privileges.Dangerous in usrprv and int(session['user_data']['id']) not in [3,4]:
        access_denied = {'higher_group': True, 'err_msg': "You dont have permissions to edit Developers"}
        return await render_template('admin/edit_user.html', user_data=user_data, access_denied=access_denied)
    else:
        access_denied = {'higher_group': False}
    if Privileges.Admin in usrprv and Privileges.Dangerous not in admpriv:
        access_denied = {'higher_group': True, 'err_msg': "You dont have permissions to edit Admins"}
        return await render_template('admin/edit_user.html', user_data=user_data, access_denied=access_denied)
    else:
        access_denied = {'higher_group': False}


    #Format join date
    user_data['creation_time'] = datetime.datetime.fromtimestamp(int(user_data['creation_time'])).strftime("%d %B %Y, %H:%M")

    admin = session['user_data']
    if int(admin['id']) in [3,4]:
        admin['is_owner'] = True


    return await render_template('admin/edit_user.html', user_data=user_data, admin=admin, access_denied=access_denied)