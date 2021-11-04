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

gw_api = Blueprint('gw_api', __name__)


@gw_api.route('/')
async def api_home():
    return {'status': 'Error', 'msg': 'You must specify route'}

@gw_api.route('/test_route')
async def api_test_route():
    if 'authenticated' not in session or int(session['user_data']['id']) not in [4]:
        return {'status': 'Error', 'msg': 'You are not on welcome list'}
    else:
        return '<img src="https://c.tenor.com/PnUf_7Zl63cAAAAC/touhou-fumo.gif">'
