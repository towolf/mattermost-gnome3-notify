#!/usr/bin/env python3
""" Simple script, which connects to Mattermost using a Websocket, to notice
@-mentions and pop up persistent Gnome Notifications.

Requires https://github.com/Vaelor/python-mattermost-driver
"""

import json
import logging
import asyncio
from mattermostdriver import Driver

import gi
gi.require_version('Notify', '0.7')
gi.require_version('Secret', '1')
from gi.repository import GLib
from gi.repository import Notify
from gi.repository import Secret

log = logging.getLogger(__name__)

SECRET_SCHEMA = Secret.Schema.new(
    'com.mattermost.mock',
    Secret.SchemaFlags.DONT_MATCH_NAME,
    {'username_value': Secret.SchemaAttributeType.STRING,
     'action_url': Secret.SchemaAttributeType.STRING}
)

# Default websocket timeout - this is needed to send a heartbeat
# to keep the connection alive
DEFAULT_TIMEOUT = 30

class MattermostBackend():
    def __init__(self):
        self.url = 'mattermost.example.com'
        self._login = 'foo@example.com'
        self._scheme = 'https'
        self._port = 443
        self.insecure = False
        self.timeout = DEFAULT_TIMEOUT
        self.teamid = ''
        self.token = ''
        self.driver = None

        # Get password from Gnome keyring, matching the stored Chromium password
        self._password = Secret.password_lookup_sync(
            SECRET_SCHEMA,
            {'username_value': self._login,
             'action_url': 'https://mattermost.example.com/login'},
            None
        )

    @asyncio.coroutine
    def mattermost_event_handler(self, payload):
        if not payload:
            return

        payload = json.loads(payload)
        if 'event' not in payload:
            log.debug('Message contains no event: {}'.format(payload))
            return

        event_handlers = {
            'posted': self._message_event_handler,
        }

        event = payload['event']
        event_handler = event_handlers.get(event)

        if event_handler is None:
            log.debug('No event handler available for {}, ignoring.'.format(event))
            return

        try:
            event_handler(payload)
        except Exception:
            log.exception('{} event handler raised an exception'.format(event))

    def _message_event_handler(self, message):
        log.debug(message)
        data = message['data']

        broadcast = message['broadcast']

        if 'channel_id' in data:
            channelid = data['channel_id']
        elif 'channel_id' in broadcast:
            channelid = broadcast['channel_id']
        else:
            log.error("Couldn't find a channelid for event {}".format(message))
            return

        channel_type = data['channel_type']

        if channel_type != 'D':
            channel = data['channel_name']
            if 'team_id' in data:
                teamid = data['team_id']
                if teamid:
                    team = self.driver.api['teams'].get_team(team_id=teamid)
                    teamname = team['display_name']
        else:
            channel = channelid
            teamname = None

        text = ''
        userid = None

        if 'post' in data:
            post = json.loads(data['post'])
            text = post['message']
            userid = post['user_id']
            if 'type' in post and post['type'] == 'system_add_remove':
                log.info('Ignoring message from System')
                return

        if 'user_id' in data:
            userid = data['user_id']

        if not userid:
            log.error('No userid in event {}'.format(message))
            return

        mentions = []
        if 'mentions' in data:
            mentions = json.loads(data['mentions'])

        if mentions:
            username = self.driver.api['users'].get_user(user_id=userid)['username']

            print('mentioned: ', teamname, '"', mentions, '"', username, text)
            if self.userid in mentions:
                if teamname:
                    self.notify('{} in {}/{}'.format(username, teamname, channel), text)
                else:
                    self.notify('{} in DM'.format(username), text)
            log.info('"posted" event from {}: {}'.format(
                self.driver.api['users'].get_user(user_id=userid)['username'],
                text
            ))

    def notify(self, summary, desc=''):
        self._notification = Notification(summary, desc)

    def serve_once(self):
        self.driver = Driver({
            'scheme': self._scheme,
            'url': self.url,
            'port': self._port,
            'verify': not self.insecure,
            'timeout': self.timeout,
            'login_id': self._login,
            'password': self._password
        })
        self.driver.login()

        self.userid = self.driver.api['users'].get_user(user_id='me')['id']

        self.token = self.driver.client.token

        try:
            loop = self.driver.init_websocket(event_handler=self.mattermost_event_handler)
            loop.run_forever()
            # loop.stop()
        except KeyboardInterrupt:
            log.info("Interrupt received, shutting down..")
            Notify.uninit()
            self.driver.logout()
            return True
        except Exception:
            log.exception("Error reading from RTM stream:")
        finally:
            log.debug("Triggering disconnect callback")


class Notification:
    def __init__(self, summary, body):
        if Notify.is_initted() or Notify.init('Mattermost'):
            self.notification = Notify.Notification.new(summary, body, 'user-available')
            self.notification.set_hint('desktop-entry', GLib.Variant('s', 'mattermost'))
            self.notification.set_hint('category', GLib.Variant('s', 'im.received'))
            self.notification.set_category('im.received')
            self.notification.show()
        else:
            raise Exception('Not Supported')

if __name__ == '__main__':
    backend = MattermostBackend()
    backend.serve_once()
