# RadicaleIMAP IMAP authentication plugin for Radicale.
# Copyright (C) 2017, 2020 Unrud <unrud@outlook.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import imapclient
import ssl
import string

from radicale.auth import BaseAuth
from radicale.log import logger
from scramp import ScramClient

def imap_address(value):
    if "]" in value:
        pre_address, pre_address_port = value.rsplit("]", 1)
    else:
        pre_address, pre_address_port = "", value
    if ":" in pre_address_port:
        pre_address2, port = pre_address_port.rsplit(":", 1)
        address = pre_address + pre_address2
    else:
        address, port = pre_address + pre_address_port, None
    try:
        return (address.strip(string.whitespace + "[]"),
                None if port is None else int(port))
    except ValueError:
        raise ValueError("malformed IMAP address: %r" % value)


def imap_security(value):
    if value not in ("tls", "starttls", "none"):
        raise ValueError("unsupported IMAP security: %r" % value)
    return value


PLUGIN_CONFIG_SCHEMA = {"auth": {
    "imap_host": {"value": "", "type": imap_address},
    "imap_security": {"value": "tls", "type": imap_security}}}

class ScrampAuthMech():
    def __init__(self, username, password, mechanisms):
        self._client = ScramClient(mechanisms, username, password)
        self._step = 0
    
    def __call__(self, challenge):
        logger.info(f"Auth step {self._step}, challenge: {repr(challenge)}")
        if type(challenge) is bytes:
            challenge = challenge.decode('utf-8')
        if self._step == 0:
            self._step += 1
            return self._client.get_client_first()
        if self._step == 1:
            self._step += 1
            self._client.set_server_first(challenge)
            return self._client.get_client_final()
        self._client.set_server_final(challenge)
        

class Auth(BaseAuth):
    """Authenticate user with IMAP."""

    def __init__(self, configuration):
        super().__init__(configuration.copy(PLUGIN_CONFIG_SCHEMA))

    def login(self, login, password):
        host, port = self.configuration.get("auth", "imap_host")
        security = self.configuration.get("auth", "imap_security")
        try:
            connection = imapclient.IMAPClient(host, port, ssl=(security == "tls"))
            if security == "starttls":
                connection.starttls()
            capabilities = [c.decode() for c in connection.capabilities()]
            logger.info(f"Server has the following capabilities: {', '.join(capabilities)})")
            scram_mechs = [item.split('=')[1] for item in capabilities if item.startswith('AUTH=') and 'SCRAM' in item]
            supports_plain = 'AUTH=PLAIN' in capabilities

            try:
                if scram_mechs:
                    mech = scram_mechs[0]
                    logger.info(f"Trying SASL with {mech}")
                    connection.sasl_login(scram_mechs[0], ScrampAuthMech(login, password, [mech]))
                elif supports_plain:
                    logger.info(f"Trying AUTH PLAIN")
                    connection.plain_login(login, password)
                else:
                    logger.info(f"Trying LOGIN")
                    connection.login(login, password)
            except Exception as e:
                        logger.debug(
                            "IMAP authentication failed: %s", e, exc_info=True)
                        return ""

            connection.logout()
            return login
        except Exception as e:
            raise RuntimeError("Failed to communicate with IMAP server %r: "
                               "%s" % ("[%s]:%d" % (host, port), e)) from e
