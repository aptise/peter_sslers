"""
Based on:

https://github.com/Pylons/webtest/blob/main/webtest/http.py

------------------

Copyright (c) 2010 Ian Bicking and Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
"""

# stdlib
from http import client
import logging
import os
import socket
import threading
import time
from typing import Dict, Tuple, TYPE_CHECKING, Union

if TYPE_CHECKING:
    from waitress.wasyncore import dispatcher

# pypy
from waitress.server import TcpWSGIServer
import webob


def get_free_port() -> Tuple[str, int]:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("", 0))
    ip, port = s.getsockname()
    s.close()
    ip = os.environ.get("WEBTEST_SERVER_BIND", "127.0.0.1")
    return ip, port


def check_server(
    host: str,
    port: Union[str, int],
    path_info: str = "/",
    timeout: float = 3,
    retries: int = 30,
) -> int:
    """Perform a request until the server reply"""
    if retries < 0:
        return 0
    time.sleep(0.3)
    for i in range(retries):
        conn = client.HTTPConnection(host, int(port), timeout=timeout)
        try:
            conn.request("GET", path_info)
            res = conn.getresponse()
            return res.status
        except (OSError, client.HTTPException):
            time.sleep(0.3)
        finally:
            conn.close()
    return 0


class StopableWSGIServer(TcpWSGIServer):
    """StopableWSGIServer is a TcpWSGIServer which run in a separated thread.
    This allow to use tools like casperjs or selenium.

    Server instance have an ``application_url`` attribute formatted with the
    server host and port.
    """

    _map: Dict[int, "dispatcher"]
    was_shutdown = False

    def __init__(self, application, *args, **kwargs):
        super().__init__(self.wrapper, *args, **kwargs)
        self.runner = None
        self.test_app = application
        self.application_url = f"http://{self.adj.host}:{self.adj.port}/"

    def wrapper(self, environ, start_response):
        """Wrap the wsgi application to override some path:
        ``/__application__``: allow to ping the server.
        """
        if "__application__" in environ["PATH_INFO"]:
            return webob.Response("server started")(environ, start_response)
        return self.test_app(environ, start_response)

    def run(self):
        """Run the server"""
        try:
            self.asyncore.loop(0.5, map=self._map)
        except OSError:  # pragma: no cover
            if not self.was_shutdown:
                raise

    def shutdown(self) -> bool:
        """Shutdown the server"""
        # avoid showing traceback related to asyncore
        self.was_shutdown = True
        self.logger.setLevel(logging.FATAL)
        while self._map:
            triggers = list(self._map.values())
            for trigger in triggers:
                trigger.handle_close()
        self.maintenance(0)
        self.task_dispatcher.shutdown()
        return True

    @classmethod
    def create(cls, application, **kwargs):
        """Start a server to serve ``application``. Return a server
        instance."""
        host, port = get_free_port()
        if "port" not in kwargs:
            kwargs["port"] = port
        if "host" not in kwargs:
            kwargs["host"] = host
        server = cls(application, **kwargs)
        server.runner = threading.Thread(target=server.run)
        server.runner.daemon = True
        server.runner.start()
        return server

    def wait(self, retries: int = 30) -> bool:
        """Wait until the server is started"""
        running = check_server(
            self.adj.host, self.adj.port, "/__application__", retries=retries
        )
        if running:
            return True
        self.shutdown()
        return False
