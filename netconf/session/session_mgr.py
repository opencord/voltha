#!/usr/bin/env python
#
# Copyright 2017 the original author or authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
from session import Session
import structlog

log = structlog.get_logger()

class SessionManager:
    instance = None

    def __init__(self):
        self.next_session_id = 1
        self.sessions = {}

    def create_session(self, user):
        session = Session(self.next_session_id, user)
        self.sessions[self.next_session_id] = session
        self.next_session_id += 1
        return session

    def remove_session(self, session):
        session_id = session.session_id
        if session_id in self.sessions.keys():
            del self.sessions[session_id]
            log.info('remove-session', session_id=session_id)
        else:
            log.error('invalid-session', session_id=session_id)


def get_session_manager_instance():
    if SessionManager.instance == None:
        SessionManager.instance = SessionManager()
    return SessionManager.instance