###############################################################################
#
#   Suricata_Redis - Poc de code de la NDH2K14
#    cert@sekoia.fr - http://www.sekoia.fr
#   Copyright (C) 2014  SEKOIA
#
#   This program is free software: you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation, either version 3 of the License, or
#   (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
###############################################################################
import json
from redis.client import StrictRedis
import sh
import threading


class redis(object):
    def __init__(self,host='127.0.0.1',port=6379):
        self.r = StrictRedis(host,port)
    def rec(self,k,v):
        self.r.set(k, v)
    def rpush(self,v):
        self.r.rpush('alerts',v)
        
class jsontoredis(object):
    def __init__(self, path,host='localhost',port=6379): 
        self.path=path
        self.r=redis(host,port)
        
    def read(self):
        for l in sh.tail("-f", self.path, _iter=True):
            try:
                yield l.replace('\r\n','')
            except sh.ErrorReturnCode:
                yield None
    
    def run(self):
            restruct={}
            for obj in self.read():
                self.r.rpush(obj)