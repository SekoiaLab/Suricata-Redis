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
from datetime import time
import json
from redis.client import StrictRedis
from time import sleep


class Record(object):
    def __init__(self,host='127.0.0.1',port=6379):         
        self.r=StrictRedis()
    
    def run(self):
        while True:
            value=self.r.rpop('alerts')
            if value:
                obj=json.loads(value)
                keyredis=obj['src_ip']+'_'+str(obj['src_port'])+'_'+ obj['dest_ip']+'_'+str(obj['dest_port'])
                entry=self.r.get(keyredis)
                if entry:
                    restruct=json.loads(entry)
                else:
                    restruct={}
                if not 'http' in restruct:
                    restruct['http']=[]
                if not 'alerts' in restruct:
                    restruct['alerts']=[]
                if not 'files' in restruct:
                    restruct['files']=[]  
                if 'alert' in obj:    
                    restruct['alerts'].append(obj['alert']['signature'])
                if 'fileinfo' in obj:
                    restruct['files'].append(obj['fileinfo'])
                if 'http' in obj:
                    restruct['http'].append(obj['http'])
                if len(restruct)>0:
                    self.r.set(keyredis, json.dumps(restruct))
            else:
                sleep(1)
