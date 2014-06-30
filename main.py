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
from multiprocessing.process import Process
import os
import pyinotify
from subprocess import Popen, PIPE
import sys

import json2redis
import record


def rename(path):
    wm = pyinotify.WatchManager()  # Watch Manager
    mask = pyinotify.IN_DELETE | pyinotify.IN_CREATE  # watched events

    class EventHandler(pyinotify.ProcessEvent):
        def process_IN_CREATE(self, event):
            #print "Creating:", event.pathname
            filename= os.path.basename(event.pathname)
            if not filename.endswith('meta') and filename.find('file') != -1 and os.path.isfile(event.pathname):
                p=Popen(['md5deep',event.pathname],stdout=PIPE)
                for l in p.stdout.readlines():
                    tokens=l.split(' ')
                    md5value=tokens[0]
                    path=tokens[2].replace('\n','')
                    print path
                    print md5value
                    md5file=os.path.join(os.path.dirname(path),md5value)
                    print os.path.join(os.path.dirname(path),md5value)
                    os.rename(path,md5file)
    def process_IN_DELETE(self, event):
        print "Removing:", event.pathname

    notifier = pyinotify.AsyncNotifier(wm, EventHandler())
    wdd = wm.add_watch(path, mask, rec=True)

    notifier.loop()

def transform(path):
    js=json2redis.jsontoredis(path)
    js.run()
def process():
    r=record.Record()
    r.run()
def prepare_env(path):
    if not os.path.isdir(path):
        os.mkdir(path)
    file_watching = os.path.join(path,'eve.json')
    if not os.path.isfile(file_watching):
        with open(file_watching, 'a'):
                os.utime(file_watching, None)
                return file_watching
    else:
        return file_watching
if __name__ == '__main__':
    
    re= Process(target=rename,args=(sys.argv[1],))
    re.start()
    file_watching=prepare_env(sys.argv[1])
    print file_watching
    if file_watching:
        tr=Process(target=transform,args=(file_watching,))                                                                                                                                                                                                                                                                                                                                                                                                       
        tr.start()
    rec=Process(target=process,args=())
    rec.start()
    
    pass