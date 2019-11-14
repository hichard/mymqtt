Import('RTT_ROOT')
from building import *

# get current directory
cwd = GetCurrentDir()

# The set of source files associated with this SConscript file.
src = Glob('MQTTPacket/src/*.c')

src += ['MQTTClient-C/mqtt_client.c']

if GetDepend(['PKG_USING_MYMQTT_EXAMPLE']):
    src += Glob('samples/*.c')

if GetDepend(['PKG_USING_MYMQTT_TEST']):
    src += Glob('tests/*.c')

path = [cwd + '/MQTTPacket/src']
path += [cwd + '/MQTTClient-C']

group = DefineGroup('my-mqtt', src, depend = ['PKG_USING_MYMQTT'], CPPPATH = path)

Return('group')
