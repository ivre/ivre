@load policy/protocols/smb
#@load policy/misc/dump-events

module IvreFlow;

export {
    #redef DumpEvents::include = /.*dce.*/;
}
