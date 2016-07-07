@load base/frameworks/software
@load base/utils/directions-and-hosts

@load policy/frameworks/software/windows-version-detection

@load policy/protocols/ftp/software
@load policy/protocols/http/detect-webapps
@load policy/protocols/http/software
@load policy/protocols/http/software-browser-plugins
@load policy/protocols/mysql/software
@load policy/protocols/smtp/software
@load policy/protocols/ssh/software

@load policy/protocols/modbus/track-memmap
@load policy/protocols/modbus/known-masters-slaves

# Not sure about these ones
@load policy/frameworks/dpd/detect-protocols
@load policy/frameworks/intel/do_notice
@load policy/frameworks/intel/seen
@load policy/frameworks/software/windows-version-detection
@load policy/protocols/ftp/detect

module IvreFlow;

export {
    redef FTP::default_capture_password = T;
    redef HTTP::default_capture_password = T;
    redef Software::asset_tracking = ALL_HOSTS;
}

