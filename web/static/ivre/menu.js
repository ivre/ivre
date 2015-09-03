/*
 * This file is part of IVRE.
 * Copyright 2011 - 2015 Pierre LALET <pierre.lalet@cea.fr>
 *
 * IVRE is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * IVRE is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
 * License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with IVRE. If not, see <http://www.gnu.org/licenses/>.
 */

/************* Menu content ****************/

/* Menus structure is as follow:
 *
 * - items: menu content, see below
 * - share: (optional) if set to true, add a 'Share' menu. Default is false
 *
 * The menu content is a list of recursive 'items'.
 *
 * items:
 * - title: printed string
 * - action: (optional) javascript to execute on click
 * - icon: (optional) associated glyphicon
 * - items: (recursive) sub-menu
 *
 * If there is only one level of item, the menu is displayed as '.menu-single';
 * otherwise, a Bootstrap dropdown is used.
 *
 * The second layer of recursivity is displayed thanks to right chevron.
 *
 * Only three level of menu is currently supported.
 */

var MENU_MAIN = {
    share: true,
    items: [
	{title: "HELP",
	 action: "$scope.togglenotes('doc:webui');",
	 icon: "question-sign",
	},
	{title: "Unix",
	 icon: "heart",
	 items: [
	     {title: "NFS",
	      action: "$scope.setparam('nfs', undefined, true, true); $scope.setparam('display', 'script:rpcinfo,nfs-showmount,nfs-ls', true);",
	     },
	     {title: "NIS / YP",
	      action: "$scope.setparam('nis')",
	     },
	     {title: "X11",
	      action: "$scope.setparam('x11srv');",
	      items: [
		  {title: "open",
		   action: "$scope.setparam('x11open');",
		  }
	      ],
	     },
	 ],
	},
	{title: "Win",
	 icon: "th-large",
	 items: [
	     {title: "XP / 445",
	      action: "$scope.setparam('xp445');",
	     },
	     {title: "SMB shares",
	      action: "$scope.setparam('smbshare', undefined, true, true); $scope.setparam('display', 'script:smb-enum-shares,smb-ls', true);",
	      items: [
		  {title: "writable",
		   action: "$scope.setparam('smbshare', 'w', true, true); $scope.setparam('display', 'script:smb-enum-shares,smb-ls', true);"
		  },
	      ],
	     },
	     {title: "MS-SQL empty password",
	      action: "$scope.setparam('mssqlemptypwd');"
	     },
	 ],
	},
	{title: "Web",
	 icon: "globe",
	 items: [
	     {title: "HTTP Auth",
	      action: "setparam('authhttp');",
	     },
	     {title: "Shared web files",
	      action: "$scope.setparam('webfiles', undefined, true, true); $scope.setparam('display', 'script:ls', true);",
	     },
	     {title: "Git repository",
	      action: "$scope.setparam('script', 'http-git:\"/Git repository found/\"');",
	     },
	     {title: "OWA",
	      action: "$scope.setparam('owa');",
	     },
	     {title: "PHPMyAdmin",
	      action: "$scope.setparam('phpmyadmin');",
	     }
	 ],
	},
	{title: "Auth",
	 icon: "lock",
	 items: [
	     {title: "HTTP Auth",
	      action: "$scope.setparam('authhttp');",
	     },
	     {title: "Anonymous FTP",
	      action: "$scope.setparam('anonftp', undefined, true, true); $scope.setparam('display', 'script:ftp-anon', true);",
	     },
	     {title: "Anonymous LDAP",
	      action: "$scope.setparam('anonldap')",
	     },
	     {title: "NIS / YP",
	      action: "$scope.setparam('nis')",
	     },
	     {title: "VNC Authentication Bypass",
	      action: "$scope.setparam('authbypassvnc');",
	     },
	     {title: "MS-SQL empty password",
	      action: "$scope.setparam('mssqlemptypwd')",
	     },
	     {title: "MY-SQL empty password",
	      action: "$scope.setparam('mysqlemptypwd')",
	     },
	 ],
	},
	{title: "Relay",
	 icon: "share-alt",
	 items: [
	     {title: "HTTP Open Proxy",
	      action: "$scope.setparam('script', 'http-open-proxy');",
	     },
	     {title: "Socks Open Proxy",
	      action: "$scope.setparam('script', 'socks-open-proxy');",
	     },
	     {title: "SMTP Open Relay",
	      action: "$scope.setparam('script', 'smtp-open-relay');",
	     },
	     {title: "FTP Bounce",
	      action: "$scope.setparam('script', 'ftp-bounce:&quot;bounce working!&quot;');",
	     },
	 ],
	},
	{title: "Fun",
	 icon: "screenshot",
	 items: [
	     {title: "Webcam",
	      action: "$scope.setparam('devicetype', 'webcam');",
	      items: [
		  {title: "GeoVision",
		   action: "$scope.setparam('geovision');",
		  },
	      ],
	     },
	     {title: "Network devices",
	      action: "setparam('netdev');",
	     },
	     {title: "Telephony devices",
	      action: "setparam('phonedev');",
	     },
	     {title: "Screenshots",
	      action: "$scope.setparam('screenshot', undefined, true, true); $scope.setparam('display', 'screenshot', true);",
	     },
	     {title: "Shared files",
	      action: "setparam('file', undefined, true, true); setparam('display', 'script:ls', true);",
	     },
	 ],
	},
	{title: "Sort",
	 icon: "random",
	 items: [
	     {title: "Date of scan",
	      action: "$scope.setparam('sortby', 'endtime', true);",
	      icon: "arrow-down",
	     },
	     {title: "Date of scan",
	      action: "$scope.setparam('-sortby', 'endtime', true);",
	      icon: "arrow-up",
	     },
	     {title: "IP Address",
	      action: "$scope.setparam('sortby', 'addr', true);",
	      icon: "arrow-down",
	     },
	     {title: "IP Address",
	      action: "$scope.setparam('-sortby', 'addr', true);",
	      icon: "arrow-up",
	     },
	     {title: "Open ports",
	      action: "$scope.setparam('sortby', 'openports.count', true);",
	      icon: "arrow-down",
	     },
	     {title: "Open ports",
	      action: "$scope.setparam('-sortby', 'openports.count', true);",
	      icon: "arrow-up",
	     },
	     {title: "Archives",
	      action: "'archives' in parametersobj ? unsetparam('archives') : $scope.setparam('archives');",
	      icon: "file",
	     },
	 ],
	},
    ]
};

var MENU_REPORT = {
    share: true,
    items: [
	{title: "Main",
	 action: "document.location='index.html' + document.location.hash",
	 icon: "home",
	},
	{title: "Config",
	 action: "$scope.toggleShowFilter();",
	 icon: "list",
	},
	{title: "Build",
	 action: "$scope.build_all();",
	 icon: "ok",
	},
    ]
};

var MENUS = {
    main: MENU_MAIN,
    report: MENU_REPORT,
};
