#!/bin/bash

# Example: ./install.sh chef.xtain.net 172.16.1.1 wrt-individual-mruta "role[micro-router]"

if [ -f "deployment/etc/chef/config.json" ]; then
  rm deployment/etc/chef/*
fi

server="${1}"
node="${2}"
nodename="${3}"
runlist="${4}"
privatekeypath="${5}"

create-config() {
  if [ -z "${server}" ]; then
    read -p "Server: " server
  fi
  if [ -z "${nodename}" ]; then
    read -p "Node name: " nodename
  fi
  if [ "${nodename}" ]; then
    knife client show --no-color "${nodename}" > /dev/null 2>&1
    if [ "${?}" -eq "100" ]; then
      PRIVATEKEY=$(knife client create -d "${nodename}")
    else
      while [ -z "${privatekeypath}" ]; do
        read -p "Client for '${nodename}' already exists. Please give me the path to the private key: " privatekeypath
        if [ "${privatekeypath}" ] && ! [ -f "${privatekeypath}" ]; then
          echo "'${privatekeypath}' is not a file."
          privatekeypath=""
        fi
      done
      PRIVATEKEY=$(cat "${privatekeypath}")
    fi;

    knife node show -E --no-color "${nodename}" > /dev/null 2>&1
    if [ "${?}" -eq "100" ]; then
      knife node create -d "${nodename}"
      EDITOR="tee" knife edit "/acls/nodes/${nodename}.json" <<EOF
{
  "create": {
    "actors": [
      "${nodename}",
      "pivotal"
    ],
    "groups": [
      "admins",
      "clients",
      "users"
    ]
  },
  "read": {
    "actors": [
      "${nodename}",
      "pivotal"
    ],
    "groups": [
      "admins",
      "clients",
      "users"
    ]
  },
  "update": {
    "actors": [
      "${nodename}",
      "pivotal"
    ],
    "groups": [
      "admins",
      "users"
    ]
  },
  "delete": {
    "actors": [
      "${nodename}",
      "pivotal"
    ],
    "groups": [
      "admins",
      "users"
    ]
  },
  "grant": {
    "actors": [
      "${nodename}",
      "pivotal"
    ],
    "groups": [
      "admins"
    ]
  }
}
EOF

    fi;

    if [ -z "${runlist}" ]; then
      read -p "Run list (comma seperated): " runlist
    fi
    if [ "${runlist}" ]; then
    	knife node run_list set "${nodename}" "${runlist}" > /dev/null
    fi

    cat > deployment/etc/chef/private.pem <<EOF
${PRIVATEKEY}
EOF
    cat > deployment/etc/chef/config.json <<EOF
{
	"chef": {
		"client": {
			"name": "${nodename}",
			"key": "/etc/chef/private.pem"
		},
		"server": "${server}",
		"node": {
			"name": "${nodename}"
		}
	},
	"cookbooks": "/opt/chef/cookbooks"
}
EOF
  fi
}

if [ -z "${nodename}" ]; then
  while true; do
    read -p "Do you want to create an config file? [Y/N] " yn
    case $yn in
      [Yy]* ) create-config; break;;
      [Nn]* ) exit;;
      * ) echo "Please answer with yes or no.";;
    esac
  done
else
  create-config
fi

cd deployment/
tar cf --owner=0 --group=0 - * | ssh root@${node} '(cd /; tar xf - ; /opt/chef/setup)'

if [ -f "deployment/etc/chef/config.json" ]; then
  rm deployment/etc/chef/*
fi