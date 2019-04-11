package main

import (
	"os"
	"strconv"
	"strings"

	"io/ioutil"
	"net/url"
)

const (
	nslcdConf     = "/etc/nslcd.conf"
	defaultFilter = "(&(objectClass=posixAccount)(uid=%s))"
)

func getNslcdConfPath() string {
	conf := os.Getenv("NSLCD_CONF")
	if conf == "" {
		conf = nslcdConf
	}
	return conf
}

func (l *ldapEnv) loadNslcdConf() error {
	conf := getNslcdConfPath()
	b, err := ioutil.ReadFile(conf)
	if err != nil {
		l.host = "localhost"
		l.port = 389
		l.base = "dc=example,dc=org"
		l.filter = defaultFilter
		l.tls = false
		l.skip = false
		l.debug = false
		l.binddn = ""
		l.bindpw = ""
		l.uidmap = "uid"
	}
	for _, s := range strings.Split(string(b), "\n") {
		v := strings.Split(s, " ")
		switch {
		case v[0] == "uri":
			u, err := url.Parse(v[1])
			if err != nil {
				return err
			}
			if u.Scheme == "ldaps" {
				l.tls = true
			} else {
				l.tls = false
			}
			if strings.Contains(u.Host, ":") {
				h := strings.Split(u.Host, ":")
				l.host = h[0]
				p, err := strconv.Atoi(h[1])
				if err != nil {
					return err
				}
				l.port = p
			} else {
				l.host = u.Host
				if l.tls {
					l.port = 636
					if isAddr(l.host) {
						l.skip = true
					}
				} else {
					l.port = 389
				}
			}
		case v[0] == "base":
			if len(v) == 3 {
				if v[1] == "passwd" {
					l.base = v[2]
				}
			} else if l.base == "" {
				l.base = v[1]
			}
		case v[0] == "binddn":
			l.binddn = v[1]
		case v[0] == "bindpw":
			l.bindpw = v[1]
		case v[0] == "pam_authz_search":
			if strings.Contains(v[1], "$username") {
				l.filter = strings.Replace(v[1], "$username", "%s", 1)
			} else {
				l.filter = v[1]
			}
		case v[0] == "tls_reqcert":
			if v[1] == "never" || v[1] == "allow" {
				l.skip = true
			}
		case v[0] == "filter" && len(v) >= 3 && v[1] == "passwd":
			l.filter = strings.Join(v[2:], " ")
		case v[0] == "map" && len(v) == 4 && v[1] == "passwd" && v[2] == "uid":
			l.uidmap = v[3]
		default:
			if l.filter == "" {
				l.filter = defaultFilter
			}
		}
	}
	return nil
}

func (l ldapEnv) fullFilter() string {
	return "(&" + l.filter + "(" + l.uidmap + "=%s))"
}
