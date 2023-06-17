package main

import (
	"encoding/json"
	"flag"
	"fmt"

	"os"
	"os/signal"
	"strings"
	"syscall"

	ldapv3 "github.com/go-ldap/ldap/v3"
	"github.com/lor00x/goldap/message"

	"github.com/sirupsen/logrus"
	ldap "github.com/vjeantet/ldapserver"
)

var log = logrus.New()

type ConfigStruct struct {
	LdapServer    string `json:"LdapServer"`
	LdapBindUser  string `json:"LdapBindUser"`
	BindDN        string `json:"BindDN"`
	UserDN        string `json:"UserDN"`
	SearchGroup   string `json:"SearchGroup"`
	ServerAddress string `json:"ServerAddress"`
}

var config ConfigStruct

func init() {

	var configFile = flag.String("configFile", "config.json", "Config file")
	flag.Parse()

	userJSON, err := os.ReadFile(*configFile)
	if err != nil {
		log.Error(fmt.Printf("Error reading config file: %s", *configFile))
	}
	if err = json.Unmarshal(userJSON, &config); err != nil {
		log.Error("Error unmarshalling json")
	}
}

func main() {

	server := ldap.NewServer()

	routes := ldap.NewRouteMux()
	routes.Bind(func(w ldap.ResponseWriter, m *ldap.Message) {
		r := m.GetBindRequest()
		log.Debug(fmt.Sprintf("Bind request start User=%s", string(r.Name())))
		res := ldap.NewBindResponse(ldap.LDAPResultSuccess)

		bindusername := string(r.Name())
		bindpassword := string(r.AuthenticationSimple())

		l, err := ldapv3.DialURL(config.LdapServer)
		if err != nil {
			log.Error(err)
		}
		defer l.Close()
		if bindusername != config.BindDN {
			bindusername = bindusername + "," + config.UserDN
		}
		errBind := l.Bind(bindusername, bindpassword)
		if errBind != nil {
			log.Error(errBind)
		}
		if bindusername != config.BindDN {
			// Search group for the given username
			searchRequest := ldapv3.NewSearchRequest(
				config.UserDN,
				ldapv3.ScopeWholeSubtree, ldapv3.NeverDerefAliases, 0, 0, false,
				fmt.Sprintf("(&(%s)(memberOf=%s))", string(r.Name()), config.SearchGroup),
				[]string{"cn"},
				nil,
			)

			sr, err := l.Search(searchRequest)

			if err != nil {
				log.Error(err)
			}

			if len(sr.Entries) != 1 {
				log.Error("User does not exist or group not matched")
				res.SetResultCode(ldap.LDAPResultInvalidCredentials)
				w.Write(res)
				return
			}
		}

		if errBind != nil {
			log.Error(fmt.Sprintf("Bind failed User=%s", string(r.Name())))
			res.SetResultCode(ldap.LDAPResultInvalidCredentials)
			res.SetDiagnosticMessage("invalid credentials")
			w.Write(res)
		} else {
			w.Write(res)
			return
		}

	})
	routes.Search(func(w ldap.ResponseWriter, m *ldap.Message) {
		r := m.GetSearchRequest()
		username := extractUsername(r.FilterString())
		if username != config.LdapBindUser {
			e := ldap.NewSearchResultEntry(fmt.Sprintf("uid=%s", username))
			e.AddAttribute(message.AttributeDescription("permission"), message.AttributeValue("H=4"))
			w.Write(e)
			res := ldap.NewSearchResultDoneResponse(ldap.LDAPResultSuccess)
			w.Write(res)
		} else {
			res := ldap.NewSearchResultDoneResponse(ldap.LDAPResultInvalidCredentials)
			w.Write(res)
		}
	}).Label("FreeIpa & Supermicro")

	server.Handle(routes)

	go server.ListenAndServe(config.ServerAddress)

	// When CTRL+C, SIGINT and SIGTERM signal occurs
	// Then stop server gracefully

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch
	close(ch)
	server.Stop()
}
func extractUsername(filter string) string {
	username := strings.Split(filter, "cn=")[1]
	username = strings.Trim(username, ")")
	return username
}
