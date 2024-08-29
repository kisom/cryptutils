// delegate hooks into the secret store to perform a Red October
// delegation.
package main

import (
	"fmt"
)

func main() {
	fmt.Println("archived")
}

//func loadStore(path string, m secret.ScryptMode) *store.SecretStore {
//	passphrase, err := util.PassPrompt("Secrets passphrase> ")
//	if err != nil {
//		util.Errorf("Failed to read passphrase: %v", err)
//		return nil
//	}
//
//	var passwords *store.SecretStore
//	if ok, _ := util.Exists(path); ok {
//		defer util.Zero(passphrase)
//		fileData, err := util.ReadFile(path)
//		if err != nil {
//			util.Errorf("%v", err)
//			return nil
//		}
//		var ok bool
//		passwords, ok = store.UnmarshalSecretStore(fileData, passphrase, m)
//		if !ok {
//			return nil
//		}
//		return passwords
//	}
//	util.Errorf("could not find %s", path)
//	return nil
//}
//
//type roData struct {
//	CAFile   string
//	User     string
//	Password string
//	Server   string
//	Labels   []string
//	Owners   []string
//	Dur      string
//	Count    int
//}
//
//func getMetadata(rec *store.SecretRecord, key, dv string) (string, bool) {
//	v, ok := rec.Metadata[key]
//	if !ok {
//		if dv != "" {
//			ok = true
//		}
//		return dv, true
//	}
//
//	return string(v), true
//}
//
//func delegate(ro *roData) (err error) {
//	srv, err := client.NewRemoteServer(ro.Server, ro.CAFile)
//	if err != nil {
//		return
//	}
//
//	request := core.DelegateRequest{
//		Name:     ro.User,
//		Password: ro.Password,
//		Uses:     ro.Count,
//		Time:     ro.Dur,
//		Users:    ro.Owners,
//		Labels:   ro.Labels,
//	}
//
//	resp, err := srv.Delegate(request)
//	if err != nil {
//		return
//	}
//	fmt.Println(resp.Status)
//	return
//}
//
//func strUser(n string, u keycache.ActiveUser) string {
//	uType := "U"
//	if u.Admin {
//		uType = "A"
//	}
//	s := fmt.Sprintf("%s (%s)", n, uType)
//	return s
//}
//
//func unwrap(attrs map[string]string) string {
//	var attrList = make([]string, 0, len(attrs))
//	for k, v := range attrs {
//		attrList = append(attrList, k+"="+v)
//	}
//
//	sort.Strings(attrList)
//	return strings.Join(attrList, "; ")
//}
//
//func strDelegation(u keycache.ActiveUser) string {
//	var attrs = map[string]string{}
//	attrs["uses"] = fmt.Sprintf("%d", u.Usage.Uses)
//
//	if len(u.Usage.Labels) > 0 {
//		attrs["labels"] = strings.Join(u.Usage.Labels, ",")
//	}
//
//	if len(u.Usage.Users) > 0 {
//		attrs["users"] = strings.Join(u.Usage.Users, ",")
//	}
//
//	attrs["expires"] = u.Usage.Expiry.Format("2006-01-02 15:04:05 MST")
//	return unwrap(attrs)
//}
//
//func summary(ro *roData) (err error) {
//	srv, err := client.NewRemoteServer(ro.Server, ro.CAFile)
//	if err != nil {
//		return
//	}
//
//	request := core.SummaryRequest{
//		Name:     ro.User,
//		Password: ro.Password,
//	}
//
//	resp, err := srv.Summary(request)
//	if err != nil {
//		return
//	}
//
//	fmt.Println(resp.Status)
//	fmt.Println("Active delegations")
//	for n, u := range resp.Live {
//		fmt.Printf("\t%s\n", strUser(n, u))
//		fmt.Printf("\t\t%s\n", strDelegation(u))
//	}
//
//	names := make([]string, 0, len(resp.All))
//	for n := range resp.All {
//		names = append(names, n)
//	}
//	sort.Strings(names)
//
//	fmt.Println("All accounts")
//	for i := range names {
//		n := names[i]
//		u := resp.All[n]
//		uType := "U"
//		if u.Admin {
//			uType = "A"
//		}
//		fmt.Printf("\t%s (%s) // %s\n", n, uType, u.Type)
//	}
//
//	return nil
//}
//
//func usage() {
//	fmt.Fprintf(os.Stderr, `usage: delegate <label> <command>
//
//	where label is the secret store label.
//`)
//}
//
//func split(s string) []string {
//	ss := strings.Split(s, ",")
//	for i := range ss {
//		ss[i] = strings.TrimSpace(ss[i])
//	}
//	return ss
//}
//
//func main() {
//	baseFile := filepath.Join(os.Getenv("HOME"), ".secrets.db")
//	count := flag.Int("n", 5, "how many delegations are going out?")
//	caFile := flag.String("ca", "", "CA file for Red October")
//	storePath := flag.String("f", baseFile, "path to password store")
//	scryptInteractive := flag.Bool("i", false, "use scrypt interactive")
//	forTime := flag.String("for", "1h", "how long should the delegation be active for?")
//	labels := flag.String("labels", "", "red october labels to use for decryption")
//	server := flag.String("server", "127.0.0.1:8080", "host:port of red october server")
//	owners := flag.String("to", "", "users to whitelist for decryption")
//	userName := flag.String("u", "", "username for red october")
//	flag.Parse()
//
//	if flag.NArg() != 2 {
//		usage()
//		os.Exit(1)
//	}
//
//	scryptMode := secret.ScryptStandard
//	if *scryptInteractive {
//		scryptMode = secret.ScryptInteractive
//	}
//
//	passwords := loadStore(*storePath, scryptMode)
//	if passwords == nil {
//		util.Errorf("Failed to open password store")
//		os.Exit(1)
//	}
//	defer passwords.Zero()
//
//	rec, ok := passwords.Store[flag.Arg(0)]
//	if !ok {
//		util.Errorf("%s is not a valid label.", flag.Arg(0))
//		os.Exit(1)
//	}
//
//	var ro roData
//	ro.User, ok = getMetadata(rec, "ro-user", *userName)
//	if !ok {
//		util.Errorf("Unable to get a valid user.")
//		os.Exit(1)
//	}
//
//	ro.Password = string(rec.Secret)
//	ro.Server, ok = getMetadata(rec, "ro-server", *server)
//	if !ok {
//		util.Errorf("Unable to get a valid user.")
//		os.Exit(1)
//	}
//
//	ro.CAFile, ok = getMetadata(rec, "ro-ca", *caFile)
//	if !ok {
//		util.Errorf("Unable to get a valid user.")
//		os.Exit(1)
//	}
//
//	ro.Labels = split(*labels)
//	ro.Owners = split(*owners)
//	ro.Count = *count
//	ro.Dur = *forTime
//
//	var err error
//	cmd := flag.Arg(1)
//	switch cmd {
//	case "delegate":
//		err = delegate(&ro)
//	case "summary":
//		err = summary(&ro)
//	default:
//		err = errors.New("rocli: invalid command " + cmd)
//	}
//	if err != nil {
//		util.Errorf("%v", err)
//		os.Exit(1)
//	}
//}
