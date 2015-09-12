package main

import (
	"errors"
	"fmt"
	"sort"
)

type cmdHelp struct {
	Args string
	Desc string
	OLD  string /* one line description */
}

var helpTable = map[string]*cmdHelp{
	"clear": {
		Args: "none",
		Desc: `

	Clear the screen using an ANSI escape code. This may not work
	in all terminals.
`,
		OLD: "attempt to clear the display",
	},
	"help": {
		Args: "optional: command names",
		Desc: `

	Show help messages. If arguments are provided, show the
	full help message for the first argument.
`,
		OLD: "print usage information",
	},
	"list": {
		Args: "optional: substrings to search for",
		Desc: `

	List the secrets in the store. If arguments are provided,
	they will be used to match labels: a label will be included
	in the list if any of the argumnts appear as substrings in
	the label.
`,
		OLD: "list the labels in the store",
	},
	"passwd": {
		Args: "none",
		Desc: `

	Change the password on the store. Accepts no arguments.
`,
		OLD: "change the store's passphrase",
	},
	"quit": {
		Args: "none",
		Desc: `

	Write the store to disk if it has been modified and exit. This
	may also be done with C-d.
`,
		OLD: "exit the program",
	},
	"rmeta": {
		Args: "required: one or more labels",
		Desc: `

	Read metadata from the listed labels. Requires at least one
	label to be provided.
`,
		OLD: "display record metadata",
	},
	"show": {
		Args: "required: one or more labels",
		Desc: `

	Print a secret's raw bytes to console. This is useful if the
	secret is textual (e.g. a passphrase); for binary data, see
	'showhex'. If more than one label is specified, the passwords
	will be printed with their label.
`,
		OLD: "show secrets as text",
	},
	"showhex": {
		Args: "required: one or more labels",
		Desc: `

	Print a hex-encoded secret to console. This is useful if the
	secret contains binary data; for textual secrets, see
	'show'. If more than one label is specified, the passwords
	will be printed with their label.
`,
		OLD: "show secrets as hex-encoded",
	},
	"store": {
		Args: "required: one or more labels",
		Desc: `

	Store a new passphrase for each of the labels specified. If the
	label already exists, the user will be prompted whether or not
	they wish to proceed.
`,
		OLD: "store secrets",
	},
	"wmeta": {
		Args: "required: a single label",
		Desc: `

	Write metadata to the label; only one label may be
	specified. For metadata keys that replace old values, the
	previous value will be displayed and the overwrite will be
	noted.
`,
		OLD: "write metadata",
	},
	"write": {
		Args: "none",
		Desc: `

	Write the store to disk. Note that this will be done
	automatically when the program exits, as well.
`,
		OLD: "write the store to disk",
	},
}

var commandList []string

func init() {
	commandList = make([]string, 0, len(dispatch))

	for cmd := range dispatch {
		if _, ok := helpTable[cmd]; ok {
			commandList = append(commandList, cmd)
		} else {
			fmt.Printf("[!] Warning: command %s isn't documented. This is a bug!\n", cmd)
		}
	}
	sort.Strings(commandList)
}

func printCommands() {
	fmt.Println("Commands:")
	for _, cmd := range commandList {
		fmt.Printf("\t%s: %s\n", cmd, helpTable[cmd].OLD)
	}

	fmt.Println("Use help command (e.g. help list) to read more detailed help messages.")
}

func help(args []string) error {
	if len(args) == 0 {
		printCommands()
		return nil
	}

	cmd, ok := helpTable[args[0]]
	if !ok {
		return errors.New("command not found")
	}

	fmt.Printf("%s: %s\n\tArguments: %s\n%s\n\n",
		args[0], cmd.OLD, cmd.Args, cmd.Desc)

	return nil
}
