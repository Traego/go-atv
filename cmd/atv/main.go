// Command atv is a small command-line remote for an Apple TV over the
// Companion protocol. It finds devices, pairs with one, and sends commands.
//
//	atv discover
//	atv pair <address> [name]
//	atv -c <credentials> <address> button up
//	atv -c <credentials> <address> off
//
// Credentials come from pair and are a colon-separated hex string. They can
// be passed with -c or in the ATV_CREDENTIALS environment variable.
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"

	"github.com/traego/go-atv/companion"
	"github.com/traego/go-atv/discovery"
	"github.com/traego/go-atv/hap"
)

func main() {
	creds := flag.String("c", os.Getenv("ATV_CREDENTIALS"), "pairing credentials")
	flag.Usage = usage
	flag.Parse()
	args := flag.Args()
	if len(args) == 0 {
		usage()
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	var err error
	switch args[0] {
	case "discover":
		err = discover(ctx)
	case "pair":
		err = pair(ctx, args[1:])
	default:
		err = control(ctx, *creds, args)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "atv:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `usage:
  atv discover
  atv pair <address> [name]
  atv -c <credentials> <address> <command> [args]

commands:
  button <name>     press a button (up down left right select menu home
                    play_pause volume_up volume_down ...)
  hold <name>       press and hold a button for a second
  tap               tap the touchpad
  on | off          wake or sleep the device
  launch <id|url>   launch an app by bundle id or open a url
  status            print the device's power status
  apps              list launchable apps
`)
}

func discover(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	devices, err := discovery.Browse(ctx)
	if err != nil {
		return err
	}
	if len(devices) == 0 {
		fmt.Println("no Companion devices found")
		return nil
	}
	for _, d := range devices {
		model := d.Model
		if model != "" {
			model = " (" + model + ")"
		}
		fmt.Printf("%-24s %s%s\n", d.Name, d.Addr, model)
	}
	return nil
}

func pair(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("pair needs an address")
	}
	name := "go-atv"
	if len(args) > 1 {
		name = args[1]
	}
	p, err := companion.StartPairing(ctx, args[0], name)
	if err != nil {
		return err
	}
	fmt.Print("enter the PIN shown on the Apple TV: ")
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		p.Close()
		return err
	}
	creds, info, err := p.Finish(ctx, strings.TrimSpace(line))
	if err != nil {
		return err
	}
	if name, ok := info["name"].(string); ok {
		fmt.Println("paired with", name)
	}
	fmt.Println("credentials (keep these):")
	fmt.Println(creds.String())
	return nil
}

func control(ctx context.Context, credsString string, args []string) error {
	if credsString == "" {
		return errors.New("no credentials; pass -c or set ATV_CREDENTIALS")
	}
	if len(args) < 2 {
		return errors.New("need an address and a command")
	}
	creds, err := hap.ParseCredentials(credsString)
	if err != nil {
		return err
	}
	addr, cmd, rest := args[0], args[1], args[2:]
	c, err := companion.Dial(ctx, addr, creds, companion.Identity{})
	if err != nil {
		return err
	}
	defer c.Close()

	switch cmd {
	case "button":
		if len(rest) == 0 {
			return errors.New("button needs a name")
		}
		b, ok := companion.ParseButton(rest[0])
		if !ok {
			return fmt.Errorf("unknown button %q", rest[0])
		}
		return c.Press(ctx, b)
	case "hold":
		if len(rest) == 0 {
			return errors.New("hold needs a name")
		}
		b, ok := companion.ParseButton(rest[0])
		if !ok {
			return fmt.Errorf("unknown button %q", rest[0])
		}
		return c.Hold(ctx, b, time.Second)
	case "tap":
		return c.Tap(ctx)
	case "on":
		return c.TurnOn(ctx)
	case "off":
		return c.TurnOff(ctx)
	case "launch":
		if len(rest) == 0 {
			return errors.New("launch needs a bundle id or url")
		}
		return c.LaunchApp(ctx, rest[0])
	case "status":
		st, err := c.SystemStatus(ctx)
		if err != nil {
			return err
		}
		fmt.Println(st)
		return nil
	case "apps":
		apps, err := c.Apps(ctx)
		if err != nil {
			return err
		}
		for _, a := range apps {
			fmt.Printf("%-40s %s\n", a.BundleID, a.Name)
		}
		return nil
	case "volume":
		if len(rest) == 0 {
			v, err := c.Volume(ctx)
			if err != nil {
				return err
			}
			fmt.Printf("%.0f%%\n", v)
			return nil
		}
		v, err := strconv.ParseFloat(rest[0], 64)
		if err != nil {
			return err
		}
		return c.SetVolume(ctx, v)
	default:
		return fmt.Errorf("unknown command %q", cmd)
	}
}
